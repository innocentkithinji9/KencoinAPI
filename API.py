import ast
import base64
import calendar
from ast import literal_eval
from functools import wraps
import firebase_admin
import flask
import requests
from datetime import datetime
from firebase_admin import credentials, firestore
from flask import Flask, request
from flask_cors import CORS
from flask_restplus import Api, Resource, fields
from pywallet import wallet
from web3 import Web3
from requests.auth import HTTPBasicAuth
import json as Jay
from crypto import HDPrivateKey, HDKey

import keys
from abi import data, fData

url = "https://rinkeby.infura.io/v3/c5aa372b19484e00ad066119a24c646e"
web3 = Web3(Web3.HTTPProvider(url))
abi = fData
address = web3.toChecksumAddress("0x081a27f4eb8aa88984e0cb749f88a4188f3c03fb")
contract = web3.eth.contract(address=address, abi=abi)

authorization = {
    'apikey': {
        'type': 'apiKey',
        'in': 'header',
        'name': 'X-API-KEY'
    }
}

app = Flask(__name__)
CORS(app)
api = Api(app, authorizations=authorization)

walletNS = api.namespace("Wallet", description="All about Wallet")

wallet_model = walletNS.model("Rebuild Wallet", {"seed":
                                                     fields.String(description="12 mnemonic words",
                                                                   required=True)})

cred = credentials.Certificate('./Kencoin-Service-Account.json')
def_app = firebase_admin.initialize_app(cred)

db = firestore.client()


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'X-API-KEY' in request.headers:
            token = request.headers['x-API-KEY']

        if not token:
            return {'message': 'Token is Missing'}, 401

        print('TOKEN: {}'.format(token))
        decode_token = firebase_admin.auth.verify_id_token(token)
        print(decode_token)
        return f(*args, **kwargs)

    return decorated


def addEther(reciever):
    mypriv = base64.b64decode(
        b'QjE1QUM0OEVFOUFDRUU0ODA5RjYyNkQ5NEUwNUMzMTk4MzI0NkM2MTY0MEQ1NEVENjE4Q0U2NDY1NkY2Qjc3RA==').decode()
    myAddr = '0xF5E9eC64c1b9e2e643107cD6e87bF5DB440c895d'
    signed_txn = web3.eth.account.signTransaction(dict(
        nonce=web3.eth.getTransactionCount(myAddr),
        gasPrice=web3.eth.gasPrice,
        gas=100000,
        to=web3.toChecksumAddress(reciever),
        value=web3.toWei(0.1, 'ether')
    ),
        mypriv)

    web3.eth.sendRawTransaction(signed_txn.rawTransaction)
    pass


@walletNS.route("/create")
class CreateWallet(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.network = "ETH"

    @walletNS.expect(wallet_model)
    def post(self):
        print(api.payload)
        data = api.payload
        seed = data['seed']
        if not seed:
            return "Failed, No seed Provided", 422

        w = wallet.create_wallet(network=self.network, seed=seed, children=3)
        childInfo = w["children"][0]
        addEther(childInfo['address'])
        wallet_info = {"address": childInfo['address'], "pubkey": childInfo['xpublic_key'].decode(),
                       "seed": w['seed']}
        return wallet_info

    def get(self):
        seed = wallet.generate_mnemonic()
        encrypt = base64.b64encode(seed.encode('utf-8'))
        print(encrypt)
        w = wallet.create_wallet(network=self.network, seed=seed, children=3)
        childInfo = w["children"][0]
        addEther(childInfo['address'])
        wallet_info = {"address": childInfo['address'], "pubkey": childInfo['xpublic_key'].decode(),
                       "seed": w['seed']}
        return wallet_info


coinNS = api.namespace("coin", description="All about Coin")

SendCoinsModel = coinNS.model("sendingTokens",
                              {"mnemonic": fields.String(description="base64 encoded string of your mnemonic",
                                                         required=True),
                               "senderAddress": fields.String(description="Senders Address", required=True),
                               "recieverAddress": fields.String(description="recievers Address", required=True),
                               "amount": fields.Integer(description="Amount being Sent", required=True)
                               })


@coinNS.route("/check_balance/<userAddr>")
class CheckBalance(Resource):

    def __init__(self, api=None, *args, **kwargs):
        super().__init__(api, *args, **kwargs)
        self.url = "https://rinkeby.infura.io/v3/c5aa372b19484e00ad066119a24c646e"
        self.web3 = Web3(Web3.HTTPProvider(self.url))
        self.abi = fData
        self.address = self.web3.toChecksumAddress("0x081a27f4eb8aa88984e0cb749f88a4188f3c03fb")
        self.contract = self.web3.eth.contract(address=self.address, abi=self.abi)

    def get(self, userAddr):
        print(self.contract)

        return getBalance(userAddr)


def getPrivateKey(mnemonic):
    decrypted = base64.b64decode(mnemonic)
    master_key = HDPrivateKey.master_key_from_mnemonic(str(decrypted.decode()))
    root_keys = HDKey.from_path(master_key, "m/44'/60'/0'")
    acct_priv_key = root_keys[-1]
    keys = HDKey.from_path(acct_priv_key, '{change}/{index}'.format(change=0, index=0))
    private_key = keys[-1]
    prv_Key = private_key._key.to_hex()
    public_key = private_key.public_key.address()
    return prv_Key, public_key


def send(sender, reciever, amount, privateKey, log=True):
    nonce = web3.eth.getTransactionCount(sender)
    tx = {
        'chainId': 4,
        'gas': 300000,
        'gasPrice': web3.toWei('1', 'gwei'),
        'nonce': nonce,
    }

    transaction = contract.functions.transfer(web3.toChecksumAddress(reciever),
                                              web3.toWei(amount, 'ether')).buildTransaction(tx)
    print(transaction)
    sign_txn = web3.eth.account.signTransaction(transaction, private_key=privateKey)
    print(sign_txn.hash)
    web3.eth.sendRawTransaction(sign_txn.rawTransaction)
    hex = web3.toHex(web3.sha3(sign_txn.rawTransaction))
    addtoDb(sender, reciever, amount, "send", hex)
    print("Send added")
    addtoDb(reciever, sender, amount, "recieve", hex)
    return hex


def deposit(sender, reciever, amount, privateKey):
    nonce = web3.eth.getTransactionCount(sender)
    tx = {
        'chainId': 4,
        'gas': 300000,
        'gasPrice': web3.toWei('1', 'gwei'),
        'nonce': nonce,
    }

    transaction = contract.functions.deposit(web3.toWei(amount, 'ether'),
                                             web3.toChecksumAddress(reciever)).buildTransaction(tx)
    print(transaction)
    sign_txn = web3.eth.account.signTransaction(transaction, private_key=privateKey)
    print(sign_txn.hash)
    web3.eth.sendRawTransaction(sign_txn.rawTransaction)
    hex = web3.toHex(web3.sha3(sign_txn.rawTransaction))
    addtoDb(sender, reciever, amount, "send", hex)
    print("Send added")
    addtoDb(reciever, sender, amount, "recieve", hex)
    return hex


def setTotals(type, userAddr, added):
    print("Setting {}".format(type))
    docref = db.collection(u'users').where(u'address', u'==', u'{}'.format(web3.toChecksumAddress(userAddr))).get()
    userslist = []
    docs_list = []
    test_lis = []
    month = calendar.month_name[datetime.today().month][:3]
    for user in docref:
        userslist.append(user)
    if len(userslist) != 0:
        userDoc = userslist[0]
    else:
        userDoc = "nothing"
    if userDoc != "nothing":
        print("foundUser")
        summarydocs = userDoc.reference.collection(u'summary').where(u'name', u'==', u'{}'.format(month)).get()
        for doc in summarydocs:
            docs_list.append(doc.to_dict())
            test_lis.append(doc)
        if len(test_lis) != 0:
            amount = int(docs_list[0][type])
            test_lis[0].reference.set({
                u'{}'.format(type): str(int(amount) + int(added))
            }, merge=True)
        else:
            col_ref = userDoc.reference.collection(u'summary')
            col_ref.add({
                u'name': u'{}'.format(month),
                u'{}'.format(type): str(int(added))
            })


def getTotals(userRef):
    print("Getting Totals")
    full_summary = []
    doc_ref = userRef.reference
    summaries = doc_ref.collection(u'summary').get()
    i = 0
    for summary in summaries:
        full_summary.append(summary.to_dict())
        # full_summary[i]["key"] = i + 1
        i += 1
    return full_summary


def addtoDb(userAddr, participantAddr, amount, type, hex):
    docref = db.collection(u'users').where(u'address', u'==', u'{}'.format(web3.toChecksumAddress(userAddr))).get()
    userslist = []
    test_list = []
    for user in docref:
        userslist.append(user)
    if len(userslist) != 0:
        userDoc = userslist[0]
    else:
        userDoc = "nothing"
    if userDoc != "nothing":
        if type == "send":
            print("type", type)
            userDoc.reference.collection(u'transactions').add({
                u'transactionHash': u'{}'.format(str(hex)),
                u'participant': u'{}'.format(participantAddr),
                u'amount': u'{}'.format(amount),
                u'time': u'{}'.format(datetime.today().strftime('%Y-%m-%d')),
                u'type': u'Send'
            })

            setTotals("SentCash", userAddr, amount)

            db.collection(u'admin').document(u'info').collection(u'transactions').add({
                u'transactionHash': u'{}'.format(str(hex)),
                u'participant': u'{}'.format(participantAddr),
                u'amount': u'{}'.format(amount),
                u'time': u'{}'.format(datetime.today().strftime('%Y-%m-%d')),
                u'from': u'{}'.format(userAddr),
                u'type': u'SentCash'
            })



        else:
            print("type", type)
            userDoc.reference.collection(u'transactions').add({
                u'transactionHash': u'{}'.format(str(hex)),
                u'participant': u'{}'.format(participantAddr),
                u'amount': u'{}'.format(amount),
                u'time': u'{}'.format(datetime.today().strftime('%Y-%m-%d')),
                u'type': u'Recieved'
            })

            setTotals("ReceivedCash", participantAddr, amount)


@coinNS.route('/send')
class SendCoins(Resource):
    def __init__(self, api=None, *args, **kwargs):
        super().__init__(api, *args, **kwargs)
        self.url = "https://rinkeby.infura.io/v3/c5aa372b19484e00ad066119a24c646e"
        self.web3 = Web3(Web3.HTTPProvider(self.url))
        self.abi = fData
        self.address = self.web3.toChecksumAddress("0x081a27f4eb8aa88984e0cb749f88a4188f3c03fb")
        self.contract = self.web3.eth.contract(address=self.address, abi=self.abi)

    @coinNS.expect(SendCoinsModel)
    def post(self):
        data = request.data
        data = literal_eval(data.decode())
        print(data)
        privateKey, address = getPrivateKey(data["mnemonic"])
        print("Private Key: ", privateKey)
        print("Address: ", address)
        sender = self.web3.toChecksumAddress(address)
        reciever = self.web3.toChecksumAddress(data["recieverAddress"])
        hex = send(sender, reciever, data["amount"], privateKey)

        return hex


depositModel = coinNS.model("depositModel",
                            {"phoneNumber": fields.String(
                                description="Number to charge for the deposit eg 254700******",
                                required=True),
                                "account": fields.String(description="Number to Receive the tokens 0700******",
                                                         required=True),
                                "amount": fields.Integer(description="Amount to deposit", required=True)
                            })


@coinNS.route("/deposit")
class MpesaDeposit(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        r = requests.get(self.auth_URL, auth=HTTPBasicAuth(keys.consumer_key, keys.consumer_secret))
        response = r.json()
        self.access_token = response['access_token']
        print(self.access_token)

    @coinNS.expect(depositModel)
    def post(self):
        data = ast.literal_eval(flask.request.data.decode())
        print(data)
        rawtime = datetime.now()
        finishedtime = rawtime.strftime("%Y%m%d%H%M%S")
        rawpass = "{}{}{}".format(keys.business_short_code, keys.passKey, finishedtime)
        print(rawpass)
        base64Pass = base64.b64encode(rawpass.encode())
        passwd = base64Pass.decode()
        phone = "254" + data['phoneNumber'][1:]
        print(phone)
        stk_api_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
        headers = {"Authorization": "Bearer %s" % self.access_token}
        request = {
            "BusinessShortCode": keys.business_short_code,
            "Password": passwd,
            "Timestamp": finishedtime,
            "TransactionType": "CustomerPayBillOnline",
            "Amount": data['amount'],
            "PartyA": phone,
            "PartyB": "174379",
            "PhoneNumber": phone,
            "CallBackURL": "https://89eade11.ngrok.io/coin/confirm",
            "AccountReference": data['account'],
            "TransactionDesc": "Simple Test"
        }

        response = requests.post(stk_api_url, json=request, headers=headers)
        final_response = response.json()

        if 'CheckoutRequestID' in final_response:
            print("Here")
            return {"recieved": True, "ID": final_response['CheckoutRequestID']}
        else:
            return {"Error": True}


@coinNS.route("/confirm")
class MpesaConfirm(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.auth_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"
        r = requests.get(self.auth_URL, auth=HTTPBasicAuth(keys.consumer_key, keys.consumer_secret))
        self.verifyPK = 'QjE1QUM0OEVFOUFDRUU0ODA5RjYyNkQ5NEUwNUMzMTk4MzI0NkM2MTY0MEQ1NEVENjE4Q0U2NDY1NkY2Qjc3RA=='
        self.adk = '0xF5E9eC64c1b9e2e643107cD6e87bF5DB440c895d'
        response = r.json()
        self.access_token = response['access_token']
        print(self.access_token)

    def post(self):
        data = ast.literal_eval(flask.request.data.decode())
        print("data confirmed")
        print(data)
        print(flask.request.data.decode())
        rawtime = datetime.now()
        finishedtime = rawtime.strftime("%Y%m%d%H%M%S")
        rawpass = "{}{}{}".format(keys.business_short_code, keys.passKey, finishedtime)
        print(rawpass)
        base64Pass = base64.b64encode(rawpass.encode())
        passwd = base64Pass.decode()
        stk_api_url = "https://sandbox.safaricom.co.ke/mpesa/stkpushquery/v1/query"
        headers = {"Authorization": "Bearer %s" % self.access_token}
        request = {
            "BusinessShortCode": keys.business_short_code,
            "Password": passwd,
            "Timestamp": finishedtime,
            "CheckoutRequestID": data["ID"]
        }
        response = requests.post(stk_api_url, json=request, headers=headers)
        resp = response.json()
        print("The Response")
        print(resp)
        print(type(resp['ResultCode']))
        if int(resp['ResultCode']) != 0:
            return {"Deposited": False, "reason": resp["ResultDesc"]}
        else:
            deposithex = deposit(self.adk, data['address'], data['amount'],
                                  str(base64.b64decode(self.verifyPK).decode()))
            docref = db.collection(u'users').where(u'address', u'==',
                                                   u'{}'.format(web3.toChecksumAddress(data['address']))).get()
            userslist = []
            for user in docref:
                userslist.append(user)
            if len(userslist) != 0:
                userDoc = userslist[0]
            else:
                userDoc = "nothing"
            print(userDoc)
            if userDoc != "nothing":
                userDoc.reference.collection(u'transactions').add({
                    u'transactionHash': u'{}'.format(deposithex),
                    u'participant': u'{}'.format("Mpesa"),
                    u'amount': u'{}'.format(data['amount']),
                    u'time': u'{}'.format(datetime.today().strftime('%Y-%m-%d')),
                    u'type': u'Deposit'
                })

                setTotals("DepositedCash", data['address'], data['amount'])

                db.collection(u'admin').document(u'info').collection(u'transactions').add({
                    u'transactionHash': u'{}'.format(deposithex),
                    u'participant': u'{}'.format("Mpesa"),
                    u'from': u'{}'.format(data['address']),
                    u'amount': u'{}'.format(data['amount']),
                    u'time': u'{}'.format(datetime.today().strftime('%Y-%m-%d')),
                    u'type': u'Deposit'
                })
            else:
                print("User was not found")
            return {"Deposited": True, "DepositHas": deposithex, "reason": "Successfull"}


userNS = api.namespace("user", description="All about users")


@coinNS.route("/withdraw/confirm")
class MpesaWithdrawConfirm(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def post(self):
        data = flask.request.data.decode()
        print(data)


userModel = userNS.model("RegistrationModel", {
    "name": fields.String(required="true", description="Name of User"),
    "email": fields.String(required="true", description="email of User"),
    "dob": fields.String(required="true", description="dob of User"),
    "phone": fields.String(required="true", description="phone of User"),
    "gender": fields.String(required="true", description="gender of User"),
    "id": fields.String(required="true", description="id of User"),
    "pin": fields.String(description="pin of User"),
    "PPic": fields.String(required="true", description="PPic of User"),
    "IDFrontPic": fields.String(required="true", description="IDFrontPic of User"),
    "IDBackPic": fields.String(required="true", description="IDBackPic of User"),
    "mnemonic": fields.String(description="IDFrontPic of User"),
    "encrypted": fields.String(required="true", description="encrypted mnemonic of User"),
    "address": fields.String(required="true", description="wallet addr of User"),
    "pubKey": fields.String(required="true", description="public Key of User"),
    "uid": fields.String(required="true", description="User uid"),
})


def getAllTransactions():
    allTrans = []
    trans = db.collection(u'admin').document(u'info').collection('transactions').get()
    for tran in trans:
        allTrans.append(tran.to_dict())
    return allTrans


@userNS.route("/admin")
class Admon(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def get(self):
        response = {}
        response['transactions'] = getAllTransactions()
        response['totalSupply'] = str(web3.fromWei(get_total_supply(), 'ether'))
        return response


@userNS.route("/<uid>")
class User(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_Data_list = []
        self.url = "https://rinkeby.infura.io/v3/c5aa372b19484e00ad066119a24c646e"
        self.web3 = Web3(Web3.HTTPProvider(self.url))
        self.user_Docs = []
        self.pass_userRefs = []

    def get(self, uid):
        print("Hello:", uid)
        userDocs = db.collection(u'users').where(u'uid', u'==', u'{}'.format(uid)).get()
        for user in userDocs:
            self.user_Docs.append(user)
            self.user_Data_list.append(user.to_dict())
            self.pass_userRefs.append(user)
        if len(self.user_Data_list) != 0:
            userDetails = self.user_Data_list[0]
            usrAddr = web3.toChecksumAddress(userDetails['address'])
            print(usrAddr)
            balance = getBalance(usrAddr)
            userDetails['balance'] = balance[0]
            userDetails['new_User'] = False
            userDetails['Admin'] = checkAdmin(userDetails['address'])
            userDetails["transactions"] = getUserTransaction(self.user_Docs[0])
            userDetails["Summary"] = getTotals(self.pass_userRefs[0])
            return userDetails
        else:
            return {"new_User": True}


@userNS.route("/register")
class Register(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_Data_list = []
        self.url = "https://rinkeby.infura.io/v3/c5aa372b19484e00ad066119a24c646e"
        self.web3 = Web3(Web3.HTTPProvider(self.url))
        self.abi = data
        self.address = self.web3.toChecksumAddress("0x068540764de212447eeaf9928cde4218fee204d7")
        self.contract = self.web3.eth.contract(address=self.address, abi=self.abi)

    @userNS.expect(userModel)
    def post(self):
        rawdata = flask.request.data.decode()
        print(rawdata)
        data = ast.literal_eval(rawdata)
        print("########################################################################")
        print(data)
        print("########################################################################")
        userDocs = db.collection(u'users').where(u'uid', u'==', u'{}'.format(data['uid'])).get()
        if 'encrypted' in data:
            print("encrypted Found")
            mnemonic = data['encrypted']
        else:
            print("Encrypted lost")
            mnemonic = str(base64.b64encode(data['mnemonic'].encode('utf-8')).decode())
        for user in userDocs:
            self.user_Data_list.append(user.to_dict())
        if len(self.user_Data_list) == 0:
            db.collection(u'users').add({
                u'name': u'{}'.format(data['name']),
                u'email': u'{}'.format(data['email']),
                u'dob': u'{}'.format(data['dob']),
                u'phone': u'{}'.format(data['phone']),
                u'gender': u'{}'.format(data['gender']),
                u'uid': u'{}'.format(data['uid']),
                u'id': u'{}'.format(data['id']),
                u'pin': u'{}'.format(data['pin']),
                u'PPic': u'{}'.format(data['PPic']),
                u'IDFrontPic': u'{}'.format(data['IDFrontPic']),
                u'mnemonic': u'{}'.format(mnemonic),
                u'address': u'{}'.format(web3.toChecksumAddress(data['address'])),
                u'pubKey': u'{}'.format(data['pubKey']),
            })
            return "Successful"
        else:
            return "The user is already registered", 304


def getBalance(userAddr):
    if web3.isConnected():
        if web3.isAddress(userAddr):
            totalsupply = contract.functions.balanceOf(userAddr).call()
            return "{}".format(web3.fromWei(totalsupply, 'ether')), 200
        else:
            return "Invalid address Provided", 422
    else:
        return "This ain't right"


def checkAdmin(address):
    if web3.isConnected():
        owner = contract.functions.owner().call()
        if (address == owner):
            print(owner)
            return True
        else:
            print("not Owner")
            return False


def get_total_supply():
    if web3.isConnected():
        total_supply = contract.functions.totalSupply().call()
        print(total_supply)
        return total_supply


def getUserTransaction(userDoc):
    print("Hello")
    all_transactions = []
    tansactions = userDoc.reference.collection(u'transactions').get()
    i = 0
    for tansaction in tansactions:
        all_transactions.append(tansaction.to_dict())
        all_transactions[i]["key"] = i + 1
        i += 1

    return all_transactions


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=4000)
