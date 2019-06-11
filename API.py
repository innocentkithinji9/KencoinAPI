import ast
import base64
from ast import literal_eval
from functools import wraps
import firebase_admin
import flask
import requests
from datetime import datetime
from firebase_admin import credentials, firestore, auth, storage
from flask import Flask, request
from flask_cors import CORS
from flask_restplus import Api, Resource, fields
from pywallet import wallet
from web3 import Web3
from requests.auth import HTTPBasicAuth
import json as Jay

import keys
from abi import data

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
        decode_token = auth.verify_id_token(token)
        print(decode_token)
        return f(*args, **kwargs)

    return decorated


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
        wallet_info = {"address": childInfo['address'], "pubkey": childInfo['xpublic_key'].decode(),
                       "seed": w['seed']}
        return wallet_info

    def get(self):
        seed = wallet.generate_mnemonic()
        encrypt = base64.b64encode(seed.encode('utf-8'))
        print(encrypt)
        w = wallet.create_wallet(network=self.network, seed=seed, children=3)
        child = w["children"][0]
        childInfo = w["children"][0]
        wallet_info = {"address": childInfo['address'], "pubkey": childInfo['xpublic_key'].decode(),
                       "seed": w['seed'], "encrypted": encrypt.decode()}
        return wallet_info


coinNS = api.namespace("coin", description="All about Coin")

SendCoinsModel = coinNS.model("sendingTokens",
                              {"private_key": fields.String(description="Private Key of Sender", required=True),
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
        self.abi = data
        self.address = self.web3.toChecksumAddress("0x068540764de212447eeaf9928cde4218fee204d7")
        self.contract = self.web3.eth.contract(address=self.address, abi=self.abi)

    def get(self, userAddr):
        print(self.contract)

        return getBalance(userAddr)


@coinNS.route('/send')
class SendCoins(Resource):
    def __init__(self, api=None, *args, **kwargs):
        super().__init__(api, *args, **kwargs)
        self.url = "https://rinkeby.infura.io/v3/c5aa372b19484e00ad066119a24c646e"
        self.web3 = Web3(Web3.HTTPProvider(self.url))
        self.abi = data
        self.address = self.web3.toChecksumAddress("0x068540764de212447eeaf9928cde4218fee204d7")
        self.contract = self.web3.eth.contract(address=self.address, abi=self.abi)

    @coinNS.expect(SendCoinsModel)
    def post(self):
        data = request.data
        data = literal_eval(data.decode())
        print(data)

        # acct = self.web3.eth.account.privateKeyToAccount(data["private_key"][2:])
        sender = self.web3.toChecksumAddress(data['senderAddress'])
        reciever = self.web3.toChecksumAddress(data["recieverAddress"])

        nonce = self.web3.eth.getTransactionCount(sender)
        tx = {
            'chainId': 4,
            'gas': 300000,
            'gasPrice': self.web3.toWei('1', 'gwei'),
            'nonce': nonce,
        }

        transaction = self.contract.functions.transfer(reciever,
                                                       self.web3.toWei(data["amount"], 'ether')).buildTransaction(tx)
        print(transaction)
        sign_txn = self.web3.eth.account.signTransaction(transaction, private_key=data["private_key"][2:])
        print(sign_txn.hash)
        self.web3.eth.sendRawTransaction(sign_txn.rawTransaction)
        hex = self.web3.toHex(self.web3.sha3(sign_txn.rawTransaction))
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

        if final_response['CheckoutRequestID']:
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
        response = r.json()
        self.access_token = response['access_token']
        print(self.access_token)

    def post(self):
        data = ast.literal_eval(flask.request.data.decode())
        print("data confirmed")
        print(data["ID"])
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
        print(request)
        response = requests.post(stk_api_url, json=request, headers=headers)
        print(response.json())
        return "success"


userNS = api.namespace("user", description="All about users")

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


@userNS.route("/<uid>")
class User(Resource):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.user_Data_list = []
        self.url = "https://rinkeby.infura.io/v3/c5aa372b19484e00ad066119a24c646e"
        self.web3 = Web3(Web3.HTTPProvider(self.url))

    def get(self, uid):
        print("Hello:", uid)
        userDocs = db.collection(u'users').where(u'uid', u'==', u'{}'.format(uid)).get()
        for user in userDocs:
            self.user_Data_list.append(user.to_dict())
        if len(self.user_Data_list) != 0:
            userDetails = self.user_Data_list[0]
            usrAddr = self.web3.toChecksumAddress(userDetails['address'])
            print(usrAddr)
            balance = getBalance(usrAddr)
            userDetails['balance'] = balance[0]
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
        print(data['name'])
        userDocs = db.collection(u'users').where(u'uid', u'==', u'{}'.format(data['uid'])).get()
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
                u'mnemonic': u'{}'.format(data['encrypted']),
                u'address': u'{}'.format(data['address']),
                u'pubKey': u'{}'.format(data['pubKey']),
            })
            return "Successful"
        else:
            return "The user is already registered", 304


def getBalance(userAddr):
    url = "https://rinkeby.infura.io/v3/c5aa372b19484e00ad066119a24c646e"
    web3 = Web3(Web3.HTTPProvider(url))
    abi = data
    address = web3.toChecksumAddress("0x068540764de212447eeaf9928cde4218fee204d7")
    contract = web3.eth.contract(address=address, abi=abi)
    if web3.isConnected():
        if web3.isAddress(userAddr):
            totalsupply = contract.functions.balanceOf(userAddr).call()
            return "{}".format(web3.fromWei(totalsupply, 'ether')), 200
        else:
            return "Invalid address Provided", 422
    else:
        return "This ain't right"


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=4000)
