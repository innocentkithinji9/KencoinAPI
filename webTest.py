from time import sleep

import requests
from datetime import datetime
from requests.auth import HTTPBasicAuth
import base64
import keys

api_URL = "https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials"

r = requests.get(api_URL, auth=HTTPBasicAuth(keys.consumer_key, keys.consumer_secret))
print (r.text)
response = r.json()
access_token = response['access_token']
print(access_token)



sleep(30)

rawtime = datetime.now()
finishedtime = rawtime.strftime("%Y%m%d%H%M%S")
rawpass = "{}{}{}".format(keys.business_short_code, keys.passKey, finishedtime)
print(rawpass)
base64Pass = base64.b64encode(rawpass.encode())
passwd = base64Pass.decode()

stk_api_url = "https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest"
headers = { "Authorization": "Bearer %s" % access_token }
request = {
  "BusinessShortCode": keys.business_short_code,
  "Password": passwd,
  "Timestamp": finishedtime,
  "TransactionType": "CustomerPayBillOnline",
  "Amount": "5",
  "PartyA": "254722396354",
  "PartyB": "174379",
  "PhoneNumber": "254722396354",
  "CallBackURL": "https://innocent.me/mpesa",
  "AccountReference": "254724612644",
  "TransactionDesc": "Simple Test"
}

response = requests.post(stk_api_url, json = request, headers=headers)

print (response.text)
