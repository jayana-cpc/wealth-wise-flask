'''

This utils model is generally the entire backend for our project.
It makes the app.py file with the routes look simple but all the
detailed coding will be here and utilized there in a simple manner.

So far this is just being used for login/registration purposes but as

we need features those will go here too (like API stuff ya feel).


BCRYPT is the module we are using for encryption of passwords/user IDs
Introduce the firebase module to work with Google Authentication (trust)
'''


import bcrypt
import json
import requests
import logging

import firebase_admin
import os 
from dotenv import load_dotenv
load_dotenv()

import yfinance as yf

from flask import make_response
from time import time
from firebase_admin import initialize_app, db, credentials, auth

# from bardapi import Bard

from gemini import Gemini


# Authenticate Firebase, Establish Connection
# Use an absolute path or ensure the relative path is correct
DATABASE_URL = 'https://wealthwise-46f60-default-rtdb.firebaseio.com/'

# Load credentials from environment variables
cred = credentials.Certificate({
    "type": os.getenv('FIREBASE_TYPE'),
    "project_id": os.getenv('FIREBASE_PROJECT_ID'),
    "private_key_id": os.getenv('FIREBASE_PRIVATE_KEY_ID'),
    "private_key": os.getenv('FIREBASE_PRIVATE_KEY').replace('\\n', '\n'),
    "client_email": os.getenv('FIREBASE_CLIENT_EMAIL'),
    "client_id": os.getenv('FIREBASE_CLIENT_ID'),
    "auth_uri": os.getenv('FIREBASE_AUTH_URI'),
    "token_uri": os.getenv('FIREBASE_TOKEN_URI'),
    "auth_provider_x509_cert_url": os.getenv('FIREBASE_AUTH_PROVIDER_X509_CERT_URL'),
    "client_x509_cert_url": os.getenv('FIREBASE_CLIENT_X509_CERT_URL'),
    "universe_domain": os.getenv('FIREBASE_UNIVERSE_DOMAIN')
})

firebase_admin.initialize_app(cred, {
    'databaseURL': DATABASE_URL
})

# Initialize CORS
def init_curs():
    response = make_response()
    # Allow specific origin(s)
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')  # Adjust the origin as needed

    # Allow specific headers
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')

    # Allow specific methods
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')

# This function is for when the user is registering with email,
# password, first name, and last name. If they use Google Sign-in
# then this method is never called.
def agg_vals(data):
    email = data.get("email")
    pwd = data.get('password')
    fname = data.get('fname')
    lname = data.get('lname')
    return email, pwd, fname, lname

# This is just a simplified function created because I'm lazy, when the
# user is logging in with email and password and NOT Google.
def agg_vals_login(data):
    email = data.get("email")
    pwd = data.get('password')
    return email, pwd

# Get ticker information from api
def graphStock(tickersymbol):
    tickerSymbol = tickersymbol
    tickerData = yf.Ticker(tickerSymbol)
    tickerDF = tickerData.history(period = '1d', start='2015-5-23', end='2023-6-23')
    tickerDF = tickerDF[['Close']]
    return tickerDF

'''
This class goes kinda crazy. It's the basis for every interaction on the login/register
pages, I create a user object to handle all of the code in a simple manner that is somewhat
masked on the app.py file. Depending on what type of user they are (default or Google), class 
methods vary. 

If a user is created through Google, they will not have a "pwd" attribute and if
a user is created normally, they will not have an "id" attribute. This is the primary distinction
that is used throughout the code to determine if a user is Google-generated or not. 
'''
class User(object):
    def __init__(self, data):
        self.icon = data['photoURL']
        self.username = data['displayName']
        self.email = data['email']
        self._uid = data['uid']
        self.regdate = time()

        self._portfolio = {}

    # Posts a new ticker to a user's portfolio
    # Creates a portfolio subcategory if that is their first ticker.
    def post_portfolio_info(self, portfolio):
        ref = db.reference('users')
        data = ref.child(f'{self._uid}/portfolio').get()
        if data is None:
            data = portfolio
        else:   
            
            data.update(portfolio)
        ref.child(self._uid).update({
            'portfolio': data
        })
        self._portfolio = data

    # Removes a ticker from a user's portfolio
    def delete_portfolio_info(self, ticker):
        users_ref = db.reference('users')
        users_ref.child(f'{self._uid}/portfolio/{ticker}').delete()
        self._portfolio = users_ref.child(f"{self._uid}/portfolio").get()

    # Retrieves the user's entire portfolio
    def get_portfolio_info(self):
        users_ref = db.reference('users')
        self._portfolio = users_ref.child(f"{self._uid}/portfolio").get()
        return self._portfolio

    # Registers User in Realtime Database using their permanent UID as key
    # Will store portfolio information
    def reg_user(self):
        ref = db.reference('users')
        try:
            if not ref.child(self._uid).get():

                # Create new user object in database
                ref.child(self._uid).set({
                    "photoURL": self.icon,
                    "username": self.username,
                    "email": self.email,
                    'regdate': self.regdate,
                })
                return True, 201 # Tell frontend we need to prompt for more personalization info
            return True, 200
        except Exception as e:
            print(f"Exception: {e}")
            return False, 400  # Something crazy happened, server error please debug if this happens.


class BardAI(object):

    def __init__(self):

        cookies = {"_ga":"GA1.1.433599624.1712448754","AEC":"AQTF6HwWYk8cHD8KtVQfQW9jcmN0wfC_82W1bLuoZHH7R7fU22TcHWdI7g","SID":"g.a000kQjePJ8ZwgvSdXaY7x_wpNDNUoqM_czUrDdf-_0VV_phk2HxA5aPEnv2H96SyJbyv2jRwgACgYKASUSAQASFQHGX2MiPoPzMMsADQlcSj-AHOBpaRoVAUF8yKrCqj_rdLhGZ8OGemCgmLEn0076","__Secure-1PSID":"g.a000kQjePJ8ZwgvSdXaY7x_wpNDNUoqM_czUrDdf-_0VV_phk2HxnwsqFysKUxyDKNyqYax4WAACgYKAewSAQASFQHGX2MinYNWIqeQsP6Cxb3rFmf9pRoVAUF8yKrb_0nAU_uSW4ddGdQONK3-0076","__Secure-3PSID":"g.a000kQjePJ8ZwgvSdXaY7x_wpNDNUoqM_czUrDdf-_0VV_phk2HxaLGH8jrGtri9Bh4xB34yugACgYKARwSAQASFQHGX2Mi5iy_fy9GCoYXp8Lk_rrCSRoVAUF8yKobGwewHsPRa4IBCimtAgpo0076","HSID":"AH2mKYYudKGBPuVgu","SSID":"AIICINJIrKl_G6XKy","APISID":"ph4-0K8Dz-mVzLi3/AXOyqUOEE9fwtbAFr","SAPISID":"mX_zZMmgxRHrjSb1/AAHFig4THILa9XFXU","__Secure-1PAPISID":"mX_zZMmgxRHrjSb1/AAHFig4THILa9XFXU","__Secure-3PAPISID":"mX_zZMmgxRHrjSb1/AAHFig4THILa9XFXU","_ga_WC57KJ50ZZ":"GS1.1.1717646844.4.1.1717646891.0.0.0","__Secure-1PSIDTS":"sidts-CjIB3EgAEhm7hUrZGS4R9DPrWuZsD0M0cVmEP2kQ8-Nmikj2Pc409gBjJWG8K0W3wzYecxAA","__Secure-3PSIDTS":"sidts-CjIB3EgAEhm7hUrZGS4R9DPrWuZsD0M0cVmEP2kQ8-Nmikj2Pc409gBjJWG8K0W3wzYecxAA","NID":"515","SIDCC":"AKEyXzXW0P1NeN_Ckg_KVbCVDfYCZCytO9stmHyqVM6cbUem0mgH0LR3sYMooUWmA5ldcfVtBLY","__Secure-1PSIDCC":"AKEyXzWiwBmmWqwPQ3YckLIb_QY84UD6QhSUGjyIbQtf2vDbpqCn3dR5d9PRD33zuVXa79AlxNM","__Secure-3PSIDCC":"AKEyXzXqt8P8HbUUrN8mmLzYZiOzHZZE3yyMqBbzPENUeJpd8pfI8OK89eI5vIs3Zn7WzJov5eE"}
        self.bard = Gemini(cookies=cookies)
        #
        # GOOGLE_API_KEY = "AIzaSyASoC8oPKQM1XE9rhw8i0rQKTZSvflA7jE"
        # genai.configure(api_key=GOOGLE_API_KEY)
        # self.model = genai.GenerativeModel('gemini-pro')

    def get_response(self, query):
        response = self.bard.generate_content(query)
        return response.text

# bard = BardAI()
# print(bard.get_response("tell me about paul george"))

