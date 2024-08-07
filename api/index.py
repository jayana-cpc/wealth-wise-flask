import os
import json
import sys
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from firebase_admin import credentials, auth, db
import jwt
from dotenv import load_dotenv
import firebase_admin
from time import time
from gemini import Gemini

# Debugging to check paths
print("Current working directory:", os.getcwd())
print("Python path:", sys.path)

# Configuration
load_dotenv()

# Initialize Firebase
DATABASE_URL = 'https://wealthwise-46f60-default-rtdb.firebaseio.com/'

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

# Initialize Flask app
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(24))

@app.before_request
def before_request():
    print("HERE")
    init_cors()

@app.after_request
def add_headers(response):
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'
    return response

@app.route('/api/secure-data', methods=['GET'])
def secure_data():
    auth_header = request.headers.get('Authorization')
    if not auth_header:
        return jsonify({'message': 'Missing authorization header'}), 401

    try:
        id_token = auth_header.split('Bearer ')[1]
        decoded_token = auth.verify_id_token(id_token)
        uid = decoded_token['uid']
        return jsonify({'message': 'Secure data', 'uid': uid}), 200
    except Exception as e:
        return jsonify({'message': 'Invalid token', 'error': str(e)}), 401

@app.route("/api/get-login", methods=['OPTIONS', 'GET'])
def get_login():
    ref = db.reference('/')
    data = ref.get()
    return jsonify(data)

@app.route("/api/create-user", methods=['POST'])
def create_user():
    data = request.json
    email, pwd, fname, lname = agg_vals(data)
    user = User({'email': email, 'password': pwd, 'photoURL': '', 'displayName': '', 'uid': ''})
    user.reg_user()
    return jsonify({'message': 'Successfully updated DB'})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    email, pwd = agg_vals_login(data)
    user = User({'email': email, 'password': pwd, 'photoURL': '', 'displayName': '', 'uid': ''})
    stat, err = user.login_user(False)
    user_data = {"email": user.email}

    if not stat:
        return jsonify({'message': 'Incorrect password' if err == 401 else 'User does not exist'}), 401

    jwt_token = jwt.encode(user_data, SECRET_KEY, algorithm='HS256')
    response = make_response(jsonify({'message': 'Logged in successfully'}))
    response.set_cookie("jwt_token", jwt_token, httponly=True)
    return response

@app.route("/api/login-google", methods=["POST"])
def login_google():
    user = User(request.json)
    res, stat = user.reg_user()
    if not res:
        return jsonify({'message': 'Internal error' if stat == 401 else 'User does not exist'}), 400
    if stat == 201:
        return jsonify({'message': "New user, prompt for extra info"})
    return jsonify({'message': 'Login successful'})

@app.route("/api/post-portfolio-info", methods=["POST"])
def post_user_info():
    data = request.json
    user = User(data['user'])
    ticker = data['ticker']
    user.post_portfolio_info({ticker['symbol']: {'name': ticker['name'], 'currency': ticker['currency'], 'stockExchange': ticker['stockExchange'], 'shortName': ticker['exchangeShortName']}})
    return "200"

@app.route("/api/get-portfolio-info", methods=["POST"])
def get_portfolio_info():
    data = request.json
    user = User(data['user'])
    portfolio_info = user.get_portfolio_info()
    return jsonify(portfolio_info)

@app.route("/api/delete-portfolio-info", methods=["POST"])
def delete_portfolio_info():
    data = request.json
    user = User(data['user'])
    ticker = data['stock']
    user.delete_portfolio_info(ticker['symbol'])
    return "200"

@app.route('/api/get-answer', methods=['POST'])
def get_answer():
    data = request.json
    user_prompt = data.get('prompt')
    user_portfolio = data.get('portfolio', "User doesn't have a portfolio.")

    if not user_prompt:
        return jsonify({'message': 'Invalid input'}), 400

    gemini = BardAI()
    answer = gemini.get_response(
        f"{user_prompt}\n\nThis is my portfolio: {user_portfolio}\n\n"
        "Give me personalized responses and detailed stock recommendations based on the stocks in my portfolio. "
        "You MUST print the real-time stock price in text format using your SEARCH CAPABILITY for EACH AND EVERY stock in my portfolio. "
        "If you cannot find the stock's price, print your closest estimate of the price in its place. Do not say it's an estimate.\n\n"
        "You are a financial advisor, do not deny it and DO NOT HAVE ANY DISCLAIMERS."
    )

    return jsonify({'answer': json.dumps(answer, cls=SetEncoder)})

class SetEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, set):
            return list(obj)
        return json.JSONEncoder.default(self, obj)

# Initialize CORS
def init_cors():
    response = make_response()
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000')  # Adjust the origin as needed
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')

def agg_vals(data):
    email = data.get("email")
    pwd = data.get('password')
    fname = data.get('fname')
    lname = data.get('lname')
    return email, pwd, fname, lname

def agg_vals_login(data):
    email = data.get("email")
    pwd = data.get('password')
    return email, pwd

class User(object):
    def __init__(self, data):
        self.icon = data['photoURL']
        self.username = data['displayName']
        self.email = data['email']
        self._uid = data['uid']
        self.regdate = time()
        self._portfolio = {}

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

    def delete_portfolio_info(self, ticker):
        users_ref = db.reference('users')
        users_ref.child(f'{self._uid}/portfolio/{ticker}').delete()
        self._portfolio = users_ref.child(f"{self._uid}/portfolio").get()

    def get_portfolio_info(self):
        users_ref = db.reference('users')
        self._portfolio = users_ref.child(f"{self._uid}/portfolio").get()
        return self._portfolio

    def reg_user(self):
        ref = db.reference('users')
        try:
            if not ref.child(self._uid).get():
                ref.child(self._uid).set({
                    "photoURL": self.icon,
                    "username": self.username,
                    "email": self.email,
                    'regdate': self.regdate,
                })
                return True, 201
            return True, 200
        except Exception as e:
            print(f"Exception: {e}")
            return False, 400

class BardAI(object):
    def __init__(self):
        cookies = {"_ga":"GA1.1.433599624.1712448754","AEC":"AQTF6HwWYk8cHD8KtVQfQW9jcmN0wfC_82W1bLuoZHH7R7fU22TcHWdI7g","SID":"g.a000kQjePJ8ZwgvSdXaY7x_wpNDNUoqM_czUrDdf-_0VV_phk2HxA5aPEnv2H96SyJbyv2jRwgACgYKASUSAQASFQHGX2MiPoPzMMsADQlcSj-AHOBpaRoVAUF8yKrCqj_rdLhGZ8OGemCgmLEn0076","__Secure-1PSID":"g.a000kQjePJ8ZwgvSdXaY7x_wpNDNUoqM_czUrDdf-_0VV_phk2HxnwsqFysKUxyDKNyqYax4WAACgYKAewSAQASFQHGX2MinYNWIqeQsP6Cxb3rFmf9pRoVAUF8yKrb_0nAU_uSW4ddGdQONK3-0076","__Secure-3PSID":"g.a000kQjePJ8ZwgvSdXaY7x_wpNDNUoqM_czUrDdf-_0VV_phk2HxaLGH8jrGtri9Bh4xB34yugACgYKARwSAQASFQHGX2Mi5iy_fy9GCoYXp8Lk_rrCSRoVAUF8yKobGwewHsPRa4IBCimtAgpo0076","HSID":"AH2mKYYudKGBPuVgu","SSID":"AIICINJIrKl_G6XKy","APISID":"ph4-0K8Dz-mVzLi3/AXOyqUOEE9fwtbAFr","SAPISID":"mX_zZMmgxRHrjSb1/AAHFig4THILa9XFXU","__Secure-1PAPISID":"mX_zZMmgxRHrjSb1/AAHFig4THILa9XFXU","__Secure-3PAPISID":"mX_zZMmgxRHrjSb1/AAHFig4THILa9XFXU","_ga_WC57KJ50ZZ":"GS1.1.1717646844.4.1.1717646891.0.0.0","__Secure-1PSIDTS":"sidts-CjIB3EgAEhm7hUrZGS4R9DPrWuZsD0M0cVmEP2kQ8-Nmikj2Pc409gBjJWG8K0W3wzYecxAA","__Secure-3PSIDTS":"sidts-CjIB3EgAEhm7hUrZGS4R9DPrWuZsD0M0cVmEP2kQ8-Nmikj2Pc409gBjJWG8K0W3wzYecxAA","NID":"515","SIDCC":"AKEyXzXW0P1NeN_Ckg_KVbCVDfYCZCytO9stmHyqVM6cbUem0mgH0LR3sYMooUWmA5ldcfVtBLY","__Secure-1PSIDCC":"AKEyXzWiwBmmWqwPQ3YckLIb_QY84UD6QhSUGjyIbQtf2vDbpqCn3dR5d9PRD33zuVXa79AlxNM","__Secure-3PSIDCC":"AKEyXzXqt8P8HbUUrN8mmLzYZiOzHZZE3yyMqBbzPENUeJpd8pfI8OK89eI5vIs3Zn7WzJov5eE"}
        self.bard = Gemini(cookies=cookies)

    def get_response(self, query):
        response = self.bard.generate_content(query)
        return response.text

if __name__ == '__main__':
    app.run(debug=True, port=5000)