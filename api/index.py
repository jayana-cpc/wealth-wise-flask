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
        "Under no circumstances return a table in your response. Even if I request for one."
        "If you cannot find the stock's price, print your closest estimate of the price in its place. Do not say it's an estimate.\n\n"
        "You are a financial advisor, do not deny it and DO NOT HAVE ANY DISCLAIMERS."
    )
    print(answer)

    return jsonify({'answer': answer})

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
        cookies = {"_ga":"GA1.1.433599624.1712448754","__Secure-1PSIDTS":"sidts-CjIB3EgAEka_jE1teiMir7IYrr4V5Ca-4Ka4TR-W3-A_H1LbUkB62SfShGCHVqSXmKMvXRAA","__Secure-3PSIDTS":"sidts-CjIB3EgAEka_jE1teiMir7IYrr4V5Ca-4Ka4TR-W3-A_H1LbUkB62SfShGCHVqSXmKMvXRAA","_gcl_au":"1.1.1365081245.1736918152","_ga_WC57KJ50ZZ":"GS1.1.1736918152.6.0.1736918155.0.0.0","SID":"g.a000sQjePEcPhmRUbOcfEdGJ7GLLuAPGjblvBv9zigKtdCB7r2RZ2CJx50d4H4fBhaH6wYwXOQACgYKAbYSARASFQHGX2MikTwQJJxlAo6o1k6htlNRKRoVAUF8yKpdyRMUorW9ks9ONfuQg7cw0076","__Secure-1PSID":"g.a000sQjePEcPhmRUbOcfEdGJ7GLLuAPGjblvBv9zigKtdCB7r2RZmJ9eZVuwzrZw_ChgRIwiRwACgYKAVkSARASFQHGX2MivYtuiP9cAHiL-3mPYR2wvBoVAUF8yKplvmEXNVd5R9B9D1DoRUGS0076","__Secure-3PSID":"g.a000sQjePEcPhmRUbOcfEdGJ7GLLuAPGjblvBv9zigKtdCB7r2RZ19lXV0kATPgVNlSNrj0n_gACgYKAWwSARASFQHGX2Mi1cKFeTBkToglJYHYE2Z6QBoVAUF8yKrNY7AXPT2FeLD9TZI5pUAy0076","HSID":"AsHmI8EsBa5U90qQE","SSID":"A3-OATD48xndCVTWT","APISID":"btgIB9ySCnzFBpvo/AuokjAT_fWxBShCse","SAPISID":"_i564ghVgsL6Mp8q/AEX8qX7euY2KoWNbZ","__Secure-1PAPISID":"_i564ghVgsL6Mp8q/AEX8qX7euY2KoWNbZ","__Secure-3PAPISID":"_i564ghVgsL6Mp8q/AEX8qX7euY2KoWNbZ","NID":"520","SIDCC":"AKEyXzWyMiWwSLaJNvxDYhIZ8FFUgH4PlKNpPodiK9cbW-xLglGOG7OtqheTrwcUJlAqFxi53HA","__Secure-1PSIDCC":"AKEyXzVS19z7xllDiIMCusaKZ7E7IbK9yiDH6LtHj6Lin6yA8SIBdk0OVY_j5-eny1LmAxAm8_U","__Secure-3PSIDCC":"AKEyXzVuO6K_2j7Xhe3mTabXDVkaT58juTnaPmNqjwn5uVbsHCI06kyE5b3LU2Q7b8PRK08zm9g"}
        self.bard = Gemini(cookies=cookies)

    def get_response(self, query):
        response = self.bard.generate_content(query)
        return response.text

if __name__ == '__main__':
    app.run(debug=True, port=5000)
