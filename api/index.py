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
import time  
import requests
from datetime import datetime, timedelta
from urllib.parse import unquote
from threading import Lock
from flask import Flask, request, jsonify
from flask_mail import Mail, Message

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
CORS(app, resources={r"/api/*": {"origins": ["http://localhost:3000", "https://www.wealthwise.tech"]}})
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
    try:
        user = User(request.json)
        res, stat = user.reg_user()
        if not res:
            return jsonify({'message': 'Internal error' if stat == 401 else 'User does not exist'}), 400
        if stat == 201:
            return jsonify({'message': "New user, prompt for extra info"})
        return jsonify({'message': 'Login successful'})
    except Exception as e:
        print(f"An error occurred: {e}")
        return jsonify({'message': 'Server Error', 'error': str(e)}), 500


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

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'wealthwisehelpline@gmail.com'
app.config['MAIL_PASSWORD'] = 'fphl zqpq ojxk hmiy'  # Use an app-specific password if using Gmail
app.config['MAIL_DEFAULT_SENDER'] = 'wealthwisehelpline@gmail.com'

mail = Mail(app)

@app.route('/api/send-message', methods=['POST'])
def send_message():
    data = request.json
    name = data.get('name')
    email = data.get('email')
    subject = data.get('subject')
    phone = data.get('phone')
    message = data.get('message')

    try:
        msg = Message(subject=subject, recipients=['weathwisehelpline@gmail.com'])
        msg.body = f"""
        Name: {name}
        Email: {email}
        Phone: {phone}

        Message:
        {message}
        """

        mail.send(msg)
        return jsonify({"status": "success", "message": "Email sent successfully!"}), 200

    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


cached_data = {}
last_updated = None
data_lock = Lock()

# Group stock symbols by sector
sectors = {
    "Energy": ["XOM", "CVX", "NEE", "FSLR", "DUK", "SO"],
    "Communication Services": ["GOOGL", "META", "NFLX", "DIS", "VZ", "T"],
    "Consumer Discretionary": ["TSLA", "AMZN", "HD", "NKE", "MCD", "SBUX"],
    "Consumer Staples": ["PG", "KO", "PEP", "WMT", "COST", "MDLZ"],
    "Financials": ["JPM", "BAC", "WFC", "C", "GS", "MS"],
    "Healthcare": ["JNJ", "PFE", "UNH", "MRK", "ABBV", "TMO"],
    "Industrials": ["BA", "CAT", "GE", "UNP", "MMM", "UPS"],
    "Materials": ["LIN", "APD", "ECL", "SHW", "NEM", "FCX"],
    "Real Estate": ["AMT", "PLD", "CCI", "SPG", "EQIX", "DLR"],
    "Technology": ["AAPL", "MSFT", "GOOGL", "AMZN", "META", "INTC"],
    "Utilities": ["NEE", "DUK", "SO", "D", "AEP", "EXC"]
}

# Function to fetch stock profile data
def fetch_stock_profile(symbol):
    api_key = os.getenv('NEXT_PUBLIC_FIN_MOD_API_KEY')
    response = requests.get(f"https://financialmodelingprep.com/api/v3/profile/{symbol}?apikey={api_key}")
    if response.status_code == 200:
        profile_data = response.json()
        print(f"Profile data for {symbol}: {profile_data}")  # Log the full response data
        return profile_data[0] if profile_data else None
    else:
        print(f"Failed to fetch profile for {symbol}: {response.status_code}, {response.text}")
    return None

# Function to fetch stock price data
def fetch_stock_price_data(symbol):
    polygon_api_key = os.getenv('NEXT_PUBLIC_POLYGON_API_KEY')
    yesterday = (datetime.now() - timedelta(days=1)).strftime('%Y-%m-%d')
    one_month_ago = (datetime.now() - timedelta(days=30)).strftime('%Y-%m-%d')

    api_url = f"https://api.polygon.io/v2/aggs/ticker/{symbol}/range/1/day/{one_month_ago}/{yesterday}?adjusted=true&sort=asc&limit=120&apiKey={polygon_api_key}"
    response = requests.get(api_url)
    if response.status_code == 200:
        price_data = response.json()
        print(f"Price data for {symbol}: {price_data}")  # Log the full response data
        return price_data if price_data else None
    else:
        print(f"Failed to fetch price data for {symbol}: {response.status_code}, {response.text}")
    return None

# Function to fetch all data for a sector
def fetch_sector_data(sector):
    stock_symbols = sectors[sector]
    sector_data = []

    for symbol in stock_symbols:
        profile = fetch_stock_profile(symbol)
        price_data = fetch_stock_price_data(symbol)

        if profile and price_data:
            sector_data.append({
                "symbol": symbol,
                "companyName": profile.get("companyName"),
                "price": profile.get("price"),
                "industry": profile.get("industry"),
                "description": profile.get("description"),
                "website": profile.get("website"),
                "image": profile.get("image"),
                "priceData": price_data
            })
        else:
            print(f"Data for {symbol} in sector {sector} could not be fetched.")

    print(f"Fetched data for sector {sector}: {sector_data}")  # Log fetched data
    return sector_data

# Route to get stock data for a specific sector
@app.route('/api/sector-data/<sector>', methods=['GET'])
def get_sector_data(sector):
    global cached_data, last_updated

    # Normalize the sector name by unquoting any URL encoding (like %20)
    normalized_sector = unquote(sector)

    # Check if sector is valid
    if normalized_sector not in sectors:
        return jsonify({"error": "Invalid sector name"}), 400

    with data_lock:
        # Check if data was fetched within the last 60 seconds for testing
        if last_updated is None or (datetime.now() - last_updated) > timedelta(days=1):
            print(f"Fetching new data for sector: {normalized_sector}")
            cached_data[normalized_sector] = fetch_sector_data(normalized_sector)
            last_updated = datetime.now()

        print(f"Returning cached data for sector: {normalized_sector}")
        print(f"Cached data: {cached_data[normalized_sector]}")  # Debugging: Log cached data
        return jsonify({
            "data": cached_data.get(normalized_sector, []),
            "last_updated": last_updated.isoformat()
        })


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
def init_cors(response=None):
    if not response:
        response = make_response()
    response.headers.add('Access-Control-Allow-Origin', 'http://localhost:3000, https://www.wealthwise.tech, https://wealth-wise-git-dev-jayana-nanayakkaras-projects.vercel.app/')
    response.headers.add('Access-Control-Allow-Headers', 'Content-Type,Authorization')
    response.headers.add('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
    return response

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
        self.regdate = time.time()
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
