import os
import json
from flask import Flask, request, jsonify, make_response
from flask_cors import CORS
from firebase_admin import credentials, auth, db
import jwt
from dotenv import load_dotenv

from utils import User, init_curs, agg_vals, agg_vals_login, graphStock, BardAI
load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}})

# Configuration
SECRET_KEY = os.getenv('SECRET_KEY', os.urandom(24))

@app.before_request
def before_request():
    print("HERE")
    init_curs()

@app.after_request
def add_headers(response):
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'  # Change as needed
    return response

# @app.after_request
# def add_headers(response):
#     # Set the desired value for Cross-Origin-Opener-Policy
#     response.headers['Cross-Origin-Opener-Policy'] = 'same-origin-allow-popups'  # Change this value as needed
#     return response



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

@app.route("/api/get-ticker-data", methods=['OPTIONS', 'GET'])
def get_data():
    tick_value = request.args.get('ticker')
    new_val = graphStock(tick_value)
    data = new_val.to_dict(orient='records')
    return jsonify(data)

@app.route("/api/get-login", methods=['OPTIONS', 'GET'])
def get_login():
    ref = db.reference('/')
    data = ref.get()
    return jsonify(data)

@app.route("/api/create-user", methods=['POST'])
def create_user():
    data = request.json
    email, pwd, fname, lname = agg_vals(data)
    user = User(email, pwd, fname, lname)
    user.reg_user()
    return jsonify({'message': 'Successfully updated DB'})

@app.route("/api/login", methods=["POST"])
def login():
    data = request.json
    email, pwd = agg_vals_login(data)
    user = User(email, pwd)
    stat, err = user.login_user(True)
    user_data = {"email": user.email}

    jwt_token = jwt.encode(user_data, SECRET_KEY, algorithm='HS256')

    response = make_response(jsonify({'message': 'Logged in successfully'}))
    response.set_cookie("jwt_token", jwt_token, httponly=True)

    if not stat:
        return jsonify({'message': 'Incorrect password' if err == 401 else 'User does not exist'}), 401
    return response

# @app.route('/api/register-google', methods=["POST"])
# def register_google():
#     data = request.json
#     user = User(id=data.get('idToken'))
#     res, stat = user.reg_user()
#     if not res:
#         return jsonify({'message': 'User already exists' if stat == 401 else 'Internal error'}), 400
#     return jsonify({'message': 'Registration successful'})

@app.route("/api/login-google", methods=["POST"])
def login_google():
    print("HERE!")
    print(request.json)
    user = User(request.json)
    print(user)
    res, stat = user.reg_user()
    if not res:
        return jsonify({'message': 'Internal error' if stat == 401 else 'User does not exist'}), 400
    if stat == 201:
        return jsonify({'message': "New user, prompt for extra info"})
    return jsonify({'message': 'Login successful'})

@app.route("/api/post-portfolio-info", methods=["POST"])
def post_user_info():
    data = request.json
    print(data)
    user = User(data['user'])
    ticker = data['ticker']
    user.post_portfolio_info({ticker['symbol']: {'name': ticker['name'], 'currency': ticker['currency'], 'stockExchange': ticker['stockExchange'], 'shortName': ticker['exchangeShortName']}})
    return "200"
    # email, _, _, _ = agg_vals(data)
    # user = User(email=email)
    # portfolio_data = data.get("parsedData") or data.get("updatedStocks")
    # if not portfolio_data:
    #     is_deleted = True
    # user.post_portfolio_info(portfolio_data, is_delete=is_deleted)
    # return jsonify({'message': 'Portfolio info updated'})

@app.route("/api/get-portfolio-info", methods=["POST"])
def get_portfolio_info():
    data = request.json
    print(data)
    user = User(data['user'])
    portfolio_info = user.get_portfolio_info()
    return jsonify(portfolio_info)


@app.route("/api/delete-portfolio-info", methods=["POST"])
def delete_portfolio_info():
    data = request.json
    user = User(data['user'])
    print("data:", data)
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

if __name__ == '__main__':
    app.run(debug=True, port=5000)