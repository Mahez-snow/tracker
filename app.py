# app.py
from flask import Flask, redirect, url_for, request, jsonify, session
from flask_cors import CORS # <<< ADD THIS IMPORT
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import requests
import os
import jwt # For creating session tokens (JWT is standard practice)
import time
from datetime import datetime, timedelta

# --- Configuration (REPLACE WITH YOUR ACTUAL VALUES/ENVIRONMENT VARIABLES) ---
# NOTE: In a real application, these should be loaded from environment variables (.env file)
GOOGLE_CLIENT_ID = "YOUR_GOOGLE_CLIENT_ID" 
GOOGLE_CLIENT_SECRET = "YOUR_GOOGLE_CLIENT_SECRET"
REDIRECT_URI = "http://localhost:5000/api/auth/google/callback" 
JWT_SECRET_KEY = "SUPER_SECRET_KEY_FOR_JWT" # Used to sign the session token
MONGO_URI = "mongodb+srv://mahez3717_db_user:snow_mahez@financialtracker.xreytyk.mongodb.net/?appName=financialtracker"

# --- MongoDB Setup ---
client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
db = client.financialtracker # Access the 'financialtracker' database
users_collection = db.users # 'users' collection for storing user data

try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(f"MongoDB connection error: {e}")
app = Flask(__name__)
app.secret_key = os.urandom(24) 
CORS(app) # <<< ADD THIS LINE RIGHT AFTER INITIALIZING THE APP
# --- Helper Functions ---

def create_jwt(user_id):
    """Creates a JSON Web Token for user session management."""
    payload = {
        'user_id': str(user_id),
        'exp': datetime.utcnow() + timedelta(hours=24), # Token expires in 24 hours
        'iat': datetime.utcnow()
    }
    return jwt.encode(payload, JWT_SECRET_KEY, algorithm='HS256')

def find_or_create_user(email, name=None, google_id=None, password_hash=None):
    """Finds a user by email or creates a new one."""
    user_data = users_collection.find_one({'email': email})

    if user_data:
        # Existing user found
        return user_data

    # User does not exist, create a new account
    new_user = {
        'name': name if name else email.split('@')[0],
        'email': email,
        'google_id': google_id,
        'password': password_hash,
        'created_at': datetime.utcnow()
    }
    result = users_collection.insert_one(new_user)
    new_user['_id'] = result.inserted_id
    return new_user

# --- Standard Login/Signup Endpoints ---

@app.route('/api/signup', methods=['POST'])
def signup():
    data = request.get_json()
    name = data.get('name')
    email = data.get('email')
    password = data.get('password')

    if not all([name, email, password]):
        return jsonify({"error": "Missing required fields"}), 400

    if users_collection.find_one({'email': email}):
        return jsonify({"error": "User already exists"}), 409

    hashed_password = generate_password_hash(password)
    user = find_or_create_user(email=email, name=name, password_hash=hashed_password)
    token = create_jwt(user['_id'])
    
    # ✅ CORRECT FLOW: 1. Create response. 2. Set headers. 3. Return.
    response = jsonify({"message": "User created successfully", "token": token})
    response.headers['Content-Type'] = 'application/json' 
    return response, 201
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = users_collection.find_one({'email': email})

    if user and user.get('password') and check_password_hash(user['password'], password):
        token = create_jwt(user['_id'])
        
        # ✅ CORRECT FLOW: 1. Create response. 2. Set headers. 3. Return.
        response = jsonify({"message": "Login successful", "token": token})
        response.headers['Content-Type'] = 'application/json'
        return response, 200
    else:
        return jsonify({"error": "Invalid email or password"}), 401
# --- Google OAuth Endpoints ---

@app.route('/api/auth/google')
def google_login():
    """Step 1: Redirect user to Google for authorization."""
    google_auth_url = 'https://accounts.google.com/o/oauth2/auth'
    params = {
        'client_id': GOOGLE_CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid email profile', # Request email and profile info
        'access_type': 'offline'
    }
    # 
    # Sends user to Google's sign-in page
    return redirect(f"{google_auth_url}?{'&'.join(f'{k}={v}' for k, v in params.items())}")

@app.route('/api/auth/google/callback')
def google_callback():
    """Step 2: Handle Google's response, exchange code for tokens, and login/register user."""
    code = request.args.get('code')
    
    if not code:
        return jsonify({"error": "Authorization failed, no code received"}), 400

    # 1. Exchange the authorization code for an access token
    token_url = 'https://oauth2.googleapis.com/token'
    token_data = {
        'code': code,
        'client_id': GOOGLE_CLIENT_ID,
        'client_secret': GOOGLE_CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI,
        'grant_type': 'authorization_code'
    }
    token_response = requests.post(token_url, data=token_data)
    token_json = token_response.json()

    if 'error' in token_json:
        print(f"Token exchange error: {token_json.get('error_description', token_json['error'])}")
        return jsonify({"error": "Failed to authenticate with Google"}), 400

    access_token = token_json.get('access_token')

    # 2. Use the access token to get user info
    userinfo_url = 'https://www.googleapis.com/oauth2/v1/userinfo'
    userinfo_response = requests.get(userinfo_url, headers={'Authorization': f'Bearer {access_token}'})
    user_info = userinfo_response.json()
    
    if 'error' in user_info:
        return jsonify({"error": "Failed to fetch user data from Google"}), 400

    email = user_info.get('email')
    name = user_info.get('name')
    google_id = user_info.get('id')

    # 3. Find or create the user in your MongoDB database
    user = find_or_create_user(email=email, name=name, google_id=google_id)
    
    # 4. Generate application token and redirect
    token = create_jwt(user['_id'])
    
    # **SUCCESS REDIRECT**
    # You should redirect the user back to your frontend application's main page,
    # passing the JWT token, typically as a query parameter or via a cookie.
    # Example: http://localhost:3000/dashboard?token={token}
    
    # For demonstration, we'll just return the token as JSON
    return jsonify({
        "message": "Google login successful",
        "token": token,
        "user": {"email": email, "name": name}
    }), 200

# --- Run the App ---

if __name__ == '__main__':
    # Add CORS headers if running frontend and backend on different ports
    # app.run(debug=True, port=5000)
    print("Flask app running on http://localhost:5000")
    app.run(debug=True)