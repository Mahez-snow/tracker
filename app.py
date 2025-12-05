# app.py
from flask import Flask, redirect, url_for, request, jsonify, session, render_template_string
from flask_cors import CORS # <<< ADD THIS IMPORT
from werkzeug.security import generate_password_hash, check_password_hash
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import requests
import os
import jwt # For creating session tokens (JWT is standard practice)
import time
from datetime import datetime, timedelta
from bson.objectid import ObjectId # NEW IMPORT for working with MongoDB IDs
from functools import wraps # NEW IMPORT for the decorator
# --- Configuration (REPLACE WITH YOUR ACTUAL VALUES/ENVIRONMENT VARIABLES) ---
# NOTE: In a real application, these should be loaded from environment variables (.env file)
GOOGLE_CLIENT_ID = "YOUR_GOOGLE_CLIENT_ID" 
GOOGLE_CLIENT_SECRET = "YOUR_GOOGLE_CLIENT_SECRET"
REDIRECT_URI = "http://localhost:5000/api/auth/google/callback" 
JWT_SECRET_KEY = "hii@i_am_mahez!|my_lucky_number|3717" # Used to sign the session token
MONGO_URI = "mongodb+srv://mahez3717_db_user:snow_mahez@financialtracker.xreytyk.mongodb.net/?appName=financialtracker"

# --- MongoDB Setup ---
client = MongoClient(MONGO_URI, server_api=ServerApi('1'))
db = client.financialtracker # Access the 'financialtracker' database
users_collection = db.users # 'users' collection for storing user data

expenses_collection = db.expenses_and_income # New
trading_collection = db.trading_portfolio # New

try:
    with open('logined.html', 'r') as f: # REPLACE 'index.html' if your file is named differently
        FRONTEND_HTML = f.read()
except FileNotFoundError:
    FRONTEND_HTML = "<h1>Error: Frontend HTML file not found!</h1>"
try:
    with open('dashboard.html', 'r') as f:
        DASHBOARD_HTML = f.read()
except FileNotFoundError:
    DASHBOARD_HTML = "<h1>Error: Dashboard HTML file not found!</h1>"
try:
    client.admin.command('ping')
    print("Pinged your deployment. You successfully connected to MongoDB!")
except Exception as e:
    print(f"MongoDB connection error: {e}")
#app = Flask(__name__)
#app.secret_key = os.urandom(24) 
#CORS(app) # <<< ADD THIS LINE RIGHT AFTER INITIALIZING THE APP
# --- Helper Functions ---
# --- Flask App Initialization and Core Configuration ---
app = Flask(__name__)
app.secret_key = os.urandom(24) 
CORS(app) # <<< PLACE IT HERE, right after app initialization
# app.py

# ... (after MongoDB Setup) ...

def jwt_required(f):
    """
    Decorator to check for a valid JWT in the Authorization header.
    It passes the user_id from the token payload to the decorated function.
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        # 1. Check for 'Authorization' header
        auth_header = request.headers.get('Authorization')
        if not auth_header:
            return jsonify({'error': 'Authorization header missing'}), 401

        try:
            # Token expected format: "Bearer <token>"
            token = auth_header.split(' ')[1]
        except IndexError:
            return jsonify({'error': 'Token format is "Bearer <token>"'}), 401

        try:
            # 2. Decode and Validate the token
            # The 'audience' parameter is a security best practice, ensure the token 
            # was meant for this service. We'll use your user collection name as a simple audience identifier.
            payload = jwt.decode(token, 
                                 os.environ.get("JWT_SECRET_KEY"), # Get the secret key from environment
                                 algorithms=["HS256"], 
                                 audience="financialtracker") 
            
            # The user_id is passed to the decorated function
            user_id = payload.get('user_id')
            
            # Optionally check if user still exists in DB
            if not users_collection.find_one({"_id": ObjectId(user_id)}):
                return jsonify({'error': 'User not found'}), 401
                
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidAudienceError:
            return jsonify({'error': 'Invalid token audience'}), 401
        except jwt.InvalidSignatureError:
            return jsonify({'error': 'Invalid token signature'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        except Exception as e:
            # Catch all other exceptions (e.g., malformed token)
            return jsonify({'error': f'Authentication failed: {e}'}), 401

        # 3. Success: Execute the original route function
        # The user_id is passed as a keyword argument
        return f(*args, **kwargs, user_id=user_id) 

    return decorated
# app.py

def create_jwt(user_id):
    """Creates a JSON Web Token for user session management."""
    # Define token expiration time
    expiration_time = datetime.utcnow() + timedelta(hours=24)
    
    payload = {
        'user_id': str(user_id),
        'exp': expiration_time,
        'iat': datetime.utcnow(),
        'aud': "financialtracker"  # 🚨 IMPORTANT: Add the Audience claim for security
    }
    
    # 🚨 IMPORTANT: Use os.environ.get() for secure key retrieval
    secret = os.environ.get("JWT_SECRET_KEY") 
    
    # Fallback for local testing if ENV is not set (you should use os.environ.get in prod)
    if not secret:
        secret = "hii@i_am_mahez!|my_lucky_number|3717"
        
    return jwt.encode(payload, secret, algorithm='HS256')

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
# ----------------------------------------------------
# 🚨 NEW ROUTE: Serve the Frontend Page
# ----------------------------------------------------
@app.route('/')
def serve_frontend():
    """Serves the main HTML page when the user visits the root URL."""
    # Use render_template_string to send the pre-loaded HTML content
    return render_template_string(FRONTEND_HTML)
# --- Standard Login/Signup Endpoints ---
# --- New: Load Dashboard HTML content (Add this near where you load logined.html) ---

# app.py

# ... (Helper Functions are above) ...

# --- Standard Login/Signup Endpoints ---
# --- NEW SECURE DASHBOARD ROUTE ---
@app.route('/dashboard') # No .html extension needed here
def serve_dashboard():
    # This route serves the secure dashboard content.
    return render_template_string(DASHBOARD_HTML)
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
    
    # 🚨 FIX 1: Use create_jwt (which we will update next)
    token = create_jwt(user['_id'])
    
    # ✅ CORRECT FLOW: 1. Create response. 2. Set headers. 3. Return.
    response = jsonify({"message": "User created successfully", "token": token})
    response.headers['Content-Type'] = 'application/json' 
    return response, 201
# app.py

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    user = users_collection.find_one({'email': email})

    if user and user.get('password') and check_password_hash(user['password'], password):
        
        # 🚨 FIX 2: Use create_jwt (which we will update next)
        token = create_jwt(user['_id'])
        
        # ✅ CORRECT FLOW: 1. Create response. 2. Set headers. 3. Return.
        response = jsonify({"message": "Login successful", "token": token})
        response.headers['Content-Type'] = 'application/json'
        return response, 200
    else:
        return jsonify({"error": "Invalid email or password"}), 401# --- Google OAuth Endpoints ---

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
#creating protected route example
# app.py

# ... (After your existing /api/login and /api/signup routes) ...

# ----------------------------------------------------
# 🚨 ROUTE 3: Protected User Profile Endpoint
# ----------------------------------------------------
@app.route('/api/user/profile', methods=['GET'])
@jwt_required
def get_user_profile(user_id):
    """Fetches user data for the dashboard after token verification."""
    try:
        # We use the user_id passed from the decorator
        user_data = users_collection.find_one({"_id": ObjectId(user_id)}, {"password": 0}) 

        if not user_data:
            return jsonify({"error": "User not found"}), 404

        # Convert ObjectId to string for JSON serialization
        user_data['user_id'] = str(user_data['_id'])
        del user_data['_id']

        return jsonify(user_data), 200

    except Exception as e:
        return jsonify({"error": f"An error occurred: {str(e)}"}), 500

# ----------------------------------------------------
# 🚨 ROUTE 4: Protected Daily Transaction Entry
# ----------------------------------------------------
@app.route('/api/finance/entry', methods=['POST'])
@jwt_required
def add_daily_entry(user_id):
    """Saves a new income or expense transaction to the database."""
    data = request.get_json()
    
    # 1. Validate incoming data
    required_fields = ['type', 'amount', 'description']
    if not all(field in data for field in required_fields):
        return jsonify({"error": "Missing required fields (type, amount, description)"}), 400

    try:
        # 2. Prepare transaction document
        transaction_doc = {
            "user_id": ObjectId(user_id), # Link the transaction to the user's ID
            "type": data['type'], # 'income' or 'expense'
            "amount": float(data['amount']),
            "description": data['description'],
            "timestamp": datetime.utcnow(), # Auto-apply the time of filling
            "category": data.get('category', 'Uncategorized'), # Use provided category or default
        }

        # 3. Insert into the expenses collection
        expenses_collection.insert_one(transaction_doc)
        
        return jsonify({"message": "Transaction logged successfully"}), 201

    except ValueError:
        return jsonify({"error": "Amount must be a valid number"}), 400
    except Exception as e:
        return jsonify({"error": f"Failed to log transaction: {str(e)}"}), 500
# app.py

# ... (After your existing @app.route('/api/user/profile') route) ...

# ----------------------------------------------------
# 🚨 ROUTE 4: Protected Monthly Finance Summary
# ----------------------------------------------------
@app.route('/api/finance/summary', methods=['GET'])
@jwt_required
def get_finance_summary(user_id):
    """Calculates and returns total income and expenses for the current month."""
    try:
        current_year = datetime.utcnow().year
        current_month = datetime.utcnow().month
        
        # 1. Define the start and end dates for the current month in UTC
        start_of_month = datetime(current_year, current_month, 1)
        
        # Calculate the start of the next month to define the end of the current month
        if current_month == 12:
            start_of_next_month = datetime(current_year + 1, 1, 1)
        else:
            start_of_next_month = datetime(current_year, current_month + 1, 1)

        # 2. MongoDB Aggregation Pipeline
        pipeline = [
            # Filter by the authenticated user and the current month
            {
                '$match': {
                    'user_id': ObjectId(user_id),
                    'timestamp': {
                        '$gte': start_of_month,
                        '$lt': start_of_next_month
                    }
                }
            },
            # Group by transaction type ('income' or 'expense') and calculate the total amount
            {
                '$group': {
                    '_id': '$type', 
                    'total_amount': {'$sum': '$amount'}
                }
            }
        ]
        
        # 3. Execute the pipeline
        results = expenses_collection.aggregate(pipeline)
        
        # 4. Process results into a dictionary
        summary = {
            'total_income': 0.0,
            'total_expense': 0.0,
            'net_flow': 0.0
        }
        
        for result in results:
            if result['_id'] == 'income':
                summary['total_income'] = result['total_amount']
            elif result['_id'] == 'expense':
                summary['total_expense'] = result['total_amount']
                
        # 5. Calculate Net Flow
        summary['net_flow'] = summary['total_income'] - summary['total_expense']
        
        return jsonify(summary), 200

    except Exception as e:
        return jsonify({"error": f"Failed to retrieve finance summary: {str(e)}"}), 500
# --- Run the App ---

if __name__ == '__main__':
    # Add CORS headers if running frontend and backend on different ports
    # app.run(debug=True, port=5000)
    #print("Flask app running on http://localhost:5000")
    app.run(debug=True)