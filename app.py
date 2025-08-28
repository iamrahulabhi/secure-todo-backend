# app.py
import os
import datetime
import jwt
from functools import wraps
from flask import Flask, request, jsonify
from flask_pymongo import PyMongo
from flask_cors import CORS
from bson.objectid import ObjectId
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv
import secrets
import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import random

load_dotenv()

app = Flask(__name__)

# --- Configuration ---
app.config["MONGO_URI"] = os.getenv("MONGO_URI")
app.config["SECRET_KEY"] = os.getenv("JWT_SECRET_KEY")

# --- Extensions ---
mongo = PyMongo(app)
# Secure CORS for production by specifying your frontend's deployed URL
# For local dev, you can use "http://localhost:3000"
CORS(app, resources={r"/api/*": {"origins": "*"}}) 

# --- Collections ---
users_collection = mongo.db.users
todos_collection = mongo.db.todos

# --- Helper Functions ---
def serialize_doc(doc):
    if doc and "_id" in doc:
        doc["_id"] = str(doc["_id"])
    return doc

# --- Authentication Decorator ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1]

        if not token:
            return jsonify({'message': 'Authentication token is missing!'}), 401

        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users_collection.find_one({'_id': ObjectId(data['user_id'])})
            if not current_user:
                return jsonify({'message': 'User not found!'}), 401
        except Exception as e:
            return jsonify({'message': 'Token is invalid or expired!', 'error': str(e)}), 401
        
        return f(str(current_user['_id']), *args, **kwargs)
    return decorated

# --- Authentication Routes ---
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # --- NEW: Get email from request data ---
    email = data.get('email')
    username = data.get('username')
    password = data.get('password')

    if not email or not username or not password:
        return jsonify({'message': 'Missing username, email, or password!'}), 400

    # --- NEW: Check if username OR email already exists ---
    if users_collection.find_one({'username': username}):
        return jsonify({'message': 'Username already exists!'}), 409
    
    if users_collection.find_one({'email': email}):
        return jsonify({'message': 'Email address already in use!'}), 409

    hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
    
    users_collection.insert_one({
        'username': username,
        'email': email, # --- NEW: Save email to the database ---
        'password': hashed_password
    })
    return jsonify({'message': 'New user registered successfully!'}), 201

@app.route('/api/login', methods=['POST'])
def login():
    auth = request.get_json()
    if not auth or not auth.get('username') or not auth.get('password'):
        return jsonify({'message': 'Could not verify'}), 401

    user = users_collection.find_one({'username': auth['username']})
    if user and check_password_hash(user['password'], auth['password']):
        token = jwt.encode({
            'user_id': str(user['_id']),
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        return jsonify({'token': token})

    return jsonify({'message': 'Invalid username or password'}), 401

@app.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    data = request.get_json()
    email = data.get('email')
    user = users_collection.find_one({'email': email})

    if not user:
        return jsonify({'message': 'If a user with that email exists, a reset link has been sent.'}), 200

    # --- NEW: Generate OTP and update token logic ---
    token = secrets.token_urlsafe(16)
    otp = str(random.randint(100000, 999999)) # Generate a 6-digit OTP
    expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=15) # Shorten expiry for OTP

    users_collection.update_one(
        {'_id': user['_id']},
        {'$set': {'reset_token': token, 'reset_token_expiry': expiry, 'otp': otp}}
    )

    sender_email = os.getenv('SENDER_EMAIL')
    sender_password = os.getenv('SENDER_PASSWORD')
    link =os.getenv('BASE_URL')
    reset_link = f"http://localhost:3000/reset-password?token={token}" # Change to Vercel URL for production

    # --- NEW: Update email content to include OTP ---
    message = MIMEMultipart("alternative")
    message["Subject"] = "Password Reset Request"
    message["From"] = sender_email
    message["To"] = email
    html_content = f"""
    <html>
      <body>
        <p>Hi,<br>
           You requested a password reset. Please use the following One-Time Password (OTP) and click the link below.<br>
           Your OTP is: <h2>{otp}</h2>
           <a href="{reset_link}">Click here to reset your password</a><br>
           This link and OTP will expire in 15 minutes.
        </p>
      </body>
    </html>
    """
    message.attach(MIMEText(html_content, "html"))

    # ... (keep the smtplib sending logic exactly the same) ...
    context = ssl.create_default_context()
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465, context=context) as server:
            server.login(sender_email, sender_password)
            server.sendmail(sender_email, email, message.as_string())
    except Exception as e:
        return jsonify({'message': f'Could not send email. Error: {e}'}), 500

    return jsonify({'message': 'If a user with that email exists, a reset link has been sent.'}), 200


@app.route('/api/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    token = data.get('token')
    new_password = data.get('password')

    user = users_collection.find_one({
        'reset_token': token,
        'reset_token_expiry': {'$gt': datetime.datetime.utcnow()}
    })

    if not user:
        return jsonify({'message': 'Invalid or expired token.'}), 400

    hashed_password = generate_password_hash(new_password, method='pbkdf2:sha256')
    users_collection.update_one(
        {'_id': user['_id']},
        {
            '$set': {'password': hashed_password},
            '$unset': {'reset_token': "", 'reset_token_expiry': ""}
        }
    )
    return jsonify({'message': 'Password has been reset successfully.'}), 200

@app.route('/api/verify-otp', methods=['POST'])
def verify_otp():
    data = request.get_json()
    token = data.get('token')
    otp = data.get('otp')

    if not token or not otp:
        return jsonify({'message': 'Token and OTP are required.'}), 400

    # Find user based on the token from the URL
    user = users_collection.find_one({
        'reset_token': token,
        'reset_token_expiry': {'$gt': datetime.datetime.utcnow()}
    })

    if not user:
        return jsonify({'message': 'Invalid or expired token.'}), 400

    # Check if the provided OTP matches the one in the database
    if user.get('otp') == otp:
        return jsonify({'message': 'OTP verified successfully.'}), 200
    else:
        return jsonify({'message': 'Invalid OTP.'}), 400


# --- SECURE To-Do Routes ---
@app.route("/api/todos", methods=["GET"])
@token_required
def get_todos(current_user_id):
    todos = todos_collection.find({'user_id': current_user_id})
    return jsonify([serialize_doc(todo) for todo in todos])

@app.route("/api/todos", methods=["POST"])
@token_required
def add_todo(current_user_id):
    data = request.get_json()
    new_todo = {
        "text": data["text"],
        "completed": False,
        "priority": data.get("priority", "Medium"),
        "dueDate": data.get("dueDate"),
        "user_id": current_user_id # Link todo to the logged-in user
    }
    result = todos_collection.insert_one(new_todo)
    created_todo = todos_collection.find_one({"_id": result.inserted_id})
    return jsonify(serialize_doc(created_todo)), 201

@app.route("/api/todos/<id>", methods=["PUT"])
@token_required
def update_todo(current_user_id, id):
    data = request.get_json()
    # Ensure users can't update a todo that doesn't belong to them
    query = {"_id": ObjectId(id), "user_id": current_user_id}
    if not todos_collection.find_one(query):
        return jsonify({"message": "Todo not found or access denied"}), 404
        
    data.pop("_id", None)
    todos_collection.update_one(query, {"$set": data})
    updated_todo = todos_collection.find_one(query)
    return jsonify(serialize_doc(updated_todo))

@app.route("/api/todos/<id>", methods=["DELETE"])
@token_required
def delete_todo(current_user_id, id):
    query = {"_id": ObjectId(id), "user_id": current_user_id}
    result = todos_collection.delete_one(query)
    if result.deleted_count == 0:
        return jsonify({"message": "Todo not found or access denied"}), 404
    return jsonify({"message": "Todo deleted successfully"}), 200

# --- Final Step ---
# Create requirements.txt for deployment
# Run this command in your terminal: pip freeze > requirements.txt