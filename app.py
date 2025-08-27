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
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    
    # Check if user already exists
    if users_collection.find_one({'username': data['username']}):
        return jsonify({'message': 'Username already exists!'}), 409

    users_collection.insert_one({
        'username': data['username'],
        'password': hashed_password
    })
    return jsonify({'message': 'New user registered!'}), 201

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