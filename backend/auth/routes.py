from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from models.user import User
from email_validator import validate_email, EmailNotValidError

auth_bp = Blueprint('auth', __name__)

# In-memory user storage (replace with database in production)
users = {}

@auth_bp.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Missing email or password'}), 400
    
    try:
        # Validate email
        valid = validate_email(data['email'])
        email = valid.email
    except EmailNotValidError as e:
        return jsonify({'error': str(e)}), 400
    
    if email in users:
        return jsonify({'error': 'Email already registered'}), 400
    
    # Create new user
    user = User.create(email, data['password'])
    users[email] = user
    
    return jsonify({'message': 'User registered successfully'}), 201

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or 'email' not in data or 'password' not in data:
        return jsonify({'error': 'Missing email or password'}), 400
    
    user = users.get(data['email'])
    if not user or not user.check_password(data['password']):
        return jsonify({'error': 'Invalid email or password'}), 401
    
    # Create access token
    access_token = create_access_token(identity=user.email)
    return jsonify({
        'access_token': access_token,
        'user': user.to_dict()
    }), 200

@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    data = request.get_json()
    
    if not data or 'email' not in data:
        return jsonify({'error': 'Missing email'}), 400
    
    if data['email'] not in users:
        return jsonify({'error': 'Email not found'}), 404
    
    # In a real application, you would:
    # 1. Generate a password reset token
    # 2. Send an email with the reset link
    # 3. Implement a token verification endpoint
    
    return jsonify({'message': 'Password reset instructions sent to email'}), 200

@auth_bp.route('/me', methods=['GET'])
@jwt_required()
def get_current_user():
    current_user_email = get_jwt_identity()
    user = users.get(current_user_email)
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    return jsonify(user.to_dict()), 200 