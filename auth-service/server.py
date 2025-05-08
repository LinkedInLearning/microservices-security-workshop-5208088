from flask import Flask, request, jsonify
from flask_cors import CORS
import jwt
import datetime
import os
import re
from functools import wraps
from passlib.hash import argon2
from passlib.context import CryptContext
from collections import defaultdict
import time

app = Flask(__name__)
CORS(app)

# Constants for JWT
JWT_ISSUER = "planet-destroyer-auth"
JWT_AUDIENCE = "planet-destroyer-api"

# Brute force protection settings
MAX_LOGIN_ATTEMPTS = 5
LOGIN_TIMEOUT = 300  # 5 minutes in seconds
failed_attempts = defaultdict(lambda: {"count": 0, "last_attempt": 0})

# Password requirements
PASSWORD_REQUIREMENTS = {
    "min_length": 12,
    "require_uppercase": True,
    "require_lowercase": True,
    "require_digit": True,
    "require_special": True,
    "max_length": 128
}

# Configure password hashing with Argon2id
# OWASP minimum settings for Argon2id:
# - memory_cost: 19456 (64 MiB)
# - time_cost: 2 (number of iterations)
# - parallelism: 1 (degree of parallelism)
# - hash_len: 16 (length of the hash in bytes)
pwd_context = CryptContext(
    schemes=["argon2"],
    deprecated="auto",
    argon2__type="id",  # Use Argon2id variant
    argon2__memory_cost=65536,  # 64 MiB
    argon2__time_cost=3,  # 3 iterations
    argon2__parallelism=4,  # 4 parallel threads
    argon2__hash_len=32,  # 32 bytes hash length
    argon2__salt_len=16  # 16 bytes salt length
)

# Simulated AWS Secrets Manager integration
"""
def get_secret_from_aws():
    # In a real implementation, this would use boto3 to fetch secrets
    # import boto3
    # client = boto3.client('secretsmanager')
    # response = client.get_secret_value(SecretId='jwt-secrets')
    # return response['SecretString']
    
    # For now, we'll simulate different keys for different purposes
    return {
        'jwt_signing_key': os.environ.get('JWT_SIGNING_KEY', 'your-signing-key-here'),
        'jwt_encryption_key': os.environ.get('JWT_ENCRYPTION_KEY', 'your-encryption-key-here'),
        'admin_api_key': os.environ.get('ADMIN_API_KEY', 'your-admin-key-here')
    }

# Fetch secrets from AWS Secrets Manager
secrets = get_secret_from_aws()
JWT_SIGNING_KEY = secrets['jwt_signing_key']
JWT_ENCRYPTION_KEY = secrets['jwt_encryption_key']
ADMIN_API_KEY = secrets['admin_api_key']
"""

# For development/testing, we'll use environment variables
# In production, these should come from AWS Secrets Manager
JWT_SIGNING_KEY = os.environ.get('JWT_SIGNING_KEY', 'your-signing-key-here')
JWT_ENCRYPTION_KEY = os.environ.get('JWT_ENCRYPTION_KEY', 'your-encryption-key-here')
ADMIN_API_KEY = os.environ.get('ADMIN_API_KEY', 'your-admin-key-here')

# Admin users database (in a real app, this would be in a database)
# Passwords are hashed using Argon2id with OWASP recommended settings
ADMIN_USERS = {
    "admin1": pwd_context.hash("AdminPass1!Complex"),
    "admin2": pwd_context.hash("AdminPass2!Complex"),
    "admin3": pwd_context.hash("AdminPass3!Complex")
}

class SecurityError(Exception):
    """Base class for security-related errors"""
    pass

class BruteForceError(SecurityError):
    """Raised when too many login attempts are detected"""
    pass

class PasswordValidationError(SecurityError):
    """Raised when password doesn't meet requirements"""
    pass

def validate_password(password):
    """
    Validate password against security requirements
    """
    if len(password) < PASSWORD_REQUIREMENTS["min_length"]:
        raise PasswordValidationError(f"Password must be at least {PASSWORD_REQUIREMENTS['min_length']} characters long")
    
    if len(password) > PASSWORD_REQUIREMENTS["max_length"]:
        raise PasswordValidationError(f"Password must not exceed {PASSWORD_REQUIREMENTS['max_length']} characters")
    
    if PASSWORD_REQUIREMENTS["require_uppercase"] and not re.search(r'[A-Z]', password):
        raise PasswordValidationError("Password must contain at least one uppercase letter")
    
    if PASSWORD_REQUIREMENTS["require_lowercase"] and not re.search(r'[a-z]', password):
        raise PasswordValidationError("Password must contain at least one lowercase letter")
    
    if PASSWORD_REQUIREMENTS["require_digit"] and not re.search(r'\d', password):
        raise PasswordValidationError("Password must contain at least one digit")
    
    if PASSWORD_REQUIREMENTS["require_special"] and not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        raise PasswordValidationError("Password must contain at least one special character")

def check_brute_force(username):
    """
    Check if user has exceeded maximum login attempts
    """
    current_time = time.time()
    user_attempts = failed_attempts[username]
    
    # Reset attempts if timeout has passed
    if current_time - user_attempts["last_attempt"] > LOGIN_TIMEOUT:
        user_attempts["count"] = 0
    
    if user_attempts["count"] >= MAX_LOGIN_ATTEMPTS:
        time_left = int(LOGIN_TIMEOUT - (current_time - user_attempts["last_attempt"]))
        if time_left > 0:
            raise BruteForceError(f"Too many login attempts. Please try again in {time_left} seconds")
        else:
            user_attempts["count"] = 0
    
    user_attempts["last_attempt"] = current_time
    user_attempts["count"] += 1

def verify_password(plain_password, hashed_password):
    """
    Verify a password against its hash using Argon2id with OWASP recommended settings
    """
    return pwd_context.verify(plain_password, hashed_password)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        try:
            token = token.split(' ')[1]  # Remove 'Bearer ' prefix
            # Use signing key for verification
            data = jwt.decode(
                token, 
                JWT_SIGNING_KEY, 
                algorithms=["HS256"],
                audience=JWT_AUDIENCE,
                issuer=JWT_ISSUER
            )
            if data['username'] not in ADMIN_USERS:
                return jsonify({'error': 'Invalid token'}), 401
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            return jsonify({'error': f'Invalid token: {str(e)}'}), 401
        except Exception as e:
            return jsonify({'error': 'An error occurred while verifying the token'}), 500
        return f(*args, **kwargs)
    return decorated

@app.route('/login', methods=['POST'])
def login():
    try:
        auth = request.get_json()
        if not auth or not auth.get('username') or not auth.get('password'):
            return jsonify({'error': 'Missing username or password'}), 400

        username = auth.get('username')
        password = auth.get('password')

        # Check for brute force attempts
        check_brute_force(username)

        if username not in ADMIN_USERS or not verify_password(password, ADMIN_USERS[username]):
            return jsonify({'error': 'Invalid credentials'}), 401

        # Reset failed attempts on successful login
        failed_attempts[username]["count"] = 0

        # Use signing key for token generation
        token = jwt.encode({
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            'iat': datetime.datetime.utcnow(),
            'iss': JWT_ISSUER,
            'aud': JWT_AUDIENCE
        }, JWT_SIGNING_KEY)

        return jsonify({'token': token})

    except BruteForceError as e:
        return jsonify({'error': str(e)}), 429
    except PasswordValidationError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': 'An error occurred during login'}), 500

@app.route('/verify', methods=['GET'])
@token_required
def verify():
    return jsonify({'message': 'Token is valid'})

@app.route('/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        if not data or not data.get('username') or not data.get('password'):
            return jsonify({'error': 'Missing username or password'}), 400

        username = data.get('username')
        password = data.get('password')

        # Check if username already exists
        if username in ADMIN_USERS:
            return jsonify({'error': 'Username already exists'}), 400

        # Validate password complexity
        try:
            validate_password(password)
        except PasswordValidationError as e:
            return jsonify({'error': str(e)}), 400

        # Hash password with Argon2id
        hashed_password = pwd_context.hash(password)
        
        # Add new user to admin users
        ADMIN_USERS[username] = hashed_password

        # Generate JWT token
        token = jwt.encode({
            'username': username,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=24),
            'iat': datetime.datetime.utcnow(),
            'iss': JWT_ISSUER,
            'aud': JWT_AUDIENCE
        }, JWT_SIGNING_KEY)

        return jsonify({
            'message': 'Registration successful',
            'token': token
        }), 201

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.errorhandler(Exception)
def handle_error(error):
    """Global error handler"""
    if isinstance(error, SecurityError):
        return jsonify({'error': str(error)}), 400
    return jsonify({'error': 'An unexpected error occurred'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8003) 