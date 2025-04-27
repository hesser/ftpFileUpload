import os
from flask import Flask, request, jsonify
from werkzeug.utils import secure_filename
import ftplib
from datetime import datetime, timedelta
import configparser
import logging
import uuid
import jwt
import secrets
import hashlib
from functools import wraps

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.FileHandler('app.log'), logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

# Initialize Flask app
app = Flask(__name__)

# Set a secret key for JWT
SECRET_KEY = os.environ.get('SECRET_KEY', str(uuid.uuid4()))
app.config['SECRET_KEY'] = SECRET_KEY
app.config['ACCESS_TOKEN_EXPIRATION'] = 3600  # 1 hour in seconds
app.config['REFRESH_TOKEN_EXPIRATION'] = 86400 * 7  # 7 days in seconds

# Create uploads directory if it doesn't exist
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Store refresh tokens (in a production environment, use a database)
refresh_tokens = {}  # Structure: {'client_id': {'token': 'refresh_token', 'exp': expiration_time}}

# Load API configuration from config file
def load_api_config():
    config = configparser.ConfigParser()
    created_new_config = False
    admin_credentials = None
    
    # Check if config file exists, if not create a default one
    if not os.path.exists('config.ini'):
        created_new_config = True
        
        # Generate a secure API key and secret for admin
        admin_client_id = f"client_{secrets.token_hex(8)}"
        admin_client_secret = secrets.token_hex(16)
        admin_client_secret_hash = hashlib.sha256(admin_client_secret.encode()).hexdigest()
        
        # Store admin credentials to display later
        admin_credentials = {
            'client_id': admin_client_id,
            'client_secret': admin_client_secret
        }
        
        # Create default config
        config['FTP'] = {
            'host': 'ftp.example.com',
            'port': '21',
            'username': 'your_username',
            'password': 'your_password',
            'directory': '/uploads'
        }
        
        config['API_CLIENTS'] = {
            admin_client_id: admin_client_secret_hash,
        }
        
        config['CLIENT_ROLES'] = {
            admin_client_id: 'admin',
        }
        
        with open('config.ini', 'w') as f:
            config.write(f)
            
        logger.info("Created default config.ini file")
    
    # Read the config file
    config.read('config.ini')
    
    # If we created a new config, display the admin credentials
    if created_new_config and admin_credentials:
        logger.info(f"Default admin client created with ID: {admin_credentials['client_id']} and Secret: {admin_credentials['client_secret']}")
        print("\n===========================================================================")
        print(f"DEFAULT ADMIN CREDENTIALS - SAVE THESE IMMEDIATELY:")
        print(f"Client ID:     {admin_credentials['client_id']}")
        print(f"Client Secret: {admin_credentials['client_secret']}")
        print("===========================================================================\n")
        
    return config
# Token required decorator
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check if the Authorization header is present
        auth_header = request.headers.get('Authorization')
        if auth_header:
            # Get the token from the Authorization header
            # The header format should be 'Bearer <token>'
            parts = auth_header.split()
            if len(parts) == 2 and parts[0].lower() == 'bearer':
                token = parts[1]
        
        if not token:
            return jsonify({'message': 'Token is missing!'}), 401
            
        try:
            # Decode the token
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            
            # Check token type (must be access token)
            if data.get('type') != 'access':
                return jsonify({'message': 'Invalid token type! Use an access token.'}), 401
                
            current_client = data['client_id']
            client_role = data.get('role', 'client')
        except jwt.ExpiredSignatureError:
            return jsonify({
                'message': 'Token has expired!',
                'error': 'token_expired',
                'description': 'The access token has expired. Use refresh token to get a new access token.'
            }), 401
        except jwt.InvalidTokenError:
            return jsonify({'message': 'Invalid token!'}), 401
            
        # Pass the current client and role to the route function
        return f(current_client, client_role, *args, **kwargs)
            
    return decorated

# Admin role required decorator
def admin_required(f):
    @wraps(f)
    def decorated(current_client, client_role, *args, **kwargs):
        if client_role != 'admin':
            return jsonify({'message': 'Admin privileges required!'}), 403
        return f(current_client, client_role, *args, **kwargs)
    return decorated

# Function to upload file to FTP server
def upload_to_ftp(file_path, filename):
    try:
        config = load_api_config()
        ftp_config = config['FTP']
        
        # Connect to FTP server
        ftp = ftplib.FTP()
        ftp.connect(ftp_config['host'], int(ftp_config['port']))
        ftp.login(ftp_config['username'], ftp_config['password'])
        
        # Change to the destination directory
        ftp.cwd(ftp_config['directory'])
        
        # Upload the file
        with open(file_path, 'rb') as file:
            ftp.storbinary(f'STOR {filename}', file)
            
        ftp.quit()
        logger.info(f"Successfully uploaded {filename} to FTP server")
        return True
    except Exception as e:
        logger.error(f"FTP upload error: {str(e)}")
        return False, str(e)

# Allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'wav'}

# Authentication routes - Client Credentials Grant
@app.route('/api/oauth/token', methods=['POST'])
def get_token():
    """
    OAuth 2.0 Client Credentials grant endpoint
    Expected request: form data with client_id, client_secret, and grant_type
    Returns: JSON with access_token and refresh_token
    """
    # Check grant type
    grant_type = request.form.get('grant_type')
    if grant_type != 'client_credentials' and grant_type != 'refresh_token':
        return jsonify({
            'error': 'unsupported_grant_type',
            'error_description': 'The authorization grant type is not supported'
        }), 400
    
    # Handle refresh token grant
    if grant_type == 'refresh_token':
        refresh_token = request.form.get('refresh_token')
        if not refresh_token:
            return jsonify({
                'error': 'invalid_request',
                'error_description': 'Missing refresh token'
            }), 400
            
        try:
            # Decode the refresh token
            data = jwt.decode(refresh_token, app.config['SECRET_KEY'], algorithms=["HS256"])
            
            # Verify this is a refresh token
            if data.get('type') != 'refresh':
                return jsonify({
                    'error': 'invalid_grant',
                    'error_description': 'Invalid token type'
                }), 400
            
            client_id = data.get('client_id')
            
            # Check if the refresh token is valid and matches stored token
            if (client_id not in refresh_tokens or 
                refresh_tokens[client_id]['token'] != refresh_token or 
                datetime.utcnow().timestamp() > refresh_tokens[client_id]['exp']):
                
                # If invalid, clear any existing token
                if client_id in refresh_tokens:
                    del refresh_tokens[client_id]
                    
                return jsonify({
                    'error': 'invalid_grant',
                    'error_description': 'Invalid or expired refresh token'
                }), 400
            
            # Get client role
            config = load_api_config()
            client_role = 'client'  # Default role
            if 'CLIENT_ROLES' in config and client_id in config['CLIENT_ROLES']:
                client_role = config['CLIENT_ROLES'][client_id]
            
            # Generate a new access token
            access_token_exp = datetime.utcnow() + timedelta(seconds=app.config['ACCESS_TOKEN_EXPIRATION'])
            new_access_token = jwt.encode({
                'client_id': client_id,
                'role': client_role,
                'exp': access_token_exp,
                'type': 'access'
            }, app.config['SECRET_KEY'], algorithm="HS256")
            
            return jsonify({
                'access_token': new_access_token,
                'token_type': 'bearer',
                'expires_in': app.config['ACCESS_TOKEN_EXPIRATION'],
                'expires_at': access_token_exp.isoformat()
            }), 200
            
        except jwt.ExpiredSignatureError:
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'Refresh token has expired'
            }), 400
        except jwt.InvalidTokenError:
            return jsonify({
                'error': 'invalid_grant',
                'error_description': 'Invalid refresh token'
            }), 400
    
    # Handle client credentials grant
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    
    if not client_id or not client_secret:
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Missing client credentials'
        }), 400
    
    config = load_api_config()
    
    if 'API_CLIENTS' not in config:
        return jsonify({
            'error': 'invalid_client',
            'error_description': 'No API clients configured'
        }), 500
        
    api_clients = config['API_CLIENTS']
    
    if client_id not in api_clients:
        return jsonify({
            'error': 'invalid_client',
            'error_description': 'Client not found'
        }), 401
    
    # Hash the provided secret for comparison
    client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
    
    if client_secret_hash != api_clients[client_id]:
        return jsonify({
            'error': 'invalid_client',
            'error_description': 'Invalid client secret'
        }), 401
    
    # Get client role
    client_role = 'client'  # Default role
    if 'CLIENT_ROLES' in config and client_id in config['CLIENT_ROLES']:
        client_role = config['CLIENT_ROLES'][client_id]
    
    # Generate access token
    access_token_exp = datetime.utcnow() + timedelta(seconds=app.config['ACCESS_TOKEN_EXPIRATION'])
    access_token = jwt.encode({
        'client_id': client_id,
        'role': client_role,
        'exp': access_token_exp,
        'type': 'access'
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    # Generate refresh token
    refresh_token_exp = datetime.utcnow() + timedelta(seconds=app.config['REFRESH_TOKEN_EXPIRATION'])
    refresh_token = jwt.encode({
        'client_id': client_id,
        'exp': refresh_token_exp,
        'type': 'refresh'
    }, app.config['SECRET_KEY'], algorithm="HS256")
    
    # Store the refresh token
    refresh_tokens[client_id] = {
        'token': refresh_token,
        'exp': refresh_token_exp.timestamp()
    }
    
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token,
        'token_type': 'bearer',
        'expires_in': app.config['ACCESS_TOKEN_EXPIRATION'],
        'refresh_expires_in': app.config['REFRESH_TOKEN_EXPIRATION'],
        'access_token_expires_at': access_token_exp.isoformat(),
        'refresh_token_expires_at': refresh_token_exp.isoformat(),
    }), 200

@app.route('/api/oauth/revoke', methods=['POST'])
def revoke_token():
    """
    Endpoint to revoke a refresh token
    Expected request: form data with client_id, client_secret, and token
    Returns: Success or error message
    """
    # Get client credentials
    client_id = request.form.get('client_id')
    client_secret = request.form.get('client_secret')
    token = request.form.get('token')
    
    if not client_id or not client_secret or not token:
        return jsonify({
            'error': 'invalid_request',
            'error_description': 'Missing required parameters'
        }), 400
    
    # Verify client credentials
    config = load_api_config()
    
    if 'API_CLIENTS' not in config or client_id not in config['API_CLIENTS']:
        return jsonify({
            'error': 'invalid_client',
            'error_description': 'Client not found'
        }), 401
    
    # Hash the provided secret for comparison
    client_secret_hash = hashlib.sha256(client_secret.encode()).hexdigest()
    
    if client_secret_hash != config['API_CLIENTS'][client_id]:
        return jsonify({
            'error': 'invalid_client',
            'error_description': 'Invalid client secret'
        }), 401
    
    try:
        # Decode the token without verification
        decoded = jwt.decode(token, options={"verify_signature": False})
        token_client_id = decoded.get('client_id')
        
        # Only allow client to revoke its own tokens
        if token_client_id != client_id:
            return jsonify({
                'error': 'invalid_request',
                'error_description': 'Cannot revoke token belonging to another client'
            }), 403
        
        # Remove the refresh token if it exists
        if client_id in refresh_tokens:
            del refresh_tokens[client_id]
            
        return jsonify({'message': 'Token successfully revoked'}), 200
    except:
        # If token decode fails, still return success
        return jsonify({'message': 'Token successfully revoked'}), 200

@app.route('/api/token/verify', methods=['GET'])
@token_required
def verify_token(current_client, client_role):
    """Verify if the token is valid"""
    return jsonify({
        'status': 'success',
        'message': 'Token is valid',
        'client_id': current_client,
        'role': client_role
    }), 200

# Client management endpoints (admin only)
@app.route('/api/clients', methods=['GET'])
@token_required
@admin_required
def get_clients(current_client, client_role):
    """Get list of API clients (admin only)"""
    config = load_api_config()
    
    if 'API_CLIENTS' in config:
        clients = []
        for client_id in config['API_CLIENTS']:
            role = 'client'
            if 'CLIENT_ROLES' in config and client_id in config['CLIENT_ROLES']:
                role = config['CLIENT_ROLES'][client_id]
            
            clients.append({
                'client_id': client_id,
                'role': role
            })
            
        return jsonify({
            'clients': clients,
            'count': len(clients)
        }), 200
    else:
        return jsonify({'message': 'No API clients configured!'}), 500

@app.route('/api/clients', methods=['POST'])
@token_required
@admin_required
def create_client(current_client, client_role):
    """Create a new API client (admin only)"""
    data = request.json
    
    if not data or not data.get('role'):
        return jsonify({'message': 'Client role required!'}), 400
    
    # Generate new client credentials
    new_client_id = f"client_{secrets.token_hex(8)}"
    new_client_secret = secrets.token_hex(16)
    new_client_secret_hash = hashlib.sha256(new_client_secret.encode()).hexdigest()
    
    # Get client role
    new_client_role = data.get('role', 'client')
    
    # Add to config
    config = load_api_config()
    
    if 'API_CLIENTS' not in config:
        config['API_CLIENTS'] = {}
    
    if 'CLIENT_ROLES' not in config:
        config['CLIENT_ROLES'] = {}
    
    config['API_CLIENTS'][new_client_id] = new_client_secret_hash
    config['CLIENT_ROLES'][new_client_id] = new_client_role
    
    # Save config
    with open('config.ini', 'w') as f:
        config.write(f)
    
    return jsonify({
        'message': 'Client created successfully',
        'client_id': new_client_id,
        'client_secret': new_client_secret,  # Only shown once
        'role': new_client_role
    }), 201

@app.route('/api/clients/<client_id>', methods=['DELETE'])
@token_required
@admin_required
def delete_client(current_client, client_role, client_id):
    """Delete an API client (admin only)"""
    # Cannot delete yourself
    if client_id == current_client:
        return jsonify({'message': 'Cannot delete your own client!'}), 400
    
    config = load_api_config()
    
    if 'API_CLIENTS' not in config or client_id not in config['API_CLIENTS']:
        return jsonify({'message': 'Client not found!'}), 404
    
    # Remove client
    del config['API_CLIENTS'][client_id]
    
    # Remove role if exists
    if 'CLIENT_ROLES' in config and client_id in config['CLIENT_ROLES']:
        del config['CLIENT_ROLES'][client_id]
    
    # Remove refresh token if exists
    if client_id in refresh_tokens:
        del refresh_tokens[client_id]
    
    # Save config
    with open('config.ini', 'w') as f:
        config.write(f)
    
    return jsonify({'message': 'Client deleted successfully'}), 200

# Protected routes
@app.route('/api/upload', methods=['POST'])
@token_required
def upload_audio(current_client, client_role):
    """
    API endpoint to upload a WAV file
    Expected request: multipart/form-data with 'audio_file' field
    Returns: JSON response with upload status
    """
    # Log the current client
    logger.info(f"Upload requested by client: {current_client} (role: {client_role})")
    
    # Check if the post request has the file part
    if 'audio_file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400
        
    file = request.files['audio_file']
    
    # If user does not select file, browser also
    # submit an empty part without filename
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400
        
    if file and allowed_file(file.filename):
        # Secure and create a unique filename
        filename = secure_filename(file.filename)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        unique_filename = f"{timestamp}_{current_client}_{filename}"
        
        # Save the file locally
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        file.save(file_path)
        logger.info(f"Saved file locally: {file_path}")
        
        # Upload to FTP server
        ftp_result = upload_to_ftp(file_path, unique_filename)
        if isinstance(ftp_result, tuple):
            # Upload failed with an error message
            return jsonify({
                'status': 'error',
                'message': 'Error uploading to FTP server',
                'error': ftp_result[1],
                'local_file': unique_filename
            }), 500
        elif ftp_result:
            # Upload succeeded
            return jsonify({
                'status': 'success',
                'message': 'File uploaded successfully',
                'filename': unique_filename,
                'local_path': file_path,
                'uploaded_by': current_client
            }), 201
        else:
            # Upload failed without specific error
            return jsonify({
                'status': 'error',
                'message': 'Error uploading to FTP server',
                'local_file': unique_filename
            }), 500
    else:
        return jsonify({'error': 'Invalid file type. Only WAV files are allowed.'}), 400

@app.route('/api/health', methods=['GET'])
def health_check():
    """Simple health check endpoint (public)"""
    return jsonify({'status': 'healthy'}), 200

@app.route('/api/config', methods=['GET'])
@token_required
def get_config(current_client, client_role):
    """Get FTP configuration (without password)"""
    config = load_api_config()
    # Remove password for security
    ftp_config = dict(config['FTP'])
    ftp_config['password'] = '********'  # Mask password
    return jsonify(ftp_config), 200

if __name__ == '__main__':
    logger.info("Starting Flask API application with Client Credentials authentication...")
    
    # Load config to generate credentials if needed
    config = load_api_config()
    
    # Start the server
    app.run(debug=True, host='0.0.0.0', port=5000)
