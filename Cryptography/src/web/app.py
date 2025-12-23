"""
Flask web application for CryptoVault
"""

import os
import sys
from flask import Flask, render_template, request, jsonify, session, redirect, url_for, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from urllib.parse import quote, unquote
import hashlib
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.auth.models import db, User
from src.cryptovault import CryptoVault
from src.messaging import MessagingModule
from email_service_factory import get_email_service

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(32)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cryptovault.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize database
db.init_app(app)

# Initialize CryptoVault and services
vault = CryptoVault()
messaging = MessagingModule()
email_service = get_email_service()

# Create upload directory
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('encrypted_files', exist_ok=True)


def create_tables():
    """Create database tables"""
    with app.app_context():
        db.create_all()

# Create tables on startup
create_tables()


@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration"""
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '').strip()
        password = data.get('password', '')
        email = data.get('email', '').strip()
        
        # Validate required fields
        if not username:
            return jsonify({'success': False, 'error': 'Username is required'}), 400
        if not password:
            return jsonify({'success': False, 'error': 'Password is required'}), 400
        if not email:
            return jsonify({'success': False, 'error': 'Email is required'}), 400
        
        success, error = vault.register(username, password, email)
        
        if success:
            return jsonify({'success': True, 'message': 'Registration successful'})
        else:
            return jsonify({'success': False, 'error': error}), 400
    
    return render_template('register.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login"""
    if request.method == 'POST':
        data = request.get_json()
        username = data.get('username', '')
        password = data.get('password', '')
        totp_code = data.get('totp_code', '')
        ip_address = request.remote_addr
        
        success, error, token = vault.login(username, password, totp_code, ip_address)
        
        if success:
            session['token'] = token
            session['username'] = username
            user = User.query.filter_by(username=username).first()
            session['user_id'] = user.id
            return jsonify({'success': True, 'token': token})
        else:
            return jsonify({'success': False, 'error': error}), 401
    
    return render_template('login.html')


@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    """Password reset request page"""
    if request.method == 'POST':
        data = request.get_json()
        identifier = data.get('identifier', '')
        
        success, error, reset_token = vault.request_password_reset(identifier)
        
        if success:
            # Get user email for sending reset link
            from src.auth.models import User
            user = User.query.filter(
                (User.username == identifier) | (User.email == identifier)
            ).first()
            
            if user and user.email:
                # Construct reset URL
                reset_url = request.host_url.rstrip('/') + url_for('reset_password', token=reset_token)
                
                # Send password reset email via Mailjet
                email_success, email_error = email_service.send_password_reset_email(
                    to_email=user.email,
                    username=user.username,
                    reset_token=reset_token,
                    reset_url=reset_url
                )
                
                if email_success:
                    return jsonify({
                        'success': True, 
                        'message': 'Password reset link has been sent to your email address'
                    })
                else:
                    # Email failed but token was created
                    return jsonify({
                        'success': False,
                        'error': f'Failed to send reset email: {email_error}. Please try again.'
                    }), 400
            else:
                return jsonify({
                    'success': False,
                    'error': 'No email address associated with this account'
                }), 400
        else:
            return jsonify({'success': False, 'error': error}), 400
    
    return render_template('forgot_password.html')


@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    """Password reset form"""
    if request.method == 'POST':
        data = request.get_json()
        new_password = data.get('password', '')
        
        success, error = vault.reset_password(token, new_password)
        
        if success:
            return jsonify({'success': True, 'message': 'Password reset successful'})
        else:
            return jsonify({'success': False, 'error': error}), 400
    
    return render_template('reset_password.html', token=token)


@app.route('/logout')
def logout():
    """Logout user"""
    token = session.get('token')
    if token:
        vault.auth_login.logout(token)
    session.clear()
    return redirect(url_for('index'))


@app.route('/dashboard')
def dashboard():
    """User dashboard"""
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    
    user = vault.auth_login.verify_session(token)
    if not user:
        return redirect(url_for('login'))
    
    return render_template('dashboard.html', username=user.username)


@app.route('/setup_totp', methods=['POST'])
def setup_totp():
    """Setup TOTP for user"""
    token = session.get('token')
    if not token:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user = vault.auth_login.verify_session(token)
    if not user:
        return jsonify({'success': False, 'error': 'Invalid session'}), 401

    # Reload user from DB to ensure we have latest fields (fresh totp_secret)
    from src.auth.models import User as UserModel
    user = UserModel.query.get(user.id)
    if not user:
        return jsonify({'success': False, 'error': 'User not found'}), 404
    
    success, error, totp_data = vault.setup_totp(user.username)

    if success:
        # Return secret and QR code, TOTP will be enabled only after confirmation
        return jsonify({'success': True, 'data': totp_data})
    else:
        return jsonify({'success': False, 'error': error}), 400


@app.route('/confirm_totp', methods=['POST'])
def confirm_totp():
    """Confirm and enable TOTP by verifying the first code"""
    token = session.get('token')
    if not token:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401

    user = vault.auth_login.verify_session(token)
    if not user:
        return jsonify({'success': False, 'error': 'Invalid session'}), 401

    data = request.get_json() or {}
    code = (data.get('code') or '').strip()
    if not code:
        return jsonify({'success': False, 'error': 'TOTP code required'}), 400

    # Verify code against stored secret
    if vault.totp_manager.verify_totp(user, code):
        vault.totp_manager.enable_totp(user)
        return jsonify({'success': True})
    else:
        return jsonify({'success': False, 'error': 'Invalid TOTP code'}), 400


@app.route('/messaging')
def messaging_page():
    """Secure messaging page"""
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    
    user = vault.auth_login.verify_session(token)
    if not user:
        return redirect(url_for('login'))
    
    return render_template('messaging.html', username=user.username)


@app.route('/api/generate_keypair', methods=['POST'])
def generate_keypair():
    """Generate messaging key pair"""
    token = session.get('token')
    if not token:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user = vault.auth_login.verify_session(token)
    if not user:
        return jsonify({'success': False, 'error': 'Invalid session'}), 401
    
    private_key, public_key = messaging.generate_keypair()
    private_pem, public_pem = messaging.serialize_keypair(private_key)
    
    return jsonify({
        'success': True,
        'private_key': private_pem,
        'public_key': public_pem
    })


@app.route('/api/send_message', methods=['POST'])
def send_message():
    """Send encrypted message"""
    token = session.get('token')
    if not token:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user = vault.auth_login.verify_session(token)
    if not user:
        return jsonify({'success': False, 'error': 'Invalid session'}), 401
    
    data = request.get_json()
    recipient_public_key = data.get('recipient_public_key', '')
    message = data.get('message', '')
    sender_private_key = data.get('sender_private_key', '')
    
    try:
        encrypted = vault.send_message(recipient_public_key, message, sender_private_key)
        return jsonify({'success': True, 'encrypted': encrypted})
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/receive_message', methods=['POST'])
def receive_message():
    """Receive and decrypt message"""
    token = session.get('token')
    if not token:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user = vault.auth_login.verify_session(token)
    if not user:
        return jsonify({'success': False, 'error': 'Invalid session'}), 401
    
    data = request.get_json()
    encrypted_data = data.get('encrypted_data', {})
    recipient_private_key = data.get('recipient_private_key', '')
    sender_public_key = data.get('sender_public_key', '')
    
    try:
        message = vault.receive_message(encrypted_data, recipient_private_key, sender_public_key)
        if message:
            return jsonify({'success': True, 'message': message})
        else:
            return jsonify({'success': False, 'error': 'Decryption failed. Check that keys are correct and match the encrypted message.'}), 400
    except Exception as e:
        error_msg = str(e)
        # Provide more helpful error messages
        if 'Could not deserialize' in error_msg or 'unsupported' in error_msg.lower():
            return jsonify({'success': False, 'error': 'Invalid key format. Make sure keys are in PEM format.'}), 400
        elif 'Decryption error' in error_msg:
            return jsonify({'success': False, 'error': error_msg}), 400
        else:
            return jsonify({'success': False, 'error': f'Decryption failed: {error_msg}'}), 400


@app.route('/files')
def files_page():
    """File encryption page"""
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    
    user = vault.auth_login.verify_session(token)
    if not user:
        return redirect(url_for('login'))
    
    return render_template('files.html', username=user.username)


@app.route('/api/encrypt_file', methods=['POST'])
def encrypt_file():
    """Encrypt uploaded file"""
    token = session.get('token')
    if not token:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user = vault.auth_login.verify_session(token)
    if not user:
        return jsonify({'success': False, 'error': 'Invalid session'}), 401
    
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file provided'}), 400
    
    file = request.files['file']
    password = request.form.get('password', '')
    
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No file selected'}), 400
    
    if not password:
        return jsonify({'success': False, 'error': 'Password required'}), 400
    
    filename = secure_filename(file.filename)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
    file.save(file_path)
    
    try:
        output_path = os.path.join('encrypted_files', filename + '.encrypted')
        success, error, metadata = vault.encrypt_file(file_path, password, user.username, output_path)
        
        if success:
            return jsonify({
                'success': True,
                'encrypted_file': output_path,
                'metadata': metadata
            })
        else:
            return jsonify({'success': False, 'error': error}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


@app.route('/api/decrypt_file', methods=['POST'])
def decrypt_file():
    """Decrypt file"""
    token = session.get('token')
    if not token:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user = vault.auth_login.verify_session(token)
    if not user:
        return jsonify({'success': False, 'error': 'Invalid session'}), 401
    
    data = request.get_json()
    if not data:
        return jsonify({'success': False, 'error': 'Invalid request data'}), 400
    
    encrypted_file_path = data.get('encrypted_file_path', '').strip()
    password = data.get('password', '')
    
    if not encrypted_file_path or not password:
        return jsonify({'success': False, 'error': 'Missing parameters: encrypted_file_path and password are required'}), 400
    
    # Ensure path is relative to project root or handle absolute paths
    if not os.path.isabs(encrypted_file_path):
        # If relative path doesn't start with encrypted_files/, add it
        if not encrypted_file_path.startswith('encrypted_files'):
            encrypted_file_path = os.path.join('encrypted_files', encrypted_file_path)
    
    try:
        output_path = os.path.join('encrypted_files', 'decrypted_' + os.path.basename(encrypted_file_path).replace('.encrypted', ''))
        success, error = vault.decrypt_file(encrypted_file_path, password, user.username, output_path)
        
        if success:
            filename = os.path.basename(output_path)  # e.g., "decrypted_esp32.jpg"
            return jsonify({
                'success': True,
                'decrypted_file': output_path,
                'decrypted_filename': filename,  # Pass filename separately
                'download_url': f'/api/download_file?file={quote(filename)}'
            })
        else:
            return jsonify({'success': False, 'error': error}), 400
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 400


@app.route('/api/download_file')
def download_file():
    """Download decrypted file"""
    try:
        token = session.get('token')
        if not token:
            return jsonify({'success': False, 'error': 'Not authenticated. Please log in.'}), 401
        
        user = vault.auth_login.verify_session(token)
        if not user:
            return jsonify({'success': False, 'error': 'Invalid session. Please log in again.'}), 401
        
        filename = unquote(request.args.get('file', ''))
        if not filename:
            return jsonify({'success': False, 'error': 'No file specified'}), 400
        
        # Security: ensure file is in encrypted_files directory and starts with 'decrypted_'
        if not filename.startswith('decrypted_'):
            return jsonify({'success': False, 'error': 'Invalid file'}), 400
        
        # Try multiple path resolution methods
        file_path = None
        
        # Method 1: Relative to current working directory
        test_path = os.path.join('encrypted_files', filename)
        if os.path.exists(test_path):
            file_path = os.path.abspath(test_path)
        else:
            # Method 2: Relative to app.py location
            app_dir = os.path.dirname(os.path.abspath(__file__))  # src/web/
            project_root = os.path.dirname(os.path.dirname(app_dir))  # Cryptography/
            test_path = os.path.join(project_root, 'encrypted_files', filename)
            if os.path.exists(test_path):
                file_path = os.path.abspath(test_path)
        
        if not file_path or not os.path.exists(file_path):
            return jsonify({
                'success': False, 
                'error': f'File not found: {filename}',
                'debug': {
                    'filename': filename,
                    'test_path_1': os.path.join('encrypted_files', filename),
                    'exists_1': os.path.exists(os.path.join('encrypted_files', filename)),
                    'cwd': os.getcwd()
                }
            }), 404
        
        # Normalize path
        file_path = os.path.normpath(file_path)
        
        # Security: prevent directory traversal
        if '..' in filename:
            return jsonify({'success': False, 'error': 'Invalid filename'}), 400
        
        # Keep the filename with 'decrypted_' prefix as requested by user
        # Format: decrypted_[filename].type
        original_filename = filename  # Keep decrypted_ prefix
        
        # Determine MIME type based on extension (use filename with decrypted_ prefix)
        ext = os.path.splitext(original_filename)[1].lower()
        mime_types = {
            '.jpg': 'image/jpeg',
            '.jpeg': 'image/jpeg',
            '.png': 'image/png',
            '.gif': 'image/gif',
            '.pdf': 'application/pdf',
            '.txt': 'text/plain',
            '.zip': 'application/zip',
            '.doc': 'application/msword',
            '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
        }
        mimetype = mime_types.get(ext, 'application/octet-stream')
        
        return send_file(
            file_path,
            as_attachment=True,
            download_name=original_filename,
            mimetype=mimetype
        )
    except Exception as e:
        import traceback
        return jsonify({
            'success': False,
            'error': f'Error downloading file: {str(e)}',
            'traceback': traceback.format_exc()
        }), 500


@app.route('/audit')
def audit_page():
    """Audit trail page"""
    token = session.get('token')
    if not token:
        return redirect(url_for('login'))
    
    user = vault.auth_login.verify_session(token)
    if not user:
        return redirect(url_for('login'))
    
    return render_template('audit.html', username=user.username)


@app.route('/api/audit_trail')
def get_audit_trail():
    """Get audit trail from blockchain"""
    token = session.get('token')
    if not token:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user = vault.auth_login.verify_session(token)
    if not user:
        return jsonify({'success': False, 'error': 'Invalid session'}), 401
    
    chain = vault.get_audit_trail()
    pending_count = len(vault.ledger.pending_transactions)
    return jsonify({
        'success': True, 
        'chain': chain,
        'pending_transactions': pending_count
    })


@app.route('/api/verify_chain')
def verify_chain():
    """Verify blockchain integrity"""
    token = session.get('token')
    if not token:
        return jsonify({'success': False, 'error': 'Not authenticated'}), 401
    
    user = vault.auth_login.verify_session(token)
    if not user:
        return jsonify({'success': False, 'error': 'Invalid session'}), 401
    
    is_valid = vault.verify_chain_integrity()
    chain_length = len(vault.ledger.chain)
    
    return jsonify({
        'success': True,
        'valid': is_valid,
        'chain_length': chain_length,
        'message': 'Chain is valid and untampered' if is_valid else 'Chain integrity check failed - tampering detected!'
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)

