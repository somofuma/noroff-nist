"""
Web Interface - Flask-based GUI for the security tools suite
"""

from flask import Flask, render_template, request, jsonify
import os
import sys
from pathlib import Path
import tempfile
import hashlib

# Add the project root directory to the Python path
project_root = str(Path(__file__).resolve().parents[2])
if project_root not in sys.path:
    sys.path.append(project_root)

from core.password_cracker import PasswordCracker
from core.network_mapper import NetworkMapper
from core.directory_buster import DirectoryBuster
from core.login_cracker import LoginCracker

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize tools
password_cracker = PasswordCracker()
network_mapper = NetworkMapper()
directory_buster = DirectoryBuster()
login_cracker = LoginCracker()

# Define a list of valid credentials
valid_credentials = [
    ('testuser', 'testpass'),
    ('admin', 'admin123'),
    ('user1', 'pass1'),
    ('user2', 'pass2')
]

@app.route('/')
def index():
    """Render the main dashboard."""
    return render_template('index.html')

@app.route('/password-cracker', methods=['GET', 'POST'])
def crack_password():
    """Handle password cracking requests."""
    if request.method == 'POST':
        algorithm = request.form.get('algorithm', 'md5')
        wordlist_file = request.files['wordlist']
        
        # Save the uploaded wordlist file temporarily
        wordlist_path = os.path.join(tempfile.gettempdir(), wordlist_file.filename)
        wordlist_file.save(wordlist_path)
        
        try:
            results = []
            # Check for a single hash
            target_hash = request.form.get('hash')
            if target_hash:
                result = password_cracker.crack_hash(target_hash, wordlist_path, algorithm)
                results.append(result if result else 'Password not found')
            
            # Check for a file upload
            hash_file = request.files['hash_file']
            if hash_file:
                hash_file_path = os.path.join(tempfile.gettempdir(), hash_file.filename)
                hash_file.save(hash_file_path)
                with open(hash_file_path, 'r') as f:
                    for line in f:
                        hash_value = line.strip()
                        if hash_value:
                            result = password_cracker.crack_hash(hash_value, wordlist_path, algorithm)
                            results.append(result if result else 'Password not found')
                os.remove(hash_file_path)
            
            return jsonify({
                'success': True,
                'results': results
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            })
        finally:
            # Clean up the temporary wordlist file
            if os.path.exists(wordlist_path):
                os.remove(wordlist_path)
            
    return render_template('password_cracker.html')

@app.route('/network-mapper', methods=['GET', 'POST'])
def map_network():
    """Handle network mapping requests."""
    if request.method == 'POST':
        target = request.form.get('target')
        start_port = int(request.form.get('start_port', 1))
        end_port = int(request.form.get('end_port', 1024))
        
        try:
            results = network_mapper.scan_target(target, start_port, end_port)
            return jsonify({
                'success': True,
                'results': results
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            })
            
    return render_template('network_mapper.html')

@app.route('/directory-buster', methods=['GET', 'POST'])
def bust_directories():
    """Handle directory busting requests."""
    if request.method == 'POST':
        target_url = request.form.get('url')
        wordlist = request.form.get('wordlist')
        
        try:
            results = directory_buster.bust_directories(target_url, wordlist)
            return jsonify({
                'success': True,
                'results': results
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            })
            
    return render_template('directory_buster.html')

@app.route('/login-cracker', methods=['GET', 'POST'])
def login_cracker_route():
    if request.method == 'GET':
        return render_template('login_cracker.html')
    
    try:
        url = request.form.get('url')
        userlist_file = request.files['userlist']
        passlist_file = request.files['passlist']
        username_field = request.form.get('username_field')
        password_field = request.form.get('password_field')
        success_indicator = request.form.get('success_indicator')
        failure_indicator = request.form.get('failure_indicator')

        # Save the uploaded files temporarily
        userlist_path = os.path.join(tempfile.gettempdir(), userlist_file.filename)
        passlist_path = os.path.join(tempfile.gettempdir(), passlist_file.filename)
        userlist_file.save(userlist_path)
        passlist_file.save(passlist_path)

        # Call the LoginCracker
        results = login_cracker.crack_login_form(
            url=url,
            userlist_path=userlist_path,
            passlist_path=passlist_path,
            form_data={'username': username_field, 'password': password_field},
            success_indicator=success_indicator,
            failure_indicator=failure_indicator
        )

        # Clean up temporary files
        os.remove(userlist_path)
        os.remove(passlist_path)

        return jsonify({'success': True, 'results': results})

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        # Check against the list of valid credentials
        if (username, password) in valid_credentials:
            return f"Welcome, {username}!"
        else:
            return "Invalid credentials", 401
    return render_template('login.html')

@app.route('/generate-hashes', methods=['GET', 'POST'])
def generate_hashes():
    if request.method == 'POST':
        wordlist_file = request.files['wordlist']
        save_path = request.form.get('save_path')
        
        # Save the uploaded wordlist file temporarily
        wordlist_path = os.path.join(tempfile.gettempdir(), wordlist_file.filename)
        wordlist_file.save(wordlist_path)
        
        try:
            # Read the wordlist and generate hashes
            with open(wordlist_path, 'r') as f:
                passwords = [line.strip() for line in f if line.strip()]
            
            # Generate MD5 hashes
            hashes = []
            for password in passwords:
                hash_object = hashlib.md5(password.encode())
                md5_hash = hash_object.hexdigest()
                hashes.append(md5_hash)
            
            # Save the hashes to the specified path
            save_path = os.path.join(os.path.dirname(__file__), 'generated_hashes.txt')
            with open(save_path, 'w') as f:
                for hash_value in hashes:
                    f.write(f"{hash_value}\n")
            
            return jsonify({
                'success': True,
                'message': f'Hashes generated successfully and saved to {save_path}.',
            })
        except Exception as e:
            return jsonify({
                'success': False,
                'error': str(e)
            })
        finally:
            # Clean up the temporary wordlist file
            if os.path.exists(wordlist_path):
                os.remove(wordlist_path)
            
    return render_template('generate_hashes.html')

if __name__ == '__main__':
    app.run(debug=True) 