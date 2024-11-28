import os
from flask import Flask, request, render_template, url_for, send_from_directory
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import secrets

# Flask application setup
app = Flask(__name__)
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['ENCRYPTED_FOLDER'] = ENCRYPTED_FOLDER

# Ensure upload and encrypted directories exist
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)

# Generate ECC key pair for the server
server_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
server_public_key = server_private_key.public_key()

# Helper function to derive a shared AES key
def derive_aes_key(private_key, peer_public_key):
    shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
    derived_key = HKDF(
        algorithm=SHA256(),
        length=32,
        salt=None,
        info=b"file-sharing",
        backend=default_backend()
    ).derive(shared_key)
    return derived_key

# AES encryption function
def encrypt_file(file_path, aes_key):
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    iv = secrets.token_bytes(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return iv + ciphertext

@app.route('/')
def home():
    public_key_pem = server_public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()
    return render_template('index.html', server_public_key=public_key_pem)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files or 'client_key' not in request.form:
        return 'Missing file or client key', 400

    file = request.files['file']
    if file.filename == '':
        return 'No file selected', 400

    client_public_key_pem = request.form['client_key'].encode()
    client_public_key = serialization.load_pem_public_key(client_public_key_pem, backend=default_backend())
    aes_key = derive_aes_key(server_private_key, client_public_key)

    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)

    encrypted_data = encrypt_file(file_path, aes_key)
    encrypted_file_path = os.path.join(app.config['ENCRYPTED_FOLDER'], file.filename + '.enc')
    with open(encrypted_file_path, 'wb') as ef:
        ef.write(encrypted_data)
    
    os.remove(file_path)  # Remove the original file for security

    download_url = url_for('download_file', filename=file.filename + '.enc', _external=True)
    return render_template('upload_success.html', download_url=download_url)

@app.route('/downloads/<filename>')
def download_file(filename):
    return send_from_directory(app.config['ENCRYPTED_FOLDER'], filename)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
