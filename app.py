import os
import base64
import secrets
from io import BytesIO
from flask import Flask, render_template, request, send_file, flash, redirect, url_for
from werkzeug.utils import secure_filename
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding as rsa_padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from PIL import Image

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'

UPLOAD_FOLDER = 'uploads'
KEY_FOLDER = 'keys'

for folder in (UPLOAD_FOLDER, KEY_FOLDER):
    if not os.path.exists(folder):
        os.makedirs(folder)

# Generate/load Fernet key
FERNET_PATH = os.path.join(KEY_FOLDER, 'fernet.key')
if not os.path.exists(FERNET_PATH):
    key = Fernet.generate_key()
    with open(FERNET_PATH, 'wb') as f:
        f.write(key)
else:
    with open(FERNET_PATH, 'rb') as f:
        key = f.read()
fernet = Fernet(key)

# Generate/load RSA keys
RSA_PRIVATE_PATH = os.path.join(KEY_FOLDER, 'rsa_private.pem')
RSA_PUBLIC_PATH = os.path.join(KEY_FOLDER, 'rsa_public.pem')
if not os.path.exists(RSA_PRIVATE_PATH) or not os.path.exists(RSA_PUBLIC_PATH):
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    with open(RSA_PRIVATE_PATH, 'wb') as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()))
    with open(RSA_PUBLIC_PATH, 'wb') as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
else:
    with open(RSA_PRIVATE_PATH, 'rb') as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    with open(RSA_PUBLIC_PATH, 'rb') as f:
        public_key = serialization.load_pem_public_key(f.read())

ALLOWED_EXTENSIONS = {'txt', 'py', 'xlsx', 'csv', 'json', 'log'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.',1)[1].lower() in ALLOWED_EXTENSIONS

def text_to_image(text):
    ascii_values = [ord(c) for c in text]
    length = len(ascii_values)
    size = int(length ** 0.5) + 1
    img = Image.new('RGB', (size, size), color='black')
    pixels = img.load()
    for i, val in enumerate(ascii_values):
        x = i % size
        y = i // size
        pixels[x, y] = (val, val, val)
    # padding remaining pixels
    for j in range(length, size*size):
        x = j % size
        y = j // size
        pixels[x, y] = (0,0,0)
    return img

def image_to_text(img):
    pixels = img.load()
    w, h = img.size
    chars = []
    for y in range(h):
        for x in range(w):
            val = pixels[x, y][0]
            if val == 0:
                return ''.join(chars)
            chars.append(chr(val))
    return ''.join(chars)

def encrypt_text(text, algorithm='Fernet'):
    if algorithm == 'Fernet':
        return fernet.encrypt(text.encode()).decode()
    elif algorithm == 'RSA':
        ciphertext = public_key.encrypt(
            text.encode(),
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        return base64.urlsafe_b64encode(ciphertext).decode()
    elif algorithm == 'AES':
        key_bytes = secrets.token_bytes(32)
        iv = secrets.token_bytes(16)
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padding_len = 16 - (len(text) % 16)
        padded_text = text + chr(padding_len) * padding_len
        ciphertext = encryptor.update(padded_text.encode()) + encryptor.finalize()
        combined = key_bytes + iv + ciphertext
        return base64.urlsafe_b64encode(combined).decode()
    else:
        return "Unsupported algorithm"

def decrypt_text(token, algorithm='Fernet'):
    if algorithm == 'Fernet':
        return fernet.decrypt(token.encode()).decode()
    elif algorithm == 'RSA':
        ciphertext = base64.urlsafe_b64decode(token.encode())
        plaintext = private_key.decrypt(
            ciphertext,
            rsa_padding.OAEP(
                mgf=rsa_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None))
        return plaintext.decode()
    elif algorithm == 'AES':
        data_bytes = base64.urlsafe_b64decode(token.encode())
        key_bytes = data_bytes[:32]
        iv = data_bytes[32:48]
        ciphertext = data_bytes[48:]
        cipher = Cipher(algorithms.AES(key_bytes), modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded_plain = decryptor.update(ciphertext) + decryptor.finalize()
        pad_len = padded_plain[-1]
        return padded_plain[:-pad_len].decode()
    else:
        return "Unsupported algorithm"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['GET','POST'])
def encrypt_page():
    if request.method == 'POST':
        text = request.form.get('text','')
        file = request.files.get('file')
        algorithm = request.form.get('algorithm','Fernet')
        output_type = request.form.get('output_type','text')
        data_to_encrypt = ''
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            file.save(filepath)
            with open(filepath,'r',encoding='utf-8',errors='ignore') as f:
                data_to_encrypt=f.read()
            os.remove(filepath)
        elif text.strip():
            data_to_encrypt=text
        else:
            flash('Please provide text or upload a supported file.')
            return redirect(url_for('encrypt_page'))

        enc_data = encrypt_text(data_to_encrypt, algorithm)

        if output_type=='text':
            return render_template('popup.html', title="Encrypted Text", data=enc_data, copybutton=True)
        else:
            img = text_to_image(enc_data)
            img_io = BytesIO()
            img.save(img_io,'PNG')
            img_io.seek(0)
            return send_file(img_io,mimetype='image/png',as_attachment=True, download_name='encrypted_image.png')
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET','POST'])
def decrypt_page():
    if request.method=='POST':
        input_type = request.form.get('input_type','text')
        algorithm = request.form.get('algorithm','Fernet')

        if input_type=='text':
            enc_text = request.form.get('encrypted_text','')
            if not enc_text.strip():
                flash('Paste the encrypted text!')
                return redirect(url_for('decrypt_page'))
            try:
                dec = decrypt_text(enc_text,algorithm)
                return render_template('popup.html', title="Decrypted Text", data=dec)
            except:
                flash('Decryption failed.')
                return redirect(url_for('decrypt_page'))
        elif input_type=='image':
            enc_image = request.files.get('encrypted_image')
            if not enc_image:
                flash('Upload the encrypted image!')
                return redirect(url_for('decrypt_page'))
            try:
                img = Image.open(enc_image)
                encrypted_text = image_to_text(img)
                dec = decrypt_text(encrypted_text,algorithm)
                return render_template('popup.html', title='Decrypted Text', data=dec)
            except:
                flash('Decryption failed.')
                return redirect(url_for('decrypt_page'))
    return render_template('decrypt.html')

if __name__ == '__main__':
    app.run(debug=True)