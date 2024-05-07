from flask import Flask, render_template, request, redirect, url_for
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)

def generate_key():
    return get_random_bytes(16)

def encrypt(plain_text, key):
    cipher = AES.new(key, AES.MODE_CBC)
    cipher_text = cipher.encrypt(pad(plain_text.encode(), AES.block_size))
    return cipher.iv + cipher_text

def decrypt(cipher_text, key):
    iv = cipher_text[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_text = unpad(cipher.decrypt(cipher_text[AES.block_size:]), AES.block_size)
    return decrypted_text.decode()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt_text():
    key = generate_key()
    plain_text = request.form['plain_text']
    cipher_text = encrypt(plain_text, key)
    return render_template('result_encrypt.html', plain_text=plain_text, cipher_text=cipher_text.hex(), key=key.hex())

@app.route('/decrypt', methods=['POST'])
def decrypt_text():
    try:
        key = bytes.fromhex(request.form['key'])
        cipher_text = bytes.fromhex(request.form['cipher_text'])
        decrypted_text = decrypt(cipher_text, key)
        return render_template('result_decrypt.html', plain_text=decrypted_text, cipher_text=cipher_text, key=key.hex())
    except Exception as e:
        return redirect(url_for('error'))

@app.route('/error')
def error():
    return render_template('error.html')

if __name__ == '__main__':
    app.run(debug=True)
