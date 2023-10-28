import bcrypt

password = b"my_secure_password"
hashed_password = bcrypt.hashpw(password, bcrypt.gensalt())

# Verify a password
if bcrypt.checkpw(b"entered_password", hashed_password):
    print("Password is correct.")
else:
    print("Password is incorrect.")



from cryptography.fernet import Fernet

key = Fernet.generate_key()
cipher_suite = Fernet(key)

text = "This is a secret message.".encode('utf-8')
encrypted_text = cipher_suite.encrypt(text)
decrypted_text = cipher_suite.decrypt(encrypted_text)

print("Decrypted Text:", decrypted_text.decode('utf-8'))



from flask import Flask

app = Flask(__name__)

@app.after_request
def add_security_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'self'"
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response




import socket
import ssl

context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations('ca-certificates.crt')

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    with context.wrap_socket(s, server_hostname='example.com') as secure_socket:
        secure_socket.connect(('example.com', 443))
