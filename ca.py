from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import socket
import json
from datetime import datetime, timedelta
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

print("[CA] Starting Certificate Authority...")

# 1. CA PRIVATE KEY
ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

# 2. CA PUBLIC KEY
ca_public_key = ca_private_key.public_key()

print("[CA] CA public/private keys generated.")

# ===============================
# SOCKET SERVER SETUP
# ===============================
HOST = "0.0.0.0"   # herkes bağlanabilsin
PORT = 5050        # CA portu

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)

print(f"[CA] Listening on port {PORT}...")


print("[CA] Waiting for client connections...")

conn, addr = server_socket.accept()
print(f"[CA] Connection received from {addr}")

data = conn.recv(4096).decode()
print("[CA] Data received from client:")
print(data)

request = json.loads(data)

subject_id = request["subject_id"]
client_public_key = request["public_key"]

print(f"[CA] Creating certificate for {subject_id}")

from datetime import datetime, timedelta

certificate = {
    "subject_id": subject_id,
    "algorithm": "RSA",
    "public_key": client_public_key,
    "serial_number": "CERT-" + datetime.now().strftime("%Y%m%d%H%M%S"),
    "valid_from": str(datetime.now().date()),
    "valid_to": str((datetime.now() + timedelta(days=365)).date())
}

print("[CA] Certificate created (unsigned):")
print(json.dumps(certificate, indent=2))

# ===============================
# SIGN CERTIFICATE
# ===============================
certificate_bytes = json.dumps(certificate, sort_keys=True).encode()

signature = ca_private_key.sign(
    certificate_bytes,
    padding.PKCS1v15(),
    hashes.SHA256()
)

signature_b64 = base64.b64encode(signature).decode()
certificate["signature"] = signature_b64

print("[CA] Certificate signed.")
print(json.dumps(certificate, indent=2))

conn.send(json.dumps(certificate).encode())
conn.close()

print("[CA] Certificate sent to client.")