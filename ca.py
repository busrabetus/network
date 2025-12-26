import socket
import json
import base64
import threading
import tkinter as tk
from tkinter.scrolledtext import ScrolledText
from datetime import datetime, timedelta

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

# ===============================
# LOG FUNCTION (GUI + TERMINAL)
# ===============================
def log(message):
    print(message)
    log_area.insert(tk.END, message + "\n")
    log_area.see(tk.END)

# ===============================
# CA KEY GENERATION
# ===============================
log_placeholder = None  # GUI gelmeden önce hata olmasın

print("[CA] Starting Certificate Authority...")

ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)
ca_public_key = ca_private_key.public_key()

print("[CA] CA public/private keys generated.")

# ===============================
# SOCKET SERVER SETUP
# ===============================
HOST = "0.0.0.0"
PORT = 5050

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((HOST, PORT))
server_socket.listen(5)

print(f"[CA] Listening on port {PORT}...")

# ===============================
# CA SERVER FUNCTION
# ===============================
def run_ca_server():
    log("[CA] Waiting for client connections...")

    conn, addr = server_socket.accept()
    log(f"[CA] Connection received from {addr}")

    data = conn.recv(4096).decode()
    log("[CA] Data received from client:")
    log(data)

    request = json.loads(data)

    subject_id = request["subject_id"]
    client_public_key = request["public_key"]

    log(f"[CA] Creating certificate for {subject_id}")

    certificate = {
        "subject_id": subject_id,
        "algorithm": "RSA",
        "public_key": client_public_key,
        "serial_number": "CERT-" + datetime.now().strftime("%Y%m%d%H%M%S"),
        "valid_from": str(datetime.now().date()),
        "valid_to": str((datetime.now() + timedelta(days=365)).date())
    }

    # ===============================
    # SIGN CERTIFICATE
    # ===============================
    certificate_bytes = json.dumps(certificate, sort_keys=True).encode()

    signature = ca_private_key.sign(
        certificate_bytes,
        padding.PKCS1v15(),
        hashes.SHA256()
    )

    certificate["signature"] = base64.b64encode(signature).decode()

    log("[CA] Certificate signed.")

    conn.send(json.dumps(certificate).encode())
    conn.close()

    log("[CA] Certificate sent to client.")

# ===============================
# GUI SETUP
# ===============================
root = tk.Tk()
root.title("Certificate Authority")

status_label = tk.Label(
    root,
    text="CA is running",
    fg="green",
    font=("Arial", 14)
)
status_label.pack(pady=10)

log_area = ScrolledText(root, width=80, height=20)
log_area.pack(padx=10, pady=10)

# Start server thread
server_thread = threading.Thread(target=run_ca_server, daemon=True)
server_thread.start()

# Initial logs
log("[CA] Starting Certificate Authority...")
log("[CA] CA public/private keys generated.")
log(f"[CA] Listening on port {PORT}...")

root.mainloop()
