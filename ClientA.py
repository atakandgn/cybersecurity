# ClientA.py
import socket
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import tkinter as tk
from tkinter import filedialog
from cryptography.fernet import Fernet
import pickle
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def symmetric_encrypt(data, key):
    # Encrypt data using Fernet symmetric encryption
    cipher = Fernet(key)
    ciphertext = cipher.encrypt(data.encode())
    return ciphertext

def generate_key():
    # Generate a key using PBKDF2 with a strong password and random salt
    password = b"secret_password"
    salt = b"salt"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        iterations=100000,
        salt=salt,
        length=32,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

# Key generation and handling functions

def generate_key_pair():
    # Generate an RSA key pair
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_key_to_file(key, filename):
    # Save a key to a file
    with open(filename, 'wb') as file:
        file.write(key)

def load_key_from_file(filename):
    # Load a key from a file
    with open(filename, 'rb') as file:
        key = file.read()
    return key

def check_key_exists(filename):
    # Check if a key file exists
    return os.path.isfile(filename)

def sign_message(private_key, message):
    # Sign a message using an RSA private key and SHA-256 hash function
    key = RSA.import_key(private_key)
    h = SHA256.new(message)
    signature = pkcs1_15.new(key).sign(h)
    return signature

# File upload and communication functions

def upload_file():
    # Prompt user to select a file and return the file path
    file_path = filedialog.askopenfilename()
    return file_path

def send_file(choice, file_path):
    # Send file to the server based on the user's choice

    # Server address and port
    host = '127.0.0.1'
    port = 12345

    # Create a socket and attempt to connect to the server
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        client_socket.connect((host, port))
    except Exception as e:
        # Display an error message if the connection fails
        print("Connection error:", str(e))
        show_error_message("Connection Error", "Could not establish a connection with the server.")
        return

    with open(file_path, 'rb') as file:
        file_content = file.read()

    if choice == 1:
        # Send the file content without encryption
        client_socket.send(b'1' + file_content)

    elif choice == 2:
        # Encrypt the file content symmetrically and send it
        key = generate_key()
        cipher = Fernet(key)
        data = file_content.decode("utf-8")
        encrypted_content = cipher.encrypt(data.encode())
        client_socket.send(b'2' + encrypted_content)

    elif choice == 3:
        # Digital signature
        if not check_key_exists("A_public_key.pem") or not check_key_exists("A_private_key.pem"):
            private_key_A, public_key_A = generate_key_pair()
            save_key_to_file(private_key_A, 'A_private_key.pem')
            save_key_to_file(public_key_A, 'A_public_key.pem')
        else:
            private_key_A = load_key_from_file('A_private_key.pem')
            public_key_A = load_key_from_file('A_public_key.pem')
            
        signature = sign_message(private_key_A, file_content)
        data = {
            'public_key': public_key_A,
            'message': file_content,
            'signature': signature
        }
        client_socket.send(b'3' + pickle.dumps(data))

    elif choice == 4:
        # Encrypt and sign the file content, then send it with the public key and signature
        key = generate_key()
        cipher = Fernet(key)
        data = file_content.decode("utf-8")
        encrypted_content = cipher.encrypt(data.encode())
        if not check_key_exists("A_public_key.pem") or not check_key_exists("A_private_key.pem"):
            private_key_A, public_key_A = generate_key_pair()
            save_key_to_file(private_key_A, 'A_private_key.pem')
            save_key_to_file(public_key_A, 'A_public_key.pem')
        else : 
            private_key_A = load_key_from_file('A_private_key.pem')
            public_key_A = load_key_from_file('A_public_key.pem')
            
        signature = sign_message(private_key_A, encrypted_content)
        data = {
            'public_key': public_key_A,
            'message': encrypted_content,
            'signature': signature
        }
        combined_data = b'4' + pickle.dumps(data)
        client_socket.sendall(combined_data)

    else:
        # Display an error message for an invalid choice
        print("Invalid choice.")

    # Close the connection
    client_socket.close()

# UI functions

def show_error_message(title, message):
    # Display an error message to the user
    error_window = tk.Tk()
    error_window.title(title)
    error_label = tk.Label(error_window, text=message, padx=10, pady=10)
    error_label.pack()
    error_window.mainloop()

def show_help(root):
    # Display help text in a separate window
    help_text = """
    How to Use the Program:

    1. Click '1. Upload File' to select a file for uploading.
    2. Choose an option: (Before you choose an option, receiver should be running and click to receive button for the file send.)
       - '2.1 Symmetric Encryption' for basic encryption.
       - '2.2 Digital Signature' for digital signature.
       - '2.3. Encrypt and Sign' for both encryption and signature.
    3. Follow the prompts to complete the chosen operation.

    NOTES: 
    ! Make sure to select a file before choosing an option.
    ! Make sure to click "Receive File" before sending a file from ClientA.
    """
    help_window = tk.Toplevel(root)
    help_window.title("Help")
    help_label = tk.Label(help_window, text=help_text, padx=10, pady=10)
    help_label.pack()

def main():

    # Initialize the main UI and event loop
    root = tk.Tk()
    root.title("File Encryption")
    root.geometry("400x200+{}+{}".format(root.winfo_screenwidth() // 2 - 200, root.winfo_screenheight() // 2 - 100))

    file_path = ""

    # Function for selecting a file
    def select_file():
        nonlocal file_path
        file_path = upload_file()
        file_label.config(text="Selected File: " + file_path)

    # Function for sending the chosen option
    def send_choice(choice):
        nonlocal file_path
        if not file_path:
            file_label.config(text="Please select a file.")
            return
        send_file(choice, file_path)

    # UI elements are created and placed
    file_label = tk.Label(root, text="")
    file_label.pack()

    file_upload_button = tk.Button(
        root, text="1. Upload File", command=select_file)
    file_upload_button.pack()

    encrypt_button = tk.Button(
        root, text="2. Symmetric Encryption", command=lambda: send_choice(2))
    encrypt_button.pack()

    signature_button = tk.Button(
        root, text="3. Digital Signature", command=lambda: send_choice(3))
    signature_button.pack()

    encrypt_signature_button = tk.Button(
        root, text="4. Encrypt and Sign", command=lambda: send_choice(4))
    encrypt_signature_button.pack()

    help_button = tk.Button(root, text="Help", command=lambda: show_help(root))
    help_button.pack()

    # Start the event loop
    root.mainloop()

# Check if the script is executed directly
if __name__ == "__main__":
    # Call the main function to start the program
    main()
