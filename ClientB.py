# https://github.com/atakandgn/cybersecurity/blob/main/README.md
import socket
import os
import tkinter as tk
from tkinter import filedialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
from cryptography.fernet import Fernet
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import pickle

# Global variables for GUI components
result_label = None
clear_button = None

# Symmetric decryption function
def symmetric_decrypt(ciphertext, key):
    cipher = Fernet(key)
    decrypted_data = cipher.decrypt(ciphertext)
    return decrypted_data.decode("utf-8")

# Key generation functions
def generate_key():
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

def generate_key_pair():
    # Generate an RSA key pair with 2048 bits
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

# Key file handling functions
def save_key_to_file(key, filename):
    # Save the key to a file
    with open(filename, 'wb') as file:
        file.write(key)

def load_key_from_file(filename):
    # Load the key from a file
    with open(filename, 'rb') as file:
        key = file.read()
    return key

def check_key_exists(filename):
    # Check if a key file exists
    return os.path.isfile(filename)

# Signature verification function
def verify_signature(public_key, message, signature):
    # Verify the digital signature using the provided public key
    key = RSA.import_key(public_key)
    h = SHA256.new(message)
    try:
        pkcs1_15.new(key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False

# File receiving and processing function
def receive_file():
    host = '127.0.0.1'
    port = 12345

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen()

    print("Server listening on port", port)
    client_socket, addr = server_socket.accept()
    print("Connection from", addr)

    data = client_socket.recv(1)
    operation = int(data)
    decrypted_message = ""

    if operation == 1:
        # Receive and display a plaintext file
        ciphertext = client_socket.recv(1024)
        decrypted_message = ciphertext.decode('utf-8')
        print("Received file", decrypted_message)
    elif operation == 2:
        # Receive, decrypt, and display a symmetrically encrypted file
        key = generate_key()
        cipher = Fernet(key)
        ciphertext = client_socket.recv(1024)
        decrypted_content = cipher.decrypt(ciphertext)
        decrypted_message = decrypted_content.decode("utf-8")
        print("Received and decrypted file:", decrypted_message)
    elif operation == 3:
        # Receive, verify, and display a digitally signed message
        with client_socket:
            data = pickle.loads(client_socket.recv(1024))
            public_key_A = data['public_key']
            message = data['message']
            signature = data['signature']

            if verify_signature(public_key_A, message, signature):
                decrypted_message = message.decode('utf-8')
                print("Message from ClientA verified:", decrypted_message)
            else:
                decrypted_message = "Message from ClientA could not be verified."
    elif operation == 4:
        # Receive, verify, decrypt, and display a combined encrypted and signed message
        data = pickle.loads(client_socket.recv(4096))
        public_key_A = data['public_key']
        message = data['message']
        signature = data['signature']

        if verify_signature(public_key_A, message, signature):
            print("Message from ClientA verified:", decrypted_message)
            ciphertext = message
            key = generate_key()
            decrypted_content = symmetric_decrypt(ciphertext, key)
            decrypted_message = decrypted_content
        else:
            decrypted_message = "Message from ClientA could not be verified."

    # Close the server socket
    server_socket.close()
    return decrypted_message

# Function to clear the result label and hide the "Clear Page" button
def clear_page():
    result_label.config(text="")
    global clear_button
    if clear_button is not None:
        clear_button.pack_forget()
    clear_button = None

# Function to display help information
def show_help():
    help_text = """
    How to Use the Program:

    1. Click 'Receive File' to receive a file or message from ClientA.
    2. Follow the prompts to process and display the received data.
    3. If a file or message is displayed, the "Clear Page" button will appear.
    4. Click 'Clear Page' to clear the result and hide the "Clear Page" button.

    NOTE: 
    ! Make sure to click "Receive File" before sending a file from ClientA.
    """
    help_window = tk.Toplevel()
    help_window.title("Help")
    help_label = tk.Label(help_window, text=help_text, padx=10, pady=10)
    help_label.pack()

# Main GUI function
def main():
    global result_label, clear_button

    # Generate and save key pair if not exists
    if not check_key_exists("B_private_key.pem") or not check_key_exists("B_public_key.pem"):
        private_key, public_key = generate_key_pair()
        save_key_to_file(private_key, 'B_private_key.pem')
        save_key_to_file(public_key, 'B_public_key.pem')

    # GUI setup
    root = tk.Tk()
    root.title("File Decryption")
    root.geometry("400x200+{}+{}".format(root.winfo_screenwidth() // 2 - 200, root.winfo_screenheight() // 2 - 100))

    # Function to handle the "Receive File" button click
    def receive_file_and_display():
        decrypted_message = receive_file()
        result_label.config(text="Decrypted Message: " + decrypted_message)

        # Show the "Clear Page" button only if it's not already created
        global clear_button
        if clear_button is None:
            clear_button = tk.Button(root, text="Clear Page", command=clear_page)
            clear_button.pack()

    # Create and place the "Receive File" button
    receive_button = tk.Button(
        root, text="Receive File", command=receive_file_and_display)
    receive_button.pack()

    # Create and place the label to display the result
    result_label = tk.Label(root, text="")
    result_label.pack()

    # Create and place the "Help" button
    help_button = tk.Button(root, text="Help", command=show_help)
    help_button.pack()

    # Start the GUI event loop
    root.mainloop()

# Run the main function if the script is executed directly
if __name__ == "__main__":
    main()
