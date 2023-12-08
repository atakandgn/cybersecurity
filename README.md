# File Encryption and Decryption Project

This project demonstrates a simple file encryption and decryption system using Python. The system involves two clients, ClientA and ClientB, communicating over a network. ClientA sends encrypted and signed messages or files to ClientB, who then decrypts and verifies the authenticity of the received data.

## Features

- Symmetric encryption using Fernet for basic encryption.
- Asymmetric encryption using RSA for key pair generation and digital signatures.
- File upload and download functionality.
- Option to perform symmetric encryption, digital signature, or a combination of both.
- Graphical User Interface (GUI) for ease of use.

## Project Structure

- **ClientA.py**: Code for the ClientA application, responsible for sending encrypted messages or files.
- **ClientB.py**: Code for the ClientB application, responsible for receiving and decrypting messages or files.
- **A_public_key.pem**: Public key file for ClientA. (Automatically generated if not exists)
- **A_private_key.pem**: Private key file for ClientA. (Automatically generated if not exists)
- **B_public_key.pem**: Public key file for ClientB. (Automatically generated if not exists)
- **B_private_key.pem**: Private key file for ClientB. (Automatically generated if not exists)

## Requirements

- Python 3.x
- Tkinter (for GUI)
- cryptography library
- pycryptodome library
- Crypto library

## Usage

1. Run `ClientA.py` to initiate the sender client.
2. Run `ClientB.py` to initiate the receiver client.
3. Follow the prompts on the GUI to upload, encrypt, and send files between clients.

## Notes

- Ensure that the required libraries are installed using `pip install -r requirements.txt`.
- This is a simple educational project and may not be suitable for production use without further enhancements and security considerations.

### For communication
-  Reach out to atakandogan.info@gmail.com or [LinkedIn](https://www.linkedin.com/in/atakandoan/) 