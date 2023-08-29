from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.Cipher import AES
import os

def generate_key_pair():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key

def save_key_to_file(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)

def load_key_from_file(filename):
    with open(filename, 'rb') as file:
        key = file.read()
    return key

def encrypt_message_with_key(message, public_key_path):
    with open(public_key_path, 'rb') as file:
        public_key = file.read()
    
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

def decrypt_message_with_key(encrypted_message, private_key_path):
    with open(private_key_path, 'rb') as file:
        private_key = file.read()
    
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message.decode()

def encrypt_file(file_path, public_key):
    with open(file_path, 'rb') as file:
        content = file.read()

    # Generate a random symmetric key for AES encryption
    symmetric_key = get_random_bytes(16)
    aes_cipher = AES.new(symmetric_key, AES.MODE_EAX)
    encrypted_content, tag = aes_cipher.encrypt_and_digest(content)

    # Encrypt the symmetric key using RSA public key
    rsa_key = RSA.import_key(public_key)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_symmetric_key = rsa_cipher.encrypt(symmetric_key)

    encrypted_data = encrypted_symmetric_key + aes_cipher.nonce + encrypted_content + tag

    encrypted_file_path = os.path.splitext(file_path)[0] + "_encrypted.bin"
    with open(encrypted_file_path, 'wb') as file:
        file.write(encrypted_data)
    print("File encrypted and saved as", encrypted_file_path)

def decrypt_file(encrypted_file_path, private_key_path):
    encrypted_data = open(encrypted_file_path, 'rb').read()

    private_key = load_key_from_file(private_key_path)
    rsa_key = RSA.import_key(private_key)
    rsa_cipher = PKCS1_OAEP.new(rsa_key)

    # Extract the encrypted symmetric key, nonce, encrypted content, and tag
    encrypted_symmetric_key = encrypted_data[:rsa_cipher._key.size_in_bytes()]
    nonce = encrypted_data[rsa_cipher._key.size_in_bytes():rsa_cipher._key.size_in_bytes()+16]
    encrypted_content_tag = encrypted_data[rsa_cipher._key.size_in_bytes()+16:]
    encrypted_content = encrypted_content_tag[:-16]
    tag = encrypted_content_tag[-16:]

    # Decrypt the symmetric key using RSA
    symmetric_key = rsa_cipher.decrypt(encrypted_symmetric_key)

    # Decrypt the content using AES
    aes_cipher = AES.new(symmetric_key, AES.MODE_EAX, nonce=nonce)
    decrypted_content = aes_cipher.decrypt_and_verify(encrypted_content, tag)

    decrypted_file_path = os.path.splitext(encrypted_file_path)[0] + "_decrypted.txt"
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_content)
    print("File decrypted and saved as", decrypted_file_path)


def main():
    while True:
        print("1. Generate RSA Key Pair")
        print("2. Encrypt Message")
        print("3. Decrypt Message")
        print("4. Encrypt File")
        print("5. Decrypt File")
        print("6. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            private_key, public_key = generate_key_pair()
            save_key_to_file(private_key, 'RSA_private_key.pem')
            save_key_to_file(public_key, 'RSA_public_key.pem')
            print("Key pair generated and saved.")

        elif choice == '2':
            message = input("Enter the message to encrypt: ")
            public_key_path = input("Enter the path of the recipient's public key: ")
            encrypted_message = encrypt_message_with_key(message, public_key_path)
            with open('encrypted_message.bin', 'wb') as file:
                file.write(encrypted_message)
            print("Message encrypted and saved.")

        elif choice == '3':
            encrypted_message_path = input("Enter the path of the encrypted message: ")
            private_key_path = input("Enter the path of your private key: ")
            with open(encrypted_message_path, 'rb') as file:
                encrypted_message = file.read()
            decrypted_message = decrypt_message_with_key(encrypted_message, private_key_path)
            print("Decrypted Message:", decrypted_message)

        elif choice == '4':
            file_path = input("Enter the path of the file to encrypt: ")
            public_key = load_key_from_file('public_key.pem')
            encrypt_file(file_path, public_key)

        elif choice == '5':
            encrypted_file_path = input("Enter the path of the encrypted file: ")
            private_key_path = input("Enter the path of the private key: ")
            decrypt_file(encrypted_file_path, private_key_path)

        elif choice == '6':
            break

        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
