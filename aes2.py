from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os

def generate_aes_key(key_length):
    return get_random_bytes(key_length)

def save_key_to_file(key, filename):
    with open(filename, 'wb') as file:
        file.write(key)

def load_key_from_file(filename):
    with open(filename, 'rb') as file:
        key = file.read()
    return key

def encrypt_message(message, aes_key):
    cipher = AES.new(aes_key, AES.MODE_EAX)
    encrypted_message, tag = cipher.encrypt_and_digest(message.encode())
    return cipher.nonce + encrypted_message + tag

def decrypt_message(encrypted_message, aes_key):
    nonce = encrypted_message[:16]
    encrypted_content_tag = encrypted_message[16:]
    encrypted_content = encrypted_content_tag[:-16]
    tag = encrypted_content_tag[-16:]
    
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_message = cipher.decrypt_and_verify(encrypted_content, tag)
    return decrypted_message.decode()

def encrypt_file(file_path, aes_key):
    with open(file_path, 'rb') as file:
        content = file.read()
    
    cipher = AES.new(aes_key, AES.MODE_EAX)
    encrypted_content, tag = cipher.encrypt_and_digest(content)
    
    encrypted_data = cipher.nonce + encrypted_content + tag
    
    encrypted_file_path = os.path.splitext(file_path)[0] + "_encrypted.bin"
    with open(encrypted_file_path, 'wb') as file:
        file.write(encrypted_data)
    print("File encrypted and saved as", encrypted_file_path)

def decrypt_file(encrypted_file_path, aes_key):
    encrypted_data = open(encrypted_file_path, 'rb').read()

    nonce = encrypted_data[:16]
    encrypted_content_tag = encrypted_data[16:]
    encrypted_content = encrypted_content_tag[:-16]
    tag = encrypted_content_tag[-16:]
    
    cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
    decrypted_content = cipher.decrypt_and_verify(encrypted_content, tag)
    
    decrypted_file_path = os.path.splitext(encrypted_file_path)[0] + "_decrypted.txt"
    with open(decrypted_file_path, 'wb') as file:
        file.write(decrypted_content)
    print("File decrypted and saved as", decrypted_file_path)

def main():
    while True:
        print("1. Generate AES Key")
        print("2. Encrypt Message")
        print("3. Decrypt Message")
        print("4. Encrypt File")
        print("5. Decrypt File")
        print("6. Exit")
        choice = input("Enter your choice: ")

        if choice == '1':
            key_length = int(input("Enter the AES key length (128, 192, or 256 bits): "))
            if key_length not in [128, 192, 256]:
                print("Invalid key length. Please select 128, 192, or 256.")
                continue
            aes_key = generate_aes_key(key_length // 8)  # Convert bits to bytes
            key_file_path = f'aes_key_{key_length}.bin'
            save_key_to_file(aes_key, key_file_path)
            print(f"AES key generated and saved in {key_file_path}")
            
        elif choice == '2':
            message = input("Enter the message to encrypt: ")
            key_length = int(input("Enter the AES key length (128, 192, or 256): "))
            aes_key_path = input("Enter the path of the AES key: ")
            aes_key = load_key_from_file(aes_key_path)
            encrypted_message = encrypt_message(message, aes_key)
            with open('encrypted_message.bin', 'wb') as file:
                file.write(encrypted_message)
            print("Message encrypted and saved.")

        elif choice == '3':
            encrypted_message_path = input("Enter the path of the encrypted message: ")
            key_length = int(input("Enter the AES key length (128, 192, or 256): "))
            aes_key_path = input("Enter the path of the AES key: ")
            aes_key = load_key_from_file(aes_key_path)
            with open(encrypted_message_path, 'rb') as file:
                encrypted_message = file.read()
            decrypted_message = decrypt_message(encrypted_message, aes_key)
            print("Decrypted Message:", decrypted_message)

        elif choice == '4':
            file_path = input("Enter the path of the file to encrypt: ")
            key_length = int(input("Enter the AES key length (128, 192, or 256): "))
            aes_key_path = input("Enter the path of the AES key: ")
            aes_key = load_key_from_file(aes_key_path)
            encrypt_file(file_path, aes_key)

        elif choice == '5':
            encrypted_file_path = input("Enter the path of the encrypted file: ")
            key_length = int(input("Enter the AES key length (128, 192, or 256): "))
            aes_key_path = input("Enter the path of the AES key: ")
            aes_key = load_key_from_file(aes_key_path)
            decrypt_file(encrypted_file_path, aes_key)

        elif choice == '6':
            break

        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
