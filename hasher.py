import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

def calculate_hash(input_data):
    sha256_hash = hashlib.sha256()
    sha256_hash.update(input_data)
    return sha256_hash.hexdigest()

def save_hash_to_file(hash_value, filename):
    with open(filename, 'w') as file:
        file.write(hash_value)

def load_hash_from_file(filename):
    with open(filename, 'r') as file:
        return file.read()

def generate_digital_signature(private_key_path, data):
    with open(private_key_path, "rb") as key_file:
        private_key = serialization.load_pem_private_key(key_file.read(), password=None)
    
    signature = private_key.sign(
        data,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    
    return signature

def verify_digital_signature(public_key_path, data, signature):
    with open(public_key_path, "rb") as key_file:
        public_key = serialization.load_pem_public_key(key_file.read())
    
    try:
        public_key.verify(
            signature,
            data,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
        print("Signature is valid.")
    except Exception as e:
        print("Signature is invalid:", e)

def main():
    print("1. Generate Hash for Message")
    print("2. Generate Hash for File")
    print("3. Compare Hash with Stored Hash")
    print("4. Generate Digital Signature for Message")
    print("5. Generate Digital Signature for File")
    print("6. Verify Digital Signature for Message")
    print("7. Verify Digital Signature for File")
    choice = input("Enter your choice: ")

    if choice == '1':
        message = input("Enter the message: ")
        hash_value = calculate_hash(message.encode())
        save_to_filename = input("Enter the filename to save the hash: ")
        save_hash_to_file(hash_value, save_to_filename)
        print("Hash saved to", save_to_filename)

    elif choice == '2':
        file_path = input("Enter the path of the file: ")
        with open(file_path, 'rb') as file:
            file_data = file.read()
        hash_value = calculate_hash(file_data)
        save_to_filename = input("Enter the filename to save the hash: ")
        save_hash_to_file(hash_value, save_to_filename)
        print("Hash saved to", save_to_filename)

    elif choice == '3':
        stored_hash_filename = input("Enter the filename containing the stored hash: ")
        stored_hash = load_hash_from_file(stored_hash_filename)
        
        input_mode = input("Enter 'file' to hash a file or 'message' to hash a message: ")
        if input_mode == 'file':
            file_path = input("Enter the path of the file: ")
            with open(file_path, 'rb') as file:
                file_data = file.read()
            calculated_hash = calculate_hash(file_data)
        elif input_mode == 'message':
            message = input("Enter the message: ")
            calculated_hash = calculate_hash(message.encode())
        else:
            print("Invalid input mode.")
            return
        
        if stored_hash == calculated_hash:
            print("Hashes match. Data integrity is confirmed.")
        else:
            print("Hashes do not match. Data might have been altered.")

    elif choice == '4':
        private_key_path = input("Enter the path of the private key: ")
        message = input("Enter the message to sign: ").encode()
        signature = generate_digital_signature(private_key_path, message)
        signature_filename = input("Enter the filename to save the signature: ")
        with open(signature_filename, 'wb') as file:
            file.write(signature)
        print("Digital signature saved to", signature_filename)

    elif choice == '5':
        private_key_path = input("Enter the path of the private key: ")
        file_path = input("Enter the path of the file to sign: ")
        with open(file_path, 'rb') as file:
            file_data = file.read()
        signature = generate_digital_signature(private_key_path, file_data)
        signature_filename = input("Enter the filename to save the signature: ")
        with open(signature_filename, 'wb') as file:
            file.write(signature)
        print("Digital signature saved to", signature_filename)

    elif choice == '6':
        public_key_path = input("Enter the path of the public key: ")
        message = input("Enter the message to verify: ").encode()
        signature = input("Enter the signature: ")
        verify_digital_signature(public_key_path, message, signature.encode())

    elif choice == '7':
        public_key_path = input("Enter the path of the public key: ")
        file_path = input("Enter the path of the file to verify: ")
        with open(file_path, 'rb') as file:
            file_data = file.read()
        signature = input("Enter the signature: ")
        verify_digital_signature(public_key_path, file_data, signature.encode())

    else:
        print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
