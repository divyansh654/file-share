import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64

# Function to generate a key from a password
def generate_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to encrypt a chunk of data
def encrypt_chunk(data, key):
    iv = os.urandom(16)  # Generate a random IV
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(data) + encryptor.finalize()
    return iv + encrypted_data  # Prepend the IV to the encrypted data

# Function to decrypt a chunk of data
def decrypt_chunk(data, key):
    iv = data[:16]  # Extract the IV from the beginning of the data
    encrypted_data = data[16:]  # The rest is the encrypted data
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    return decryptor.update(encrypted_data) + decryptor.finalize()

# Function to split a file into chunks
def split_file(file_path, chunk_size):
    chunks = []
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            chunks.append(chunk)
    return chunks

# Function to merge chunks back into a file
def merge_chunks(chunks, output_file):
    with open(output_file, 'wb') as f:
        for chunk in chunks:
            f.write(chunk)

# Main function to demonstrate file sharing
def secure_file_share(file_path, password, output_folder, chunk_size=1024):
    # Step 1: Split the file into chunks
    chunks = split_file(file_path, chunk_size)
    print(f"File split into {len(chunks)} chunks.")

    # Step 2: Encrypt each chunk
    salt = os.urandom(16)  # Unique salt for encryption
    key = generate_key(password, salt)
    encrypted_chunks = [encrypt_chunk(chunk, key) for chunk in chunks]
    
    # Save encrypted chunks to files
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)
    for i, chunk in enumerate(encrypted_chunks):
        with open(f"{output_folder}/chunk_{i}.enc", 'wb') as f:
            f.write(chunk)
    
    print(f"Encrypted chunks saved to {output_folder}.")
    return salt, len(chunks)

# Function to reassemble and decrypt file
def reassemble_file(input_folder, output_file, password, salt, total_chunks):
    # Step 1: Generate the decryption key
    key = generate_key(password, salt)
    
    # Step 2: Read and decrypt each chunk
    decrypted_chunks = []
    for i in range(total_chunks):
        with open(f"{input_folder}/chunk_{i}.enc", 'rb') as f:
            encrypted_data = f.read()
            decrypted_chunks.append(decrypt_chunk(encrypted_data, key))
    
    # Step 3: Merge chunks into the original file
    merge_chunks(decrypted_chunks, output_file)
    print(f"Decrypted file saved as {output_file}.")

# Example usage
if __name__ == "__main__":
    original_file = "example.txt"  # File to be shared
    password = "securepassword123"
    output_folder = "file_chunks"
    chunk_size = 1024  # Size of each chunk in bytes

     # Check if the original file exists
    if not os.path.exists(original_file):
        print(f"File {original_file} does not exist.")
    else:
        # Securely share the file
        try:
            salt, total_chunks = secure_file_share(original_file, password, output_folder, chunk_size)
        except Exception as e:
            print(f"An error occurred: {e}")

    # Reassemble the file after sharing
    reassembled_file = "reassembled_example.txt"
    reassemble_file(output_folder, reassembled_file, password, salt, total_chunks)
