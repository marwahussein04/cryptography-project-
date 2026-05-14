from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
import base64
import hashlib
import json
import os
import time


AES_KEY_SIZE_BYTES = 32      # 256-bit AES key
AES_BLOCK_SIZE_BYTES = 16

DES_KEY_SIZE_BYTES = 8       # DES uses 8 bytes, 56 effective bits
DES_BLOCK_SIZE_BYTES = 8


def create_output_folder(output_folder):
    """
    Create output folder if it does not exist.
    """
    if not os.path.exists(output_folder):
        os.makedirs(output_folder)


def read_file_bytes(file_path):
    """
    Read any file as bytes.
    Encryption works on bytes, not normal text.
    """
    with open(file_path, "rb") as file:
        return file.read()


def write_file_bytes(file_path, data):
    """
    Save bytes to a file.
    """
    with open(file_path, "wb") as file:
        file.write(data)


def to_base64(data):
    """
    Convert bytes to Base64 text.
    This makes encrypted binary data easier to save and display.
    """
    return base64.b64encode(data).decode("utf-8")


def from_base64(text):
    """
    Convert Base64 text back to bytes.
    """
    return base64.b64decode(text.encode("utf-8"))


def sha256_hash(file_path):
    """
    Calculate SHA-256 hash of a file.
    This proves whether two files are exactly identical.
    """
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(4096)
            if not chunk:
                break
            sha256.update(chunk)

    return sha256.hexdigest()


def save_key(key_path, key):
    """
    Save encryption key in a separate binary file.
    """
    with open(key_path, "wb") as key_file:
        key_file.write(key)


def load_key(key_path):
    """
    Load encryption key from a binary file.
    """
    with open(key_path, "rb") as key_file:
        return key_file.read()


def encrypt_with_aes(input_path, output_json_path, key_path):
    """
    Encrypt the input file using AES-256-GCM.

    AES-GCM does not need padding.
    It produces:
    - ciphertext
    - nonce
    - authentication tag
    """
    plaintext = read_file_bytes(input_path)

    key = get_random_bytes(AES_KEY_SIZE_BYTES)
    save_key(key_path, key)

    cipher = AES.new(key, AES.MODE_GCM)

    start_time = time.perf_counter()
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    encryption_time = time.perf_counter() - start_time

    encrypted_package = {
        "algorithm": "AES-256-GCM",
        "nonce_base64": to_base64(cipher.nonce),
        "tag_base64": to_base64(tag),
        "ciphertext_base64": to_base64(ciphertext),
        "plaintext_size_bytes": len(plaintext),
        "ciphertext_size_bytes": len(ciphertext),
        "key_size_bits": AES_KEY_SIZE_BYTES * 8,
        "block_size_bits": AES_BLOCK_SIZE_BYTES * 8,
        "security_note": "AES is a modern recommended symmetric encryption algorithm."
    }

    with open(output_json_path, "w", encoding="utf-8") as file:
        json.dump(encrypted_package, file, indent=4)

    return encrypted_package, encryption_time


def decrypt_with_aes(input_json_path, decrypted_output_path, key_path):
    """
    Decrypt an AES-256-GCM encrypted JSON package.
    """
    with open(input_json_path, "r", encoding="utf-8") as file:
        encrypted_package = json.load(file)

    key = load_key(key_path)
    nonce = from_base64(encrypted_package["nonce_base64"])
    tag = from_base64(encrypted_package["tag_base64"])
    ciphertext = from_base64(encrypted_package["ciphertext_base64"])

    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)

    start_time = time.perf_counter()
    plaintext = cipher.decrypt_and_verify(ciphertext, tag)
    decryption_time = time.perf_counter() - start_time

    write_file_bytes(decrypted_output_path, plaintext)

    return decryption_time


def encrypt_with_des(input_path, output_json_path, key_path):
    """
    Encrypt the input file using DES-CBC.

    DES-CBC needs:
    - 8-byte key
    - 8-byte IV
    - PKCS#7 padding because DES works on fixed-size blocks
    """
    plaintext = read_file_bytes(input_path)

    key = get_random_bytes(DES_KEY_SIZE_BYTES)
    save_key(key_path, key)

    iv = get_random_bytes(DES_BLOCK_SIZE_BYTES)

    cipher = DES.new(key, DES.MODE_CBC, iv=iv)
    padded_plaintext = pad(plaintext, DES_BLOCK_SIZE_BYTES)

    start_time = time.perf_counter()
    ciphertext = cipher.encrypt(padded_plaintext)
    encryption_time = time.perf_counter() - start_time

    encrypted_package = {
        "algorithm": "DES-CBC",
        "iv_base64": to_base64(iv),
        "ciphertext_base64": to_base64(ciphertext),
        "plaintext_size_bytes": len(plaintext),
        "ciphertext_size_bytes": len(ciphertext),
        "key_size_bits": 56,
        "block_size_bits": DES_BLOCK_SIZE_BYTES * 8,
        "security_note": "DES is weak and allowed here only for educational comparison."
    }

    with open(output_json_path, "w", encoding="utf-8") as file:
        json.dump(encrypted_package, file, indent=4)

    return encrypted_package, encryption_time


def decrypt_with_des(input_json_path, decrypted_output_path, key_path):
    """
    Decrypt a DES-CBC encrypted JSON package.
    """
    with open(input_json_path, "r", encoding="utf-8") as file:
        encrypted_package = json.load(file)

    key = load_key(key_path)
    iv = from_base64(encrypted_package["iv_base64"])
    ciphertext = from_base64(encrypted_package["ciphertext_base64"])

    cipher = DES.new(key, DES.MODE_CBC, iv=iv)

    start_time = time.perf_counter()
    padded_plaintext = cipher.decrypt(ciphertext)
    plaintext = unpad(padded_plaintext, DES_BLOCK_SIZE_BYTES)
    decryption_time = time.perf_counter() - start_time

    write_file_bytes(decrypted_output_path, plaintext)

    return decryption_time


def verify_files(original_path, decrypted_path):
    """
    Compare the SHA-256 hash of original and decrypted files.
    """
    original_hash = sha256_hash(original_path)
    decrypted_hash = sha256_hash(decrypted_path)
    matched = original_hash == decrypted_hash

    return matched, original_hash, decrypted_hash


def preview_json_file(json_path, max_chars=220):
    """
    Return a short preview of the encrypted JSON output.
    """
    with open(json_path, "r", encoding="utf-8") as file:
        text = file.read()

    if len(text) > max_chars:
        return text[:max_chars] + "..."

    return text