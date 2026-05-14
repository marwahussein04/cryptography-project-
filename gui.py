import tkinter as tk
from tkinter import messagebox, scrolledtext

from crypto_utils import (
    create_output_folder,
    decrypt_with_aes,
    decrypt_with_des,
    encrypt_with_aes,
    encrypt_with_des,
    preview_json_file,
    read_file_bytes,
    sha256_hash,
    verify_files
)


INPUT_FILE = "data/student_records.csv"
OUTPUT_FOLDER = "output"

AES_KEY_FILE = "output/aes_key.key"
DES_KEY_FILE = "output/des_key.key"

AES_ENCRYPTED_FILE = "output/student_records_aes_encrypted.json"
DES_ENCRYPTED_FILE = "output/student_records_des_encrypted.json"

AES_DECRYPTED_FILE = "output/student_records_aes_decrypted.csv"
DES_DECRYPTED_FILE = "output/student_records_des_decrypted.csv"


def add_log(text):
    log_box.insert(tk.END, text + "\n")
    log_box.see(tk.END)


def clear_log():
    log_box.delete("1.0", tk.END)


def preview_original_file():
    try:
        add_log("=" * 60)
        add_log("ORIGINAL FILE PREVIEW")
        add_log("=" * 60)

        data = read_file_bytes(INPUT_FILE).decode("utf-8")

        add_log(data)
        add_log("Original SHA-256 hash:")
        add_log(sha256_hash(INPUT_FILE))

    except Exception as error:
        messagebox.showerror("Error", str(error))


def encrypt_aes():
    try:
        create_output_folder(OUTPUT_FOLDER)

        add_log("=" * 60)
        add_log("AES ENCRYPTION")
        add_log("=" * 60)

        aes_package, aes_time = encrypt_with_aes(
            INPUT_FILE,
            AES_ENCRYPTED_FILE,
            AES_KEY_FILE
        )

        add_log("AES encrypted file saved: " + AES_ENCRYPTED_FILE)
        add_log("AES key saved: " + AES_KEY_FILE)
        add_log("AES encryption time: " + f"{aes_time:.8f}" + " seconds")
        add_log("AES ciphertext size: " + str(aes_package["ciphertext_size_bytes"]) + " bytes")
        add_log("AES key size: " + str(aes_package["key_size_bits"]) + " bits")
        add_log("AES block size: " + str(aes_package["block_size_bits"]) + " bits")
        add_log("AES security note: " + aes_package["security_note"])

        add_log("\nAES encrypted output preview:")
        add_log(preview_json_file(AES_ENCRYPTED_FILE))

        messagebox.showinfo("Success", "AES encryption completed successfully.")

    except Exception as error:
        messagebox.showerror("Error", str(error))


def decrypt_aes():
    try:
        add_log("=" * 60)
        add_log("AES DECRYPTION")
        add_log("=" * 60)

        aes_decryption_time = decrypt_with_aes(
            AES_ENCRYPTED_FILE,
            AES_DECRYPTED_FILE,
            AES_KEY_FILE
        )

        add_log("AES decrypted file saved: " + AES_DECRYPTED_FILE)
        add_log("AES decryption time: " + f"{aes_decryption_time:.8f}" + " seconds")

        messagebox.showinfo("Success", "AES decryption completed successfully.")

    except Exception as error:
        messagebox.showerror("Error", str(error))


def encrypt_des():
    try:
        create_output_folder(OUTPUT_FOLDER)

        add_log("=" * 60)
        add_log("DES ENCRYPTION")
        add_log("=" * 60)

        des_package, des_time = encrypt_with_des(
            INPUT_FILE,
            DES_ENCRYPTED_FILE,
            DES_KEY_FILE
        )

        add_log("DES encrypted file saved: " + DES_ENCRYPTED_FILE)
        add_log("DES key saved: " + DES_KEY_FILE)
        add_log("DES encryption time: " + f"{des_time:.8f}" + " seconds")
        add_log("DES ciphertext size: " + str(des_package["ciphertext_size_bytes"]) + " bytes")
        add_log("DES key size: " + str(des_package["key_size_bits"]) + " bits")
        add_log("DES block size: " + str(des_package["block_size_bits"]) + " bits")
        add_log("DES security note: " + des_package["security_note"])

        add_log("\nDES encrypted output preview:")
        add_log(preview_json_file(DES_ENCRYPTED_FILE))

        messagebox.showinfo("Success", "DES encryption completed successfully.")

    except Exception as error:
        messagebox.showerror("Error", str(error))


def decrypt_des():
    try:
        add_log("=" * 60)
        add_log("DES DECRYPTION")
        add_log("=" * 60)

        des_decryption_time = decrypt_with_des(
            DES_ENCRYPTED_FILE,
            DES_DECRYPTED_FILE,
            DES_KEY_FILE
        )

        add_log("DES decrypted file saved: " + DES_DECRYPTED_FILE)
        add_log("DES decryption time: " + f"{des_decryption_time:.8f}" + " seconds")

        messagebox.showinfo("Success", "DES decryption completed successfully.")

    except Exception as error:
        messagebox.showerror("Error", str(error))


def verify_files_gui():
    try:
        add_log("=" * 60)
        add_log("SHA-256 VERIFICATION")
        add_log("=" * 60)

        aes_matched, aes_original_hash, aes_decrypted_hash = verify_files(
            INPUT_FILE,
            AES_DECRYPTED_FILE
        )

        des_matched, des_original_hash, des_decrypted_hash = verify_files(
            INPUT_FILE,
            DES_DECRYPTED_FILE
        )

        add_log("AES original hash:")
        add_log(aes_original_hash)

        add_log("AES decrypted hash:")
        add_log(aes_decrypted_hash)

        if aes_matched:
            add_log("AES verification result: SUCCESS - decrypted file matches original.")
        else:
            add_log("AES verification result: FAILED - decrypted file does not match original.")

        add_log("\nDES original hash:")
        add_log(des_original_hash)

        add_log("DES decrypted hash:")
        add_log(des_decrypted_hash)

        if des_matched:
            add_log("DES verification result: SUCCESS - decrypted file matches original.")
        else:
            add_log("DES verification result: FAILED - decrypted file does not match original.")

        if aes_matched and des_matched:
            messagebox.showinfo("Success", "AES and DES verification completed successfully.")
        else:
            messagebox.showwarning("Warning", "One verification failed.")

    except Exception as error:
        messagebox.showerror("Error", str(error))


def run_full_demo():
    try:
        clear_log()

        add_log("Running full AES vs DES comparison demo...\n")

        preview_original_file()
        encrypt_aes()
        encrypt_des()
        decrypt_aes()
        decrypt_des()
        verify_files_gui()

        add_log("\n" + "=" * 60)
        add_log("COMPARISON SUMMARY")
        add_log("=" * 60)

        add_log("AES:")
        add_log("- Algorithm: AES-256-GCM")
        add_log("- Key size: 256 bits")
        add_log("- Block size: 128 bits")
        add_log("- Padding: Not needed in GCM mode")
        add_log("- Security: Modern and recommended")

        add_log("\nDES:")
        add_log("- Algorithm: DES-CBC")
        add_log("- Key size: 56 effective bits")
        add_log("- Block size: 64 bits")
        add_log("- Padding: PKCS#7 padding used")
        add_log("- Security: Weak and used here only for educational comparison")

        messagebox.showinfo("Success", "Full demo completed successfully.")

    except Exception as error:
        messagebox.showerror("Error", str(error))


root = tk.Tk()
root.title("Cryptography Lib Lab - AES vs DES")
root.geometry("900x650")

title_label = tk.Label(
    root,
    text="Cryptography Lib Lab Project - Path 2: AES vs DES Comparison",
    font=("Arial", 16, "bold")
)
title_label.pack(pady=10)

button_frame = tk.Frame(root)
button_frame.pack(pady=10)

tk.Button(
    button_frame,
    text="Preview Original File",
    width=25,
    command=preview_original_file
).grid(row=0, column=0, padx=5, pady=5)

tk.Button(
    button_frame,
    text="Encrypt using AES",
    width=25,
    command=encrypt_aes
).grid(row=0, column=1, padx=5, pady=5)

tk.Button(
    button_frame,
    text="Decrypt AES Output",
    width=25,
    command=decrypt_aes
).grid(row=0, column=2, padx=5, pady=5)

tk.Button(
    button_frame,
    text="Encrypt using DES",
    width=25,
    command=encrypt_des
).grid(row=1, column=0, padx=5, pady=5)

tk.Button(
    button_frame,
    text="Decrypt DES Output",
    width=25,
    command=decrypt_des
).grid(row=1, column=1, padx=5, pady=5)

tk.Button(
    button_frame,
    text="Verify Files",
    width=25,
    command=verify_files_gui
).grid(row=1, column=2, padx=5, pady=5)

tk.Button(
    button_frame,
    text="Run Full Demo",
    width=25,
    command=run_full_demo
).grid(row=2, column=0, padx=5, pady=5)

tk.Button(
    button_frame,
    text="Clear Output",
    width=25,
    command=clear_log
).grid(row=2, column=1, padx=5, pady=5)

tk.Button(
    button_frame,
    text="Exit",
    width=25,
    command=root.destroy
).grid(row=2, column=2, padx=5, pady=5)

log_box = scrolledtext.ScrolledText(root, width=105, height=28)
log_box.pack(pady=10)

root.mainloop()