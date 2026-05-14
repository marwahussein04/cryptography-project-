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


def print_section(title):
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def preview_original_file():
    print_section("ORIGINAL FILE PREVIEW")

    data = read_file_bytes(INPUT_FILE).decode("utf-8")

    print(data)
    print("Original SHA-256 hash:", sha256_hash(INPUT_FILE))


def encrypt_aes_option():
    print_section("AES ENCRYPTION")

    create_output_folder(OUTPUT_FOLDER)

    aes_package, aes_time = encrypt_with_aes(
        INPUT_FILE,
        AES_ENCRYPTED_FILE,
        AES_KEY_FILE
    )

    print("AES encrypted file saved:", AES_ENCRYPTED_FILE)
    print("AES key saved:", AES_KEY_FILE)
    print("AES encryption time:", f"{aes_time:.8f}", "seconds")
    print("AES ciphertext size:", aes_package["ciphertext_size_bytes"], "bytes")
    print("AES key size:", aes_package["key_size_bits"], "bits")
    print("AES block size:", aes_package["block_size_bits"], "bits")
    print("AES security note:", aes_package["security_note"])

    print("\nAES encrypted output preview:")
    print(preview_json_file(AES_ENCRYPTED_FILE))


def decrypt_aes_option():
    print_section("AES DECRYPTION")

    aes_decryption_time = decrypt_with_aes(
        AES_ENCRYPTED_FILE,
        AES_DECRYPTED_FILE,
        AES_KEY_FILE
    )

    print("AES decrypted file saved:", AES_DECRYPTED_FILE)
    print("AES decryption time:", f"{aes_decryption_time:.8f}", "seconds")


def encrypt_des_option():
    print_section("DES ENCRYPTION")

    create_output_folder(OUTPUT_FOLDER)

    des_package, des_time = encrypt_with_des(
        INPUT_FILE,
        DES_ENCRYPTED_FILE,
        DES_KEY_FILE
    )

    print("DES encrypted file saved:", DES_ENCRYPTED_FILE)
    print("DES key saved:", DES_KEY_FILE)
    print("DES encryption time:", f"{des_time:.8f}", "seconds")
    print("DES ciphertext size:", des_package["ciphertext_size_bytes"], "bytes")
    print("DES key size:", des_package["key_size_bits"], "bits")
    print("DES block size:", des_package["block_size_bits"], "bits")
    print("DES security note:", des_package["security_note"])

    print("\nDES encrypted output preview:")
    print(preview_json_file(DES_ENCRYPTED_FILE))


def decrypt_des_option():
    print_section("DES DECRYPTION")

    des_decryption_time = decrypt_with_des(
        DES_ENCRYPTED_FILE,
        DES_DECRYPTED_FILE,
        DES_KEY_FILE
    )

    print("DES decrypted file saved:", DES_DECRYPTED_FILE)
    print("DES decryption time:", f"{des_decryption_time:.8f}", "seconds")


def verify_option():
    print_section("SHA-256 VERIFICATION")

    aes_matched, aes_original_hash, aes_decrypted_hash = verify_files(
        INPUT_FILE,
        AES_DECRYPTED_FILE
    )

    des_matched, des_original_hash, des_decrypted_hash = verify_files(
        INPUT_FILE,
        DES_DECRYPTED_FILE
    )

    print("AES original hash:")
    print(aes_original_hash)

    print("AES decrypted hash:")
    print(aes_decrypted_hash)

    if aes_matched:
        print("AES verification result: SUCCESS - decrypted file matches original.")
    else:
        print("AES verification result: FAILED - decrypted file does not match original.")

    print("\nDES original hash:")
    print(des_original_hash)

    print("DES decrypted hash:")
    print(des_decrypted_hash)

    if des_matched:
        print("DES verification result: SUCCESS - decrypted file matches original.")
    else:
        print("DES verification result: FAILED - decrypted file does not match original.")


def full_comparison_option():
    print_section("FULL AES VS DES COMPARISON DEMO")

    preview_original_file()

    print("\nNow encrypting the same CSV file using AES and DES.")

    encrypt_aes_option()
    encrypt_des_option()

    print("\nNow decrypting AES and DES outputs.")

    decrypt_aes_option()
    decrypt_des_option()

    verify_option()

    print_section("COMPARISON SUMMARY")

    print("AES:")
    print("- Algorithm: AES-256-GCM")
    print("- Key size: 256 bits")
    print("- Block size: 128 bits")
    print("- Padding: Not needed in GCM mode")
    print("- Security: Modern and recommended")

    print("\nDES:")
    print("- Algorithm: DES-CBC")
    print("- Key size: 56 effective bits")
    print("- Block size: 64 bits")
    print("- Padding: PKCS#7 padding used")
    print("- Security: Weak and used here only for educational comparison")


def show_menu():
    print_section("CRYPTOGRAPHY LIB LAB MENU - PATH 2")

    print("1. Preview original file")
    print("2. Encrypt using AES")
    print("3. Decrypt AES output")
    print("4. Encrypt using DES")
    print("5. Decrypt DES output")
    print("6. Verify decrypted files")
    print("7. Run full AES vs DES comparison")
    print("0. Exit")


def main():
    while True:
        show_menu()

        choice = input("Choose an option: ").strip()

        try:
            if choice == "1":
                preview_original_file()

            elif choice == "2":
                encrypt_aes_option()

            elif choice == "3":
                decrypt_aes_option()

            elif choice == "4":
                encrypt_des_option()

            elif choice == "5":
                decrypt_des_option()

            elif choice == "6":
                verify_option()

            elif choice == "7":
                full_comparison_option()

            elif choice == "0":
                print("Goodbye.")
                break

            else:
                print("Invalid choice. Please choose from 0 to 7.")

        except FileNotFoundError as error:
            print("\nError: A required file was not found.")
            print(error)
            print("Tip: Run option 7 first for the full demo.")

        except ValueError as error:
            print("\nError: Decryption or verification failed.")
            print(error)
            print("Tip: Do not edit the encrypted JSON files or key files manually.")


if __name__ == "__main__":
    main()