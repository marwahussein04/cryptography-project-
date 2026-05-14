# Cryptography Lib Lab Project

## Project Path
Path 2: Algorithm Comparison

## Scenario
Secure Student Records

## Algorithms
- AES-256-GCM
- DES-CBC

## Extra Features
1. Simple interactive menu.
2. SHA-256 hash verification.
3. Base64 encrypted output saved inside JSON files.
4. Execution-time comparison between AES and DES.
5. Simple Tkinter GUI.

## Project Idea
The program encrypts the same CSV file using AES and DES, then decrypts both encrypted files and verifies that the decrypted outputs match the original file.

AES is a modern recommended algorithm. DES is weak and used here only for educational comparison.

## Folder Structure

```text
crypto_project_path2_extra/
│
├── main.py
├── crypto_utils.py
├── gui.py
├── requirements.txt
├── README.md
├── report.txt
├── video_script.txt
│
├── data/
│   └── student_records.csv
│
└── output/
    ├── aes_key.key
    ├── des_key.key
    ├── student_records_aes_encrypted.json
    ├── student_records_des_encrypted.json
    ├── student_records_aes_decrypted.csv
    └── student_records_des_decrypted.csv

Video link 
https://drive.google.com/drive/folders/1ERF6_hWpycxkZeJPjYW_Qh-YaiwMDnHE?usp=sharing
