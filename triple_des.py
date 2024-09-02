import tkinter as tk
from tkinter import messagebox, ttk
from permutations import permute, shift_left, xor
from sboxes import sbox
from key_generation import generate_keys, generate_round_keys
from binary_conversion import hex2bin, bin2hex, bin2dec, dec2bin
from encryption import encrypt, run_encryption, run_decryption

def encrypt_3des(plaintexts, iv, keys_binary, keys_hex, keys_bin_reversed, keys_hex_reversed):
    full_cyphertext = []

    for index, plaintext in enumerate(plaintexts):
            if index == 0:
                new_plaintext = xor(hex2bin(plaintext), hex2bin(iv))
                cipher_text = run_encryption(bin2hex(new_plaintext), keys_binary[0], keys_hex[0])
                decrypted_text2 = run_decryption(cipher_text, keys_bin_reversed[1], keys_hex_reversed[1])
                cipher_text3 = run_encryption(decrypted_text2, keys_binary[2], keys_hex[2])
                full_cyphertext.append(cipher_text3)
            else:
                current_idx = 3 * index
                new_plaintext = xor(hex2bin(plaintext), hex2bin(full_cyphertext[index - 1]))
                cipher_text = run_encryption(bin2hex(new_plaintext), keys_binary[current_idx], keys_hex[current_idx])
                decrypted_text2 = run_decryption(cipher_text, keys_bin_reversed[current_idx + 1], keys_hex_reversed[current_idx + 1])
                cipher_text3 = run_encryption(decrypted_text2, keys_binary[current_idx + 2], keys_hex[current_idx + 2])
                full_cyphertext.append(cipher_text3)

    return full_cyphertext


def decrypt_3des(full_cyphertext, iv, keys_binary, keys_hex, keys_bin_reversed, keys_hex_reversed):
    full_plaintext = []

    for index, cyphertext in enumerate(full_cyphertext):
            if index == 0:
                plain_text = run_decryption(cyphertext, keys_bin_reversed[index + 2], keys_hex_reversed[index + 2])
                cipher_text2 = run_encryption(plain_text, keys_binary[index + 1], keys_hex[index + 1])
                plain_text3 = run_decryption(cipher_text2, keys_bin_reversed[index], keys_hex_reversed[index + 1])
                old_plaintext = xor(hex2bin(plain_text3), hex2bin(iv))
                full_plaintext.append(bin2hex(old_plaintext))
            else:
                current_idx = 3 * index
                plain_text = run_decryption(cyphertext, keys_bin_reversed[current_idx + 2], keys_hex_reversed[current_idx + 2])
                cipher_text2 = run_encryption(plain_text, keys_binary[current_idx + 1], keys_hex[current_idx + 1])
                plain_text3 = run_decryption(cipher_text2, keys_bin_reversed[current_idx], keys_hex_reversed[current_idx])
                new_cyphertext = xor(hex2bin(plain_text3), hex2bin(full_cyphertext[index - 1]))
                full_plaintext.append(bin2hex(new_cyphertext))

    return full_plaintext

#Read keys from the output_keys.txt file and populate lists.
def read_keys_from_file(filename):
    keys = []
    with open(filename, "r") as file:
        lines = file.readlines()
        for line in lines:
            line = line.strip()  # Remove trailing newline
            if line != "Keys:":
                keys.append(line)
    return keys

def process_ecrypt(file_path, iv):
    plaintext = read_text_from_file(file_path)
    # Key generation
    generate_keys(len(plaintext))

    # Lists for keys
    keys = []
    keys_binary = []
    keys_hex = []
    keys_bin_reversed = []
    keys_hex_reversed = []

    keys = read_keys_from_file("./output_keys.txt")

    plaintexts = chunk_text(plaintext)

    # Generating round keys
    for key in keys:
        generate_round_keys(key, keys_hex, keys_binary, keys_hex_reversed, keys_bin_reversed)

    # Encryption
    cyphertext = encrypt_3des(plaintexts, iv, keys_binary, keys_hex, keys_bin_reversed, keys_hex_reversed)
    full_cyphertext =  "".join(cyphertext)
    write_text_to_file("./cyphertext.txt", full_cyphertext)

def process_decrypt(file_path, iv, key_path):
    cyphertext = read_text_from_file(file_path)

    keys = []
    keys_binary = []
    keys_hex = []
    keys_bin_reversed = []
    keys_hex_reversed = []

    keys = read_keys_from_file(key_path)
    # Generating round keys
    for key in keys:
        generate_round_keys(key, keys_hex, keys_binary, keys_hex_reversed, keys_bin_reversed)

    cyphertexts = chunk_text(cyphertext)
    # Decryption
    plaintext_decrypted = decrypt_3des(cyphertexts, iv, keys_binary, keys_hex, keys_bin_reversed, keys_hex_reversed)
    full_plaintext = "".join(plaintext_decrypted)   
    write_text_to_file("./decyphered_text.txt", full_plaintext)


def chunk_text(text):
    chunks = [text[i:i+16] for i in range(0, len(text), 16)]
    #padding added
    padded_chunks = [chunk.ljust(16, '0') for chunk in chunks]
    return padded_chunks

# Make a constraint that does not let empty file be submitted
def check_empty_file(filename):
    with open(filename, "r") as file:
        if file.readline() == "":
            raise ValueError("Empty file submitted.")

def read_text_from_file(file_path):
    # Open the file in read mode
    with open(file_path, "r") as file:
        # Read the content of the file
        text_from_the_file = file.read()
    return text_from_the_file

def write_text_to_file(file_path, text):
    # Open the file in write mode (w)
    with open(file_path, "w") as file:
        # Write the string to the file
        file.write(text)
