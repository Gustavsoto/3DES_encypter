import secrets
from binary_conversion import hex2bin, bin2hex, bin2dec, dec2bin
from permutations import permute, shift_left, shift_table, keyp, key_comp

def generate_round_keys(key, key_hex, key_bin, key_hex_rev, key_bin_rev):
    key_binary = hex2bin(key)
    key_binary = permute(key_binary, keyp, 56)
    left = key_binary[:28]
    right = key_binary[28:56]
    key_list_bin = []
    key_list_hex = []

    for i in range(16):
        left = shift_left(left, shift_table[i])
        right = shift_left(right, shift_table[i])
        key_combined = left + right
        round_key = permute(key_combined, key_comp, 48)
        key_list_bin.append(round_key)
        key_list_hex.append(bin2hex(round_key))
    key_bin.append(key_list_bin)
    key_hex.append(key_list_hex)
    key_bin_rev.append(key_list_bin[::-1])
    key_hex_rev.append(key_list_hex[::-1])

def generate_keys(plaintext_length):
    padding_needed = 16 - (plaintext_length % 16) if plaintext_length % 16 != 0 else 0
    total_plaintext_length = plaintext_length + padding_needed
    total_keys_needed = (total_plaintext_length // 16) * 3
    characters = '0123456789ABCDEF'
    keys = []
    #Keys generated
    for _ in range(total_keys_needed):
        random_key = ''.join(secrets.choice(characters) for _ in range(16))
        keys.append(random_key)
    with open("output_keys.txt", "w") as file:
        # Keys written in txt file
        file.write("Keys:\n")
        for x in keys:
            file.write(x + "\n")