from binary_conversion import hex2bin, bin2hex, bin2dec, dec2bin
from sboxes import sbox
from permutations import permute, shift_left, xor, initial_perm, final_perm, exp_d, per
def encrypt(pt, rkb, rk):
    pt = hex2bin(pt)

    # Initial Permutation
    pt = permute(pt, initial_perm, 64)
    #print("After initial permutation", bin2hex(pt))

    # Splitting
    left, right = pt[:32], pt[32:64]

    for i in range(16):
        # Expansion D-box: Expanding the 32 bits data into 48 bits
        right_expanded = permute(right, exp_d, 48)

        # XOR RoundKey[i] and right_expanded
        xor_result = xor(right_expanded, rkb[i])

        # Substituting values from the S-box table
        sbox_str = ""
        for j in range(8):
            row = bin2dec(int(xor_result[j * 6] + xor_result[j * 6 + 5]))
            col = bin2dec(int(xor_result[j * 6 + 1: j * 6 + 5]))
            val = sbox[j][row][col]
            sbox_str += dec2bin(val)

        # Straight D-box: After substituting rearranging the bits
        sbox_str = permute(sbox_str, per, 32)

        # XOR left and sbox_str
        left = xor(left, sbox_str)

        # Swapper
        if i != 15:
            left, right = right, left

        #print("Round", i + 1, bin2hex(left), bin2hex(right), rk[i])

    # Combination
    combined_text = left + right

    # Final permutation: final rearranging of bits to get cipher text
    cipher_text = permute(combined_text, final_perm, 64)
    return cipher_text

def run_encryption(plaintext, rkb, rk):
    cipher_text = bin2hex(encrypt(plaintext, rkb, rk))
    return cipher_text

def run_decryption(ciphertext, rkb_rev, rk_rev):
    decrypted_text = bin2hex(encrypt(ciphertext, rkb_rev, rk_rev))
    return decrypted_text