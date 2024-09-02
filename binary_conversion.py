# Hexadecimal to binary conversion
def hex2bin(hex_string):
    bin_mapping = {
        '0': "0000", '1': "0001", '2': "0010", '3': "0011",
        '4': "0100", '5': "0101", '6': "0110", '7': "0111",
        '8': "1000", '9': "1001", 'A': "1010", 'B': "1011",
        'C': "1100", 'D': "1101", 'E': "1110", 'F': "1111"
    }

    binary_result = ""
    for char in hex_string:
        binary_result += bin_mapping[char]

    return binary_result

# Binary to hexadecimal conversion
def bin2hex(binary_string):
    hex_mapping = {
        "0000": '0', "0001": '1', "0010": '2', "0011": '3',
        "0100": '4', "0101": '5', "0110": '6', "0111": '7',
        "1000": '8', "1001": '9', "1010": 'A', "1011": 'B',
        "1100": 'C', "1101": 'D', "1110": 'E', "1111": 'F'
    }

    hex_result = ""
    for i in range(0, len(binary_string), 4):
        chunk = binary_string[i:i+4]
        hex_result += hex_mapping[chunk]

    return hex_result

# Binary to decimal conversion
def bin2dec(binary):
    decimal, i = 0, 0
    while binary:
        # Extract the last digit (rightmost bit) from the binary number
        digit = binary % 10
        # Calculate decimal value by adding the digit multiplied by 2^i
        decimal += digit * (2**i)
        # Move to the next digit by removing the last digit
        binary //= 10
        i += 1
    return decimal

# Decimal to binary conversion
def dec2bin(num):
    binary_result = bin(num).replace("0b", "")
    while len(binary_result) % 4 != 0:
        binary_result = '0' + binary_result
    return binary_result