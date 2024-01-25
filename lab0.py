import base64

# Helper functions 
def bytes_to_hex(s):
    return s.encode('utf-8').hex()

def hex_to_string(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

def base64_to_bytes(str):
    return base64.b64decode(str)

def bytes_to_base64(bytes):
    return base64.b64encode(bytes).decode('utf-8')


def xor_bytes(str1, str2):
    decoded_bytes = bytes.fromhex(str1)
    return ''.join(chr(byte ^ str2) for byte in decoded_bytes)

# Function to score the text
def score_plaintxt(text):

    # got frequencies from https://en.wikipedia.org/wiki/Letter_frequency
    english_freq = {
            'a': 0.0816, 'b': 0.0149, 'c': 0.0278, 'd': 0.0425, 'e': 0.1270,
            'f': 0.0222, 'g': 0.0201, 'h': 0.0609, 'i': 0.0696, 'j': 0.0015,
            'k': 0.0077, 'l': 0.0402, 'm': 0.0240, 'n': 0.0674, 'o': 0.0750,
            'p': 0.0192, 'q': 0.0009, 'r': 0.0598, 's': 0.0632, 't': 0.0905,
            'u': 0.0275, 'v': 0.0097, 'w': 0.0236, 'x': 0.0015, 'y': 0.0197,
            'z': 0.0007, ' ': 0.1300
        }

    # get scores of each character using frequency list 
    score = 0
    for char in text.lower():
        if char in english_freq:
            score += english_freq[char]
    
    return score


def find_english_plaintext(file_path):
    with open(file_path, 'r') as file:
        hex_strings = file.readlines()

    highest_score = 0
    english_plaintext = ""

    for hex_string in hex_strings:
        for key in range(256):  # All possible byte values (0-255)
            decrypted_text = xor_bytes(hex_string.strip(), key)
            score = score_plaintxt(decrypted_text)

            if score > highest_score:
                highest_score = score
                english_plaintext = decrypted_text

    return english_plaintext


if __name__ == "__main__":
    # print(bytes_to_hex("dd3253b54eb080325a"))
    # test_xor_bytes()
    print(find_english_plaintext("Lab0 TaskII B.txt"))

