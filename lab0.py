import base64
from collections import Counter
# Helper functions 


def bytes_to_hex(s):
    return s.encode('utf-8').hex()

def hex_to_string(hex_str):
    return bytes.fromhex(hex_str).decode('utf-8')

def base64_to_bytes(str):
    return base64.b64decode(str)

def bytes_to_base64(bytes):
    return base64.b64encode(bytes).decode('utf-8')


def xor_bytes(var, key):
    repeated_key = (key * (len(var) // len(key) + 1))[:len(var)]

    # XOR each byte of var with the corresponding byte in the repeated key
    result = bytearray()
    for byte_var, byte_key in zip(var, repeated_key):
        result.append(byte_var ^ byte_key)

    return bytes(result)

# function to score the encoded text
def score_encoded(byte_text):

    # got frequencies from https://en.wikipedia.org/wiki/Letter_frequency
    english_freq = {
        'a': 0.0816, 'b': 0.0149, 'c': 0.0278, 'd': 0.0425, 'e': 0.1270,
        'f': 0.0222, 'g': 0.0201, 'h': 0.0609, 'i': 0.0696, 'j': 0.0015,
        'k': 0.0077, 'l': 0.0402, 'm': 0.0240, 'n': 0.0674, 'o': 0.0750,
        'p': 0.0192, 'q': 0.0009, 'r': 0.0598, 's': 0.0632, 't': 0.0905,
        'u': 0.0275, 'v': 0.0097, 'w': 0.0236, 'x': 0.0015, 'y': 0.0197,
        'z': 0.0007, ' ': 0.1300
    }

    # Decode byte_text to string, ignore errors in case of non-ASCII bytes
    try:
        text = byte_text.decode('ascii', errors='ignore')
    except UnicodeDecodeError:
        return 0

    # Score the text
    score = 0
    for char in text.lower():
        if char in english_freq:
            score += english_freq[char]

    return score

# function to score plain text
def score_plain(text):
     # got frequencies from https://en.wikipedia.org/wiki/Letter_frequency
    english_freq = {
            'a': 0.0816, 'b': 0.0149, 'c': 0.0278, 'd': 0.0425, 'e': 0.1270,
            'f': 0.0222, 'g': 0.0201, 'h': 0.0609, 'i': 0.0696, 'j': 0.0015,
            'k': 0.0077, 'l': 0.0402, 'm': 0.0240, 'n': 0.0674, 'o': 0.0750,
            'p': 0.0192, 'q': 0.0009, 'r': 0.0598, 's': 0.0632, 't': 0.0905,
            'u': 0.0275, 'v': 0.0097, 'w': 0.0236, 'x': 0.0015, 'y': 0.0197,
            'z': 0.0007, ' ': 0.1300
        }

    text = text.lower()

    total_letters = sum(text.count(letter) for letter in english_freq)

    score = 0
    for letter, expected_freq in english_freq.items():
        observed_freq = text.count(letter) / total_letters if total_letters > 0 else 0

        score += abs(expected_freq - observed_freq)

    return score

def decrypt_single_byte(file_path):
    with open(file_path, 'r') as file:
        hex_strings = file.readlines()

    highest_score = 0
    english_plaintext = ""

    for hex_string in hex_strings:
        # Run through all possible keys (1-256)
        for key in range(256): 
            # XOR and find score 
            decrypted_text = xor_bytes(bytes.fromhex(hex_string.strip()), bytes([key]))
            score = score_encoded(decrypted_text)
            
            # If the score is the heighier than the previous keys, set new best message and score
            if score > highest_score:
                highest_score = score
                english_plaintext = decrypted_text

    print(english_plaintext.decode('utf-8', errors='ignore'))

#------------------------------------------------------------------------------------------------------

# breaking text into chunks for comparision
def init_chunks(ciphertxt, key_len):
    chunks = []
    for i in range(0, len(ciphertxt), key_len):
        chunks.append(ciphertxt[i:i+key_len])

    return chunks


# Using Kasiski's algorithm to estimate key length, https://en.wikipedia.org/wiki/Kasiski_examination
# Find common sequences of chunk (hamming distance)
def kasiski_key_length(ciphertxt, max_key_len=20):
    key_scores = {}
    # Start at 2 as we know this isnt a single byte encryption
    for key_len in range(2, max_key_len + 1):
        chunks = init_chunks(ciphertxt, key_len)

        dist_avgs = []

        # iterate over each chunk and compare it every chunk after the current one
        for cur_chunk in range(len(chunks)):
            for comp_chunk in range(cur_chunk+ 1, len(chunks)):
                # calculate distance between chunks using Hamming distance
                # found algo -> https://en.wikipedia.org/wiki/Hamming_distance
                distance = sum(bin(byte).count('1') for byte in (xor_bytes(chunks[cur_chunk], chunks[comp_chunk])))

                # then normalize the distances
                dist_avgs.append(distance / key_len)

        dist_avgs_score = sum(dist_avgs) / len(dist_avgs)
        key_scores[key_len] = dist_avgs_score

    return min(key_scores, key=key_scores.get)

# find correct key
# Go through possibly single byte keys and find the best byte
def get_best_key(key_len, ciphertext):
    best_key = b""

    for starting_idx in range(key_len):

        highest_score = 0
        best_single_byte_key = None
        block = bytes(ciphertext[starting_idx::key_len])

        for key in range(256): 
            decrypted_text = xor_bytes(block, bytes([key]))
            score = score_encoded(decrypted_text)

            if score > highest_score:
                highest_score = score
                best_single_byte_key = key  

        if best_single_byte_key is not None:
            best_key += bytes([best_single_byte_key])
        else:
            best_key += b'\x00'

    return best_key

def read_file(file_path):
    with open(file_path, 'r') as file:
        text = file.read().strip()
    return text

def decrypt_multi_bytes(file_path):
    ciphertxt = base64_to_bytes(read_file(file_path))

    best_key_len = kasiski_key_length(ciphertxt)
    xor_key = get_best_key(best_key_len, ciphertxt)
    decrypted_txt = (xor_bytes(ciphertxt, xor_key)).decode('utf-8', errors='ignore')

    print(decrypted_txt)
    print(best_key_len)
    print(xor_key.decode('utf-8', errors='ignore'))

#----------------------------------------------------------------------------------------------

def vigenere_decrypt(ciphertext, key):
    decrypted_text = ''
    # repeatedly extend the key to match cipher text length
    rep_count = len(ciphertext) // len(key) + 1
    exp_key = key * rep_count
    key_trimmed = exp_key[:len(ciphertext)]

    for i in range(len(ciphertext)):
        # converting the key and cipher to ascii
        ascii_char = ord(ciphertext[i])
        ascii_key_char = ord(key_trimmed[i])

        # difference calculation as well as adjust diff.
        diff = ascii_char - ascii_key_char
        diff_adj = (diff + 26) % 26

        # convert the adj. diff. back into ascii and concate. into text
        decrypted_ascii = diff_adj + ord('A')
        decrypted_char = chr(decrypted_ascii)
        decrypted_text += decrypted_char.lower()

    return decrypted_text

def get_vigenere_key(ciphertext, key_length):
    best_key = ''
    for i in range(key_length):
        # truncate to get the block
        block = ciphertext[i::key_length]
        shift_value = 0
        highest_score = 10000

        for shift in range(26):
            decrypted_text = vigenere_decrypt(block, chr(shift + ord('A')))
            score = score_plain(decrypted_text)

            if score < highest_score:
                highest_score = score
                shift_value = shift
        best_key += chr(shift_value + ord('A'))
    return best_key


def decrypt_vigenere_cipher(file_path):
    ciphertext = read_file(file_path)

    key_length = kasiski_key_length(bytes(ciphertext, 'utf-8'))
    vigenere_key = get_vigenere_key(ciphertext, key_length)
    decrypted_text = vigenere_decrypt(ciphertext, vigenere_key)

    print(key_length)
    print("Key:", vigenere_key)
    print(decrypted_text.lower())


if __name__ == "__main__":
    print("----------Task B--------------")
    decrypt_single_byte("Lab0 TaskII B.txt")
    print("----------Task C--------------")
    decrypt_multi_bytes("Lab0 TaskII C.txt")
    print("----------Task D--------------")
    decrypt_vigenere_cipher("Lab0 Task II D.txt")

