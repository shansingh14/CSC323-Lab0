import base64
from collections import Counter
import itertools
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
        for key in range(256): 
            decrypted_text = xor_bytes(hex_string.strip(), key)
            score = score_plaintxt(decrypted_text)

            if score > highest_score:
                highest_score = score
                english_plaintext = decrypted_text

    return english_plaintext

# learned about this technique to estimate key lengths from: https://en.wikipedia.org/wiki/Friedman_test
def friedman_test(encoded_bytes):
    frequencies = Counter(encoded_bytes)
    N = len(encoded_bytes)
    ic = sum(f * (f - 1) for f in frequencies.values()) / (N * (N - 1)) if N > 1 else 0
    avg_ic_english = 0.0667
    avg_ic_random = 0.0385
    key_length = (avg_ic_english * N) / (ic * (N - 1) + avg_ic_english - avg_ic_random * N) if ic > 0 else 1
    return max(1, round(key_length))

def break_xor(encoded_bytes, key_length):
    blocks = [encoded_bytes[i::key_length] for i in range(key_length)]
    key = []
    for block in blocks:
        highest_score = 0
        probable_key_byte = 0
        for key_byte in range(256):
            decrypted_text = bytes([b ^ key_byte for b in block])
            score = score_plaintxt(decrypted_text.decode(errors='ignore'))
            if score > highest_score:
                highest_score = score
                probable_key_byte = key_byte
        key.append(probable_key_byte)
    return bytes(key)

def decrypt_xor_with_key(encoded_bytes, key):
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(encoded_bytes))

def decrypt_base64_xor(file_path):
    with open(file_path, 'rb') as file:
        encoded_bytes = base64.b64decode(file.read())
    estimated_key_length = friedman_test(encoded_bytes)
    key = break_xor(encoded_bytes, estimated_key_length)
    decrypted_bytes = decrypt_xor_with_key(encoded_bytes, key)
    try:
        decrypted_text = decrypted_bytes.decode('utf-8')
    except UnicodeDecodeError:
        decrypted_text = str(decrypted_bytes)
    return decrypted_text, key


def caesar_decrypt_letter(letter, shift):
    if letter.isalpha():
        shifted = ord(letter.lower()) - shift
        if shifted < ord('a'):
            shifted += 26
        return chr(shifted)
    return letter

# Function to perform frequency analysis on each letter of the key
def vigenere_frequency_analysis(ciphertext, key_length):
    key = ''
    for i in range(key_length):
        # Extract every nth letter (where n is the key length)
        nth_letters = ciphertext[i::key_length]
        
        # Frequency analysis to find the most likely shift
        frequencies = Counter(nth_letters)
        most_common = frequencies.most_common(1)[0][0]
        shift = (ord(most_common) - ord('e')) % 26  # Assuming 'e' is the most common letter
        key += chr(shift + ord('a'))
    return key

# Function to decrypt the Vigenère cipher
def decrypt_vigenere(ciphertext, key):
    decrypted_text = ''
    key_index = 0
    for char in ciphertext:
        if char.isalpha():
            shift = ord(key[key_index]) - ord('a')
            decrypted_char = caesar_decrypt_letter(char, shift)
            decrypted_text += decrypted_char
            key_index = (key_index + 1) % len(key)
        else:
            decrypted_text += char
    return decrypted_text

# Function to decrypt a file encrypted with the Vigenère cipher
def decrypt_vigenere_file(file_path):
    with open(file_path, 'r') as file:
        ciphertext = file.read()

    key_length = friedman_test(ciphertext)
    key = vigenere_frequency_analysis(ciphertext, key_length)
    decrypted_text = decrypt_vigenere(ciphertext, key)

    return decrypted_text, key


if __name__ == "__main__":
    # print(bytes_to_hex("dd3253b54eb080325a"))
    # test_xor_bytes()
    print(find_english_plaintext("Lab0 TaskII B.txt"))
    #print(decrypt_base64_xor("Lab0 TaskII C.txt"))
    print(decrypt_vigenere_file("Lab0 Task II D.txt"))

