import time
import os
from typing import List, Tuple
import hashlib

# 16x16 AES S-box
Sbox = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# 16x16 AES Inverse S-box
InvSbox = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Matrices for Mix columns and Inverse mix columns
Mixer    = [[0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]]

InvMixer = [[0x0E, 0x0B, 0x0D, 0x09],
            [0x09, 0x0E, 0x0B, 0x0D],
            [0x0D, 0x09, 0x0E, 0x0B],
            [0x0B, 0x0D, 0x09, 0x0E]]

# Round constants
Rcons = [
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A
]

# Constants
NUMBER_OF_COLUMNS = 4
NUMBER_OF_ROUNDS = 10
BLOCK_SIZE = 16

# Default for 128-bit key
NUMBER_OF_WORDS_IN_KEY = 4

# AES encryption and decryption operational functions
def sub_bytes(state: List[List[int]]) -> List[List[int]]:
    for i in range(4):
        for j in range(4):
            state[i][j] = Sbox[state[i][j]]
    return state

def inv_sub_bytes(state: List[List[int]]) -> List[List[int]]:
    for i in range(4):
        for j in range(4):
            state[i][j] = InvSbox[state[i][j]]
    return state

def shift_rows(state: List[List[int]]) -> List[List[int]]:
    for i in range(1, NUMBER_OF_COLUMNS):
        state[i] = state[i][i:] + state[i][:i]
    return state

def inv_shift_rows(state: List[List[int]]) -> List[List[int]]:
    for i in range(1, NUMBER_OF_COLUMNS):
        state[i] = state[i][-i:] + state[i][:-i]
    return state

def gmul(a: int, b: int) -> int:
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi_bit_set = a & 0x80
        a <<= 1
        if hi_bit_set:
            a ^= 0x11B
        b >>= 1
    return p & 0xFF

# Helper function extracted
def mix_columns_generic(state: List[List[int]], matrix: List[List[int]]) -> List[List[int]]:
    new_state = [[0] * 4 for _ in range(4)]
    for col in range(4):
        for row in range(4):
            new_state[row][col] = 0
            for k in range(4):
                new_state[row][col] ^= gmul(matrix[row][k], state[k][col])
    return new_state

def mix_columns(state: List[List[int]]) -> List[List[int]]:
    return mix_columns_generic(state, Mixer)

def inv_mix_columns(state: List[List[int]]) -> List[List[int]]:
    return mix_columns_generic(state, InvMixer)

def add_round_key(state: List[List[int]], round_key: List[int]) -> List[List[int]]:
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[j * 4 + i]
    return state

def sub_word(word: List[int]) -> List[int]:
    return [Sbox[byte] for byte in word]

def rot_word(word: List[int]) -> List[int]:
    return word[1:] + word[:1]

def key_expansion(key: bytes) -> List[int]:
    global NUMBER_OF_WORDS_IN_KEY, NUMBER_OF_ROUNDS
    key_length = len(key)
    
    if key_length == 16:  # 128 bits
        NUMBER_OF_WORDS_IN_KEY = 4
        NUMBER_OF_ROUNDS = 10
    elif key_length == 24:  # 192 bits
        NUMBER_OF_WORDS_IN_KEY = 6
        NUMBER_OF_ROUNDS = 12
    elif key_length == 32:  # 256 bits
        NUMBER_OF_WORDS_IN_KEY = 8
        NUMBER_OF_ROUNDS = 14
    else:
        if key_length < 16:
            key = key + b'\x00' * (16 - key_length)
        else:
            key = key[:16]
        NUMBER_OF_WORDS_IN_KEY = 4
        NUMBER_OF_ROUNDS = 10
    
    expanded_key = [0] * (4 * NUMBER_OF_COLUMNS * (NUMBER_OF_ROUNDS + 1))
    
    for i in range(NUMBER_OF_WORDS_IN_KEY * 4):
        expanded_key[i] = key[i]
    
    for i in range(NUMBER_OF_WORDS_IN_KEY, NUMBER_OF_COLUMNS * (NUMBER_OF_ROUNDS + 1)):
        temp = [expanded_key[(i-1)*4], expanded_key[(i-1)*4+1], 
                expanded_key[(i-1)*4+2], expanded_key[(i-1)*4+3]]
        
        if i % NUMBER_OF_WORDS_IN_KEY == 0:
            temp = rot_word(temp)
            temp = sub_word(temp)
            temp[0] ^= Rcons[i // NUMBER_OF_WORDS_IN_KEY]
        elif NUMBER_OF_WORDS_IN_KEY > 6 and i % NUMBER_OF_WORDS_IN_KEY == 4:
            temp = sub_word(temp)
        
        for j in range(4):
            expanded_key[i*4+j] = expanded_key[(i-NUMBER_OF_WORDS_IN_KEY)*4+j] ^ temp[j]
    
    return expanded_key

def bytes_to_state(block: bytes) -> List[List[int]]:
    state = [[0 for _ in range(4)] for _ in range(4)]
    for i in range(4):
        for j in range(4):
            state[i][j] = block[i + 4 * j]
    return state

def state_to_bytes(state: List[List[int]]) -> bytes:
    result = bytearray(16)
    for i in range(4):
        for j in range(4):
            result[i + 4 * j] = state[i][j]
    return bytes(result)

def aes_encrypt_block(block: bytes, expanded_key: List[int]) -> bytes:
    state = bytes_to_state(block)
    
    # Initial round
    round_key = expanded_key[:16]
    state = add_round_key(state, round_key)
    
    # Main rounds
    for round_num in range(1, NUMBER_OF_ROUNDS):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        round_key = expanded_key[round_num * 16:(round_num + 1) * 16]
        state = add_round_key(state, round_key)
    
    # Final round
    state = sub_bytes(state)
    state = shift_rows(state)
    round_key = expanded_key[NUMBER_OF_ROUNDS * 16:(NUMBER_OF_ROUNDS + 1) * 16]
    state = add_round_key(state, round_key)
    
    return state_to_bytes(state)

def aes_decrypt_block(block: bytes, expanded_key: List[int]) -> bytes:
    state = bytes_to_state(block)
    
    # Initial round
    round_key = expanded_key[NUMBER_OF_ROUNDS * 16:(NUMBER_OF_ROUNDS + 1) * 16]
    state = add_round_key(state, round_key)
    
    # Main rounds
    for round_num in range(NUMBER_OF_ROUNDS-1, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        round_key = expanded_key[round_num * 16:(round_num + 1) * 16]
        state = add_round_key(state, round_key)
        state = inv_mix_columns(state)
    
    # Final round
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    round_key = expanded_key[:16]
    state = add_round_key(state, round_key)
    
    return state_to_bytes(state)

def pkcs7_pad(data: bytes, block_size: int = BLOCK_SIZE) -> bytes:
    padding_length = block_size - (len(data) % block_size)
    padding = bytes([padding_length] * padding_length)
    return data + padding

def pkcs7_unpad(data: bytes) -> bytes:
    padding_length = data[-1]
    return data[:-padding_length]

def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))

def aes_encrypt_cbc(plain_text_input: bytes, key: bytes, iv: bytes = None) -> Tuple[bytes, float]:

    key_expansion_start_time = time.time()
    expanded_key = key_expansion(key)
    key_expansion_time = time.time() - key_expansion_start_time

    start_time = time.time()

    plaintext = plain_text_input.encode('utf-8')

    if iv is None:
        iv = os.urandom(BLOCK_SIZE)

    padded_plaintext = pkcs7_pad(plaintext)
    str_padded_plaintext = padded_plaintext.decode('utf-8')
    
    ciphertext = bytearray()
    previous_block = iv
    for i in range(0, len(padded_plaintext), BLOCK_SIZE):
        block = padded_plaintext[i:i+BLOCK_SIZE]
        xored_block = xor_bytes(block, previous_block)
        encrypted_block = aes_encrypt_block(xored_block, expanded_key)
        ciphertext.extend(encrypted_block)
        previous_block = encrypted_block
    
    encryption_time = time.time() - start_time
    
    return str_padded_plaintext, iv + bytes(ciphertext), encryption_time, key_expansion_time

def aes_decrypt_cbc(ciphertext: bytes, key: bytes) -> Tuple[bytes, float]:

    start_time = time.time()
    
    iv = ciphertext[:BLOCK_SIZE]
    ciphertext = ciphertext[BLOCK_SIZE:]
    
    expanded_key = key_expansion(key)
    
    plaintext = bytearray()
    previous_block = iv
    
    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i+BLOCK_SIZE]
        decrypted_block = aes_decrypt_block(block, expanded_key)
        xored_block = xor_bytes(decrypted_block, previous_block)
        plaintext.extend(xored_block)
        previous_block = block
    
    str_padded_text = plaintext.decode('utf-8')
    unpadded_plaintext = pkcs7_unpad(plaintext)
    decrypted_text = unpadded_plaintext.decode('utf-8')
    
    decryption_time = time.time() - start_time
    
    return str_padded_text, decrypted_text, decryption_time

def handle_key(key_input: str) -> bytes:
    key_bytes = key_input.encode('utf-8')
    key_length = len(key_bytes)
    
    if key_length == 16:
        print("\nUsing AES-128")
        return key_bytes
    elif key_length == 24:
        print("\nUsing AES-192")
        return key_bytes
    elif key_length == 32:
        print("\nUsing AES-256")
        return key_bytes
    else:
        if key_length < 16:
            print(f"Key is too short/not standard. Padding to 16 bytes.")
            return key_bytes + b'\x00' * (16 - key_length)
        elif key_length > 16:
            print("Key is too long/not standard. Hashing and truncating to 16 bytes.")
            hashed_key = hashlib.sha256(key_bytes).digest()
            return hashed_key[:16]

def string_to_hex(s: str) -> str:
    return ' '.join(f"{ord(c):02x}" for c in s)

def main():
    print("\nKey: ")
    key_input = input("In ASCII: ")
    hex_key = string_to_hex(key_input)
    print("In HEX: ", hex_key)
    
    key = handle_key(key_input)
    
    print("\nPlain Text: ")
    plain_text_input = input("In ASCII: ")
    hex_plain_text = string_to_hex(plain_text_input)
    print("In HEX: ", hex_plain_text)    
    
    iv = os.urandom(BLOCK_SIZE)
    padded_plain_text, ciphertext, encryption_time, key_expansion_time = aes_encrypt_cbc(plain_text_input, key, iv)

    print("IN ASCII(After Padding): ", padded_plain_text)
    hex_padded_text = string_to_hex(padded_plain_text)
    print("IN HEX(After Padding): ", hex_padded_text)

    print("\nCiphered Text:")
    print(f"In HEX: {' '.join(f'{b:02x}' for b in ciphertext[BLOCK_SIZE:])}")
    # print("In ASCII: ", ciphertext.decode('unicode_escape', errors='backslashreplace'))
    print("In ASCII: ", ciphertext)

    padded_decrypted_text, decrypted_text, decryption_time = aes_decrypt_cbc(ciphertext, key)

    print("\nDeciphered Text:")
    print("Before Unpadding:")
    hex_padded_text = string_to_hex(padded_decrypted_text)
    print("IN HEX: ", hex_padded_text)
    print("IN ASCII: ", padded_decrypted_text)

    print("After Unpadding:")
    print("IN ASCII: ", decrypted_text)
    hex_decrypted_text = string_to_hex(decrypted_text)
    print("IN HEX: ", hex_decrypted_text)

    print(f"\nExecution Time Details:")
    print(f"Key Schedule Time: {key_expansion_time * 1000:.6f} ms")
    print(f"Encryption Time: {encryption_time * 1000:.6f} ms")
    print(f"Decryption Time: {decryption_time * 1000:.6f} ms\n")

if __name__ == "__main__":
    main()