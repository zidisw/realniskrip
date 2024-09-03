import random
import os
from django.conf import settings
import base64
from string import printable
import time
import math
from docx import Document
import numpy as np
import sys
from Crypto.Util.Padding import pad, unpad
from functools import reduce
from operator import mul
from pydrive.auth import GoogleAuth
from pydrive.drive import GoogleDrive
import dropbox

# AES S-box
s_box = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5,
    0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc,
    0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a,
    0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b,
    0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85,
    0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17,
    0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88,
    0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9,
    0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6,
    0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94,
    0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68,
    0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
]

# Inverse S-box
inv_s_box = [
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38,
    0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87,
    0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d,
    0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2,
    0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16,
    0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda,
    0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a,
    0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02,
    0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea,
    0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85,
    0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89,
    0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20,
    0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31,
    0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d,
    0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0,
    0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26,
    0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
]

# Rijndael Rcon
rcon = [
    0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
    0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a,
    0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39,
    0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
    0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a,
    0x74, 0xe8, 0xcb, 0x8d
]
# Constants for AES
BLOCK_SIZE = 16

# Helper function to XOR bytes
def xor_bytes(a, b):
    return bytes(i ^ j for i, j in zip(a, b))

# Key expansion function
def key_expansion(key):
    # Pastikan key adalah bytes
    if isinstance(key, str):
        key = bytes.fromhex(key)

    # Inisialisasi kolom kunci dari kunci input
    key_columns = bytes_to_matrix(key)
    iteration_size = len(key) // 4
    expanded_keys = []
    i = 1  # Rcon starts at index 1 as per AES specification

    # Copy initial key into expanded keys
    expanded_keys.extend(sum(key_columns, []))  # Flatten and extend

    # Generate the required keys
    while len(expanded_keys) < 44 * 4:  # 44 words, each word is 4 bytes
        word = expanded_keys[-4:]  # Get the last word (4 bytes)
        if len(expanded_keys) // 4 % iteration_size == 0:  # Each 4 words
            # Rotate word
            word = word[1:] + word[:1]
            # Apply S-box and the round constant
            word = [s_box[b] for b in word]
            word[0] ^= rcon[i]  # Round constant only to the first byte
            i += 1

        # XOR with the word 4 positions (16 bytes) back
        word = [a ^ b for a, b in zip(word, expanded_keys[-16:-12])]
        expanded_keys.extend(word)

    # Return the key schedule in chunks of 4 bytes (each key round)
    return [expanded_keys[i:i+4] for i in range(0, len(expanded_keys), 4)]

# def pad(data, block_size=16):
#     padding = block_size - len(data) % block_size
#     return data + bytes([padding] * padding)

# def unpad(data, block_size):
#     padding = data[-1]  # Last byte value represents the padding added
#     if padding > block_size:
#         raise ValueError("Invalid padding")
#     return data[:-padding]

def aes_complete_encrypt(data, key):
    key_schedule = key_expansion(key)
    encrypted_data = b""
    data = pad(data, BLOCK_SIZE)  # Pad data to ensure it's a multiple of 16 bytes

    logger.info(f"Panjang data setelah padding: {len(data)}")  # Log the length after padding

    for i in range(0, len(data), BLOCK_SIZE):
        block = data[i:i + BLOCK_SIZE]
        block_matrix = bytes_to_matrix(block)

        # Initial round key addition
        add_round_key(block_matrix, key_schedule, 0)

        # Main rounds
        for round in range(1, 10):
            sub_bytes(block_matrix)
            shift_rows(block_matrix)
            mix_columns(block_matrix)
            add_round_key(block_matrix, key_schedule, round)

        # Final round
        sub_bytes(block_matrix)
        shift_rows(block_matrix)
        add_round_key(block_matrix, key_schedule, 10)

        encrypted_block = matrix_to_bytes(block_matrix)
        encrypted_data += encrypted_block

    logger.info(f"Panjang ciphertext: {len(encrypted_data)}")  # Log the length of the final ciphertext

    return encrypted_data

def encrypt_file_util(file_path, key):
    try:
        with open(file_path, 'rb') as file:
            file_content = file.read()

        logger.info(f"File read successfully: {file_path}")
        logger.info(f"File content (first 20 bytes): {file_content[:20].hex()}")  # Log first 20 bytes as hex

        encrypted_content = aes_complete_encrypt(file_content, key)
        encrypted_file_path = file_path + '.enc'

        with open(encrypted_file_path, 'wb') as file:
            file.write(encrypted_content)

        logger.info(f"File encrypted successfully. Encrypted file saved to {encrypted_file_path}")
        return encrypted_file_path

    except Exception as e:
        logger.error(f"Error during encryption: {e}")
        raise

def adjust_key_length(key):
    if isinstance(key, str):
        key = key.encode()  # Konversi string ke bytes jika diperlukan

    if not isinstance(key, bytes):
        key = str(key).encode()  # Konversi jenis lain ke bytes

    while len(key) < 16:
        key += key  # Ulangi kunci jika terlalu pendek

    return key[:16]  # Potong jika terlalu panjang


# Ensure other functions like bytes_to_matrix, matrix_to_bytes, sub_bytes, shift_rows, mix_columns, and add_round_key are correctly implemented

def state_to_data(state):
    """Converts a 4x4 state matrix back into a 16-byte array."""
    # Flatten the 4x4 matrix row-wise and convert to bytes
    return bytes(sum(state, []))

def data_to_state(data):
    """Converts a 16-byte array into a 4x4 state matrix."""
    if len(data) != 16:
        raise ValueError("Data block must be exactly 16 bytes to convert into state matrix.")
    # Convert bytes directly into a 4x4 matrix
    return [list(data[i:i+4]) for i in range(0, 16, 4)]

def decrypt_file_util(encrypted_file_path, key):
    try:
        with open(encrypted_file_path, 'rb') as file:
            encrypted_data = file.read()

        logger.info(f"Encrypted file read successfully: {encrypted_file_path}")
        decrypted_data = aes_decrypt(encrypted_data, key)
        decrypted_file_path = encrypted_file_path + '.dec'

        with open(decrypted_file_path, 'wb') as file:
            file.write(decrypted_data)

        logger.info(f"File decrypted successfully. Decrypted file saved to {decrypted_file_path}")
        return decrypted_file_path

    except Exception as e:
        logger.error(f"Error during decryption: {e}")
        raise

def aes_decrypt(data, key):
    if isinstance(data, str):
        data = bytes(data, 'utf-8')

    key_schedule = key_expansion(key)
    decrypted_data = b""

    # Memastikan data adalah kelipatan dari 16 bytes
    if len(data) % 16 != 0:
        raise ValueError("Ciphertext must be a multiple of 16 bytes.")

    for i in range(0, len(data), 16):
        block = data[i:i+16]
        if len(block) != 16:
            raise ValueError("Data block must be exactly 16 bytes to convert into state matrix.")
        block_matrix = bytes_to_matrix(block)

        add_round_key(block_matrix, key_schedule, 10)
        for round in range(9, 0, -1):
            inv_shift_rows(block_matrix)
            inv_sub_bytes(block_matrix)
            add_round_key(block_matrix, key_schedule, round)
            inv_mix_columns(block_matrix)
        inv_shift_rows(block_matrix)
        inv_sub_bytes(block_matrix)
        add_round_key(block_matrix, key_schedule, 0)

        decrypted_block = matrix_to_bytes(block_matrix)
        decrypted_data += decrypted_block

    return unpad(decrypted_data, 16)  # Unpad after decryption




# Convert bytes to matrix and vice versa
def bytes_to_matrix(text):
    """ Converts a 16-byte array into a 4x4 matrix. """
    return [list(text[i:i+4]) for i in range(0, len(text), 4)]

def matrix_to_bytes(matrix):
    """ Converts a 4x4 matrix into a 16-byte array. """
    return bytes(sum(matrix, []))



# AES round functions and utility functions
def sub_bytes(state):
    try:
        for i in range(4):
            for j in range(4):
                state[i][j] = s_box[state[i][j]]
    except IndexError as e:
        logger.error("Sub_bytes index error")
        raise


def inv_sub_bytes(state):
    for i in range(len(state)):
        for j in range(len(state[i])):
            state[i][j] = inv_s_box[state[i][j]]

def shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]

def inv_shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]

def mix_columns(state):
    for i in range(4):
        a = state[i]
        t = a[0] ^ a[1] ^ a[2] ^ a[3]
        u = a[0]
        a[0] ^= t ^ xtime(a[0] ^ a[1])
        a[1] ^= t ^ xtime(a[1] ^ a[2])
        a[2] ^= t ^ xtime(a[2] ^ a[3])
        a[3] ^= t ^ xtime(a[3] ^ u)

def inv_mix_columns(state):
    for i in range(4):
        u = xtime(xtime(state[i][0] ^ state[i][2]))
        v = xtime(xtime(state[i][1] ^ state[i][3]))
        state[i][0] ^= u
        state[i][1] ^= v
        state[i][2] ^= u
        state[i][3] ^= v

    mix_columns(state)

def xtime(a):
    return (((a << 1) ^ 0x1b) & 0xff) if (a & 0x80) else (a << 1)

def add_round_key(state, key_schedule, round_number):
    round_key = key_schedule[round_number * 4:(round_number + 1) * 4]
    if len(round_key) < 4:
        raise ValueError("Round key is not of correct length.")
    for i in range(4):
        for j in range(4):
            state[i][j] ^= round_key[i][j]


# File operations
def read_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def write_file(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)

# RSA utility functions
def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    d, x1, x2, y1 = 0, 0, 1, 1
    temp_phi = phi

    while e > 0:
        temp1 = temp_phi // e
        temp2 = temp_phi - temp1 * e
        temp_phi, e = e, temp2

        x = x2 - temp1 * x1
        y = d - temp1 * y1

        x2, x1 = x1, x
        d, y1 = y1, y

    if temp_phi == 1:
        return d + phi

# Membaca bilangan prima dari file
def read_primes(file_path):
    with open(file_path, 'r') as file:
        primes = file.read().split()
    return list(map(int, primes))

# Memilih dua bilangan prima dari daftar
def choose_two_primes(primes):
    p = random.choice(primes)
    q = random.choice(primes)
    while q == p:
        q = random.choice(primes)
    return p, q

# Generate kunci RSA
def generate_rsa_keys(primes_file):
    primes = read_primes(primes_file)
    p, q = choose_two_primes(primes)
    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537
    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = mod_inverse(e, phi)

    return ((e, n), (d, n))

def save_rsa_keys_to_file(public_key, private_key, public_key_path, private_key_path):
    with open(public_key_path, 'w') as f:
        f.write(f"{public_key[0]},{public_key[1]}")  # menyimpan sebagai e,n

    with open(private_key_path, 'w') as f:
        f.write(f"{private_key[0]},{private_key[1]}")  # menyimpan sebagai d,n


# Fungsi enkripsi dan dekripsi RSA
def rsa_encrypt(public_key, plaintext):
    e, n = public_key
    block_size = (n.bit_length() + 7) // 8 - 1  # Menghitung ukuran blok

    encrypted_blocks = []
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i:i+block_size]
        if len(block) < block_size:
            block += b'\x00' * (block_size - len(block))  # Padding if necessary
        block_int = int.from_bytes(block, 'big')
        encrypted_block = pow(block_int, e, n)
        encrypted_blocks.append(encrypted_block)

    return encrypted_blocks

def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    block_size = (n.bit_length() + 7) // 8 - 1  # Menghitung ukuran blok

    decrypted_bytes = bytearray()
    for encrypted_block in ciphertext:
        decrypted_block_int = pow(encrypted_block, d, n)
        decrypted_block = decrypted_block_int.to_bytes(block_size, 'big').rstrip(b'\x00')
        decrypted_bytes.extend(decrypted_block)

    # Memastikan panjang kunci tepat 16 bytes
    if len(decrypted_bytes) != 16:
        logger.error(f"Decrypted key has incorrect length: {len(decrypted_bytes)} bytes")
        raise ValueError("Decryption key must be exactly 16 bytes long")

    return decrypted_bytes


## File operations and main encryption/decryption logic
def read_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

def write_file(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)

import logging

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


import hashlib
def prepare_rsa_key(key_file):
    try:
        key = key_file.read().strip()  # Membaca konten file sebagai bytes
        logger.info(f"Original RSA private key length: {len(key)} bytes")

        # Decode bytes to string and split the key into parts, then convert to integer
        key_str = key.decode('utf-8')
        key_parts = key_str.split(',')
        private_key = (int(key_parts[0]), int(key_parts[1]))

        return private_key
    except Exception as e:
        logger.error(f"Error reading RSA private key: {e}")
        return None

def prepare_aes_key(key_file):
    try:
        key = key_file.read().strip()  # Bersihkan whitespace dan null bytes

        # Log untuk debugging
        logger.info(f"Original key length before cleaning: {len(key)} bytes, Key (hex): {key.hex()}")

        # Hapus semua karakter yang tidak diinginkan
        key = key.replace(b'\r', b'').replace(b'\n', b'').replace(b',', b'')

        # Log untuk debugging setelah membersihkan
        logger.info(f"Cleaned key length: {len(key)} bytes, Key (hex): {key.hex()}")

        # Memastikan panjang kunci adalah 16 bytes untuk AES-128
        if len(key) != 16:
            logger.error("Encryption key must be exactly 16 bytes long")
            return None  # Kunci tidak valid

        return key
    except Exception as e:
        logger.error(f"Error reading key: {e}")
        return None
    

#SHAMIR SECRET SHARING

# Fungsi untuk menemukan inversi modulo
def mod_inverse(a, p):
    return pow(a, -1, p)

# Fungsi untuk mengevaluasi polinomial pada x
def eval_poly(poly, x, p):
    return sum((coef * pow(x, exp, p)) % p for exp, coef in enumerate(poly)) % p

# Fungsi untuk mengalikan beberapa angka
def prod(vals):
    return reduce(mul, vals, 1)

# Fungsi untuk membuat polinomial acak
def random_poly(degree, secret, p):
    coeffs = [secret] + [random.randint(0, p-1) for _ in range(degree)]
    return coeffs

# Fungsi untuk membuat n shares dari secret dengan threshold t
def make_shares(secret, n, t, p=2**127-1):
    poly = random_poly(t-1, secret, p)
    shares = [(i, eval_poly(poly, i, p)) for i in range(1, n+1)]
    return shares

# Fungsi untuk merekonstruksi secret dari shares
def recover_secret(shares, p=2**127-1):
    x_s, y_s = zip(*shares)
    secret = sum(y_s[i] * prod([(x_s[j] * mod_inverse(x_s[j] - x_s[i], p)) % p for j in range(len(shares)) if i != j]) for i in range(len(shares))) % p
    return secret

# Fungsi untuk membaca file biner
def read_binary_file(file_path):
    with open(file_path, 'rb') as file:
        return file.read()

# Fungsi untuk menulis file biner
def write_binary_file(file_path, data):
    with open(file_path, 'wb') as file:
        file.write(data)

# Fungsi untuk membagi data menjadi dua bagian
def split_data(data, split_size):
    return data[:split_size], data[split_size:]

# Fungsi untuk menggabungkan kembali dua bagian data
def join_data(small_part, large_part):
    return small_part + large_part

# Fungsi untuk membuat n shares dari bagian kecil dengan threshold t
def shamir_split_small_part(small_part, n=3, t=2):
    secret = int.from_bytes(small_part, 'big')
    shares = make_shares(secret, n, t)
    return shares

# Fungsi untuk merekonstruksi bagian kecil dari shares
def shamir_reconstruct_small_part(shares):
    secret = recover_secret(shares)
    small_part = secret.to_bytes((secret.bit_length() + 7) // 8, 'big')
    return small_part

# Fungsi untuk memproses pembagian data .enc menggunakan Shamir's Secret Sharing
def process_shamir_secret_sharing(file_path):
    data = read_binary_file(file_path)
    small_part, large_part = split_data(data, 16)  # 16 bytes untuk bagian kecil
    small_part_shares = shamir_split_small_part(small_part)
    return small_part_shares, large_part

# Fungsi untuk merekonstruksi data dari shares dan bagian besar
def reconstruct_from_shares(small_part_shares, large_part):
    reconstructed_small_part = shamir_reconstruct_small_part(small_part_shares)
    reconstructed_data = join_data(reconstructed_small_part, large_part)
    return reconstructed_data


#UPLOAD KE CLOUD
# def upload_to_google_drive(file_path, folder_id=None):
#     gauth = GoogleAuth()
#     gauth.LoadClientConfigFile("client_secrets.json")

#     # Autentikasi
#     gauth.LocalWebserverAuth()  # Ini akan menghandle autentikasi

#     drive = GoogleDrive(gauth)
#     file_drive = drive.CreateFile({'title': os.path.basename(file_path), 'parents': [{'id': folder_id}] if folder_id else []})
#     file_drive.SetContentFile(file_path)
#     file_drive.Upload()
#     return file_drive['id']

# def upload_to_dropbox(file_path, dropbox_access_token):
#     dbx = dropbox.Dropbox(dropbox_access_token)
    
#     with open(file_path, "rb") as f:
#         dbx.files_upload(f.read(), "/" + os.path.basename(file_path), mute=True)
#     return os.path.basename(file_path)
