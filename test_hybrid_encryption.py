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

#AES functions and constants
nb = 4  
nr = 10  
nk = 4

sbox = [
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

inv_sbox = [
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

rcon = [
    [0x01, 0x00, 0x00, 0x00],
    [0x02, 0x00, 0x00, 0x00],
    [0x04, 0x00, 0x00, 0x00],
    [0x08, 0x00, 0x00, 0x00],
    [0x10, 0x00, 0x00, 0x00],
    [0x20, 0x00, 0x00, 0x00],
    [0x40, 0x00, 0x00, 0x00],
    [0x80, 0x00, 0x00, 0x00],
    [0x1b, 0x00, 0x00, 0x00],
    [0x36, 0x00, 0x00, 0x00]
]

# rcon = [[0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36],
#         [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
#         [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
#         [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
# ]

# RSA Utility Functions
# Fungsi utilitas
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

# Fungsi enkripsi dan dekripsi RSA
def rsa_encrypt(public_key, plaintext):
    e, n = public_key
    block_size = (n.bit_length() + 7) // 8 - 1  # Menghitung ukuran blok
    plaintext_bytes = plaintext.encode()
    
    encrypted_blocks = []
    for i in range(0, len(plaintext_bytes), block_size):
        block = plaintext_bytes[i:i+block_size]
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
        decrypted_block = decrypted_block_int.to_bytes(block_size + 1, 'big')
        decrypted_bytes.extend(decrypted_block)
    
    return decrypted_bytes.rstrip(b'\x00').decode('utf-8', 'ignore')

# Fungsi untuk operasi AES
def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def pad(data):
    pad_length = 16 - (len(data) % 16)
    print(f"Padding length: {pad_length}")
    padded_data = data + bytes([pad_length] * pad_length)
    print(f"Padded data: {padded_data}")
    return padded_data

def unpad(data):
    pad_length = data[-1]
    print(f"Padding length detected: {pad_length}")
    unpadded_data = data[:-pad_length]
    print(f"Unpadded data: {unpadded_data}")
    return unpadded_data

# Fungsi untuk menambahkan padding base64
def pad_base64(b64_string):
    return b64_string + '=' * (4 - len(b64_string) % 4)

# Fungsi untuk menghapus padding base64
def unpad_base64(b64_string):
    return b64_string.rstrip('=')

# Fungsi AddRoundKey
def add_round_key(state, key_schedule, round):
    for i in range(4):
        for j in range(4):
            state[i][j] ^= key_schedule[round * 4 + j][i]
    return state

# Implementasi lengkap key expansion yang dibutuhkan oleh AES
def key_expansion(key):
    key_symbols = [symbol for symbol in key]
    key_schedule = [[0] * 4 for _ in range(44)]
    
    for r in range(4):
        for c in range(4):
            key_schedule[r][c] = key_symbols[r + 4 * c]
    
    for col in range(4, 44):
        tmp = key_schedule[col - 1][:]
        if col % 4 == 0:
            tmp = [sbox[byte] for byte in tmp[1:] + tmp[:1]]
            tmp[0] ^= (1 << ((col // 4) - 1)) if col // 4 < 8 else 0
        for row in range(4):
            key_schedule[col][row] = key_schedule[col - 4][row] ^ tmp[row]
    
    return key_schedule

# Fungsi SubBytes dan inversenya
def sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = sbox[state[i][j]]
    return state

def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = inv_sbox[state[i][j]]
    return state

def inv_sub_bytes(state):
    for i in range(4):
        for j in range(4):
            state[i][j] = inv_sbox[state[i][j]]

    return state


# Fungsi ShiftRows dan inversenya
def shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]
    
    return state

def inv_shift_rows(state):
    state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
    state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
    state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]

    return state

# Fungsi tambahan untuk operasi AES
def mul_by_02(num):
    return ((num << 1) ^ 0x1B) & 0xFF if (num & 0x80) else (num << 1)

def mul_by_03(num):
    return mul_by_02(num) ^ num

def mul_by_09(num):
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ num

def mul_by_0b(num):
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(num) ^ num

def mul_by_0d(num):
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ num

def mul_by_0e(num):
    return mul_by_02(mul_by_02(mul_by_02(num))) ^ mul_by_02(mul_by_02(num)) ^ mul_by_02(num)

# Fungsi MixColumns dan inversenya
def mix_columns(state):
    for i in range(4):
        s0 = mul_by_02(state[0][i]) ^ mul_by_03(state[1][i]) ^ state[2][i] ^ state[3][i]
        s1 = state[0][i] ^ mul_by_02(state[1][i]) ^ mul_by_03(state[2][i]) ^ state[3][i]
        s2 = state[0][i] ^ state[1][i] ^ mul_by_02(state[2][i]) ^ mul_by_03(state[3][i])
        s3 = mul_by_03(state[0][i]) ^ state[1][i] ^ state[2][i] ^ mul_by_02(state[3][i])
        state[0][i], state[1][i], state[2][i], state[3][i] = s0, s1, s2, s3
    return state

def inv_mix_columns(state):
    for i in range(4):
        s0 = mul_by_0e(state[0][i]) ^ mul_by_0b(state[1][i]) ^ mul_by_0d(state[2][i]) ^ mul_by_09(state[3][i])
        s1 = mul_by_09(state[0][i]) ^ mul_by_0e(state[1][i]) ^ mul_by_0b(state[2][i]) ^ mul_by_0d(state[3][i])
        s2 = mul_by_0d(state[0][i]) ^ mul_by_09(state[1][i]) ^ mul_by_0e(state[2][i]) ^ mul_by_0b(state[3][i])
        s3 = mul_by_0b(state[0][i]) ^ mul_by_0d(state[1][i]) ^ mul_by_09(state[2][i]) ^ mul_by_0e(state[3][i])
        state[0][i], state[1][i], state[2][i], state[3][i] = s0, s1, s2, s3
    return state

# Fungsi dekripsi blok AES
def aes_decrypt_block(key, block):
    assert len(block) == 16
    assert len(key) == 16
    
    # Dekode key schedule dari kunci utama
    key_schedule = key_expansion(key)
    
    # Inisialisasi state dari blok
    state = [[block[row * 4 + col] for row in range(4)] for col in range(4)]
    
    # Add round key (initial round)
    state = add_round_key(state, key_schedule, 10)
    
    # 9 putaran utama
    for round in range(9, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, key_schedule, round)
        state = inv_mix_columns(state)
    
    # Putaran terakhir
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, key_schedule, 0)
    
    # Konversi state kembali ke blok
    decrypted_block = bytes(state[row][col] for col in range(4) for row in range(4))
    
    return decrypted_block
    
# Fungsi enkripsi blok AES
def aes_encrypt_block(key, block):
    assert len(block) == 16
    assert len(key) == 16
    
    # Dekode key schedule dari kunci utama
    key_schedule = key_expansion(key)
    
    # Inisialisasi state dari blok
    state = [[block[row * 4 + col] for row in range(4)] for col in range(4)]
    
    # Add round key (initial round)
    state = add_round_key(state, key_schedule, 0)
    
    # 9 putaran utama
    for round in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, key_schedule, round)
    
    # Putaran terakhir
    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, key_schedule, 10)
    
    # Konversi state kembali ke blok
    encrypted_block = bytes(state[row][col] for col in range(4) for row in range(4))
    
    return encrypted_block

# File Utility Functions
def read_file(filename):
    with open(filename, 'rb') as file:
        return file.read()

def write_file(filename, data):
    with open(filename, 'wb') as file:
        file.write(data)

# Fungsi enkripsi dan dekripsi AES untuk data penuh
def aes_encrypt(key, plaintext):
    plaintext = pad(plaintext)
    iv = os.urandom(16)
    ciphertext = iv
    previous_block = iv
    
    for i in range(0, len(plaintext), 16):
        block = plaintext[i:i+16]
        block = xor_bytes(block, previous_block)
        encrypted_block = aes_encrypt_block(key, block)
        ciphertext += encrypted_block
        previous_block = encrypted_block
    
    return ciphertext

def aes_decrypt(key, ciphertext):
    iv = ciphertext[:16]
    ciphertext = ciphertext[16:]
    plaintext = b""
    previous_block = iv
    
    for i in range(0, len(ciphertext), 16):
        block = ciphertext[i:i+16]
        decrypted_block = aes_decrypt_block(key, block)
        plaintext_block = xor_bytes(decrypted_block, previous_block)
        plaintext += plaintext_block
        previous_block = block
    
    return unpad(plaintext)

# Fungsi utama untuk enkripsi dan dekripsi file
def encrypt_file_logic(plain_data, aes_key, rsa_keyfile):
    # Memastikan kunci AES memiliki panjang yang benar
    if len(aes_key) != 16:
        raise ValueError("AES key must be 16 bytes long.")
    
    aes_encrypted_data = aes_encrypt(aes_key, plain_data)
    
    rsa_public_key_data = read_file(rsa_keyfile).decode().strip()
    print(f"RSA public key data read from file: {rsa_public_key_data}")

    # Parsing kunci publik RSA dari format teks
    rsa_public_key_lines = rsa_public_key_data.split()
    rsa_public_key = tuple(map(int, rsa_public_key_lines))
    print(f"Parsed RSA public key: {rsa_public_key}")

    aes_key_b64 = base64.b64encode(aes_key).decode('utf-8')
    aes_key_b64_padded = pad_base64(aes_key_b64)  # Menambahkan padding
    rsa_encrypted_key = rsa_encrypt(rsa_public_key, aes_key_b64_padded)
    
    print(f"AES encrypted data: {aes_encrypted_data}")
    print(f"RSA encrypted key: {rsa_encrypted_key}")

    return aes_encrypted_data, rsa_encrypted_key

def decrypt_file_logic(aes_encrypted_data, rsa_encrypted_key, rsa_keyfile_path):
    rsa_private_key_data = read_file(rsa_keyfile_path).decode().strip()
    print(f"RSA private key data read from file: {rsa_private_key_data}")

    # Parsing kunci privat RSA dari format teks
    rsa_private_key_lines = rsa_private_key_data.split()
    rsa_private_key = tuple(map(int, rsa_private_key_lines))
    print(f"Parsed RSA private key: {rsa_private_key}")

    aes_key_b64_padded = rsa_decrypt(rsa_private_key, rsa_encrypted_key)
    aes_key_b64 = unpad_base64(aes_key_b64_padded)  # Menghapus padding
    print(f"Decrypted AES key (base64): {aes_key_b64}")  # Debugging line

    try:
        # Decode base64 to get the AES key
        aes_key = base64.b64decode(aes_key_b64)
    except Exception as e:
        print(f"Base64 decoding error: {e}")
        return None

    plain_data = aes_decrypt(aes_key, aes_encrypted_data)

    print(f"Decrypted plain data: {plain_data}")

    return plain_data

# File Utility Functions
def read_file(filename):
    with open(filename, 'rb') as file:
        return file.read()

def write_file(filename, data):
    with open(filename, 'wb') as file:
        file.write(data)

# Pengujian Hybrid AES dan RSA
def test_hybrid(aes_key):
    # Generate kunci RSA
    primes_file = 'posting/primes-to-100k.txt'
    rsa_public_key, rsa_private_key = generate_rsa_keys(primes_file)
    
    # Simpan kunci publik dan privat ke file untuk pengujian
    with open('public_keys.txt', 'w') as f:
        f.write(f"{rsa_public_key[0]}\n{rsa_public_key[1]}")
    
    with open('private_keys.txt', 'w') as f:
        f.write(f"{rsa_private_key[0]}\n{rsa_private_key[1]}")
    
    # Pesan asli yang akan dienkripsi
    original_message = b'This is a secret message for AES and RSA encryption testing!'
    
    # Enkripsi hybrid
    print("Original message:", original_message)
    ciphertext, rsa_encrypted_key = encrypt_file_logic(original_message, aes_key, 'public_keys.txt')
    print("Encrypted message:", ciphertext)
    print("Encrypted AES key:", rsa_encrypted_key)
    
    # Dekripsi hybrid
    decrypted_message = decrypt_file_logic(ciphertext, rsa_encrypted_key, 'private_keys.txt')
    print("Decrypted message:", decrypted_message)
    
    # Memastikan pesan asli dan pesan yang didekripsi sesuai
    assert original_message == decrypted_message, "Decrypted message does not match the original message"
    print("Hybrid encryption and decryption were successful!")

# Menjalankan pengujian hybrid
if __name__ == "__main__":
    # Menerima kunci AES dari input pengguna
    try:
        input_key = input("Please enter a 16-byte AES key (hexadecimal): ")
        aes_key = bytes.fromhex(input_key.strip())
        test_hybrid(aes_key)
    except ValueError as e:
        print(f"Error: {e}")
