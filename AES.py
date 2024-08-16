import numpy as np

# S-Box Padrão
s_box = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

# S-Box Inversa
s_box_inversa = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0xBD, 0x49, 0x0F, 0xB0, 0x54, 0xBB, 0x16, 0x9F, 0x81, 0xF3, 0xD7,
)

def split_blocks(data, block_size=16, require_padding=True):
    blocks = [data[i:i + block_size] for i in range(0, len(data), block_size)]
    if require_padding and len(blocks[-1]) < block_size:
        blocks[-1] = blocks[-1].ljust(block_size, b'\x00')
    return blocks

def pad(data, block_size=16):
    padding_len = (block_size - len(data) % block_size) % block_size
    return data + bytes([padding_len]) * padding_len

def unpad(data, block_size=16):
    padding_len = data[-1]
    if padding_len > block_size:
        raise ValueError("Invalid padding")
    return data[:-padding_len]

def xor_bytes(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def inc_bytes(b):
    b = bytearray(b)
    for i in reversed(range(len(b))):
        if b[i] != 0xFF:
            b[i] += 1
            break
        b[i] = 0
    return bytes(b)

class AES:
    def __init__(self, key):
        self.key = key
        self.round_keys = self.key_expansion()

    def key_expansion(self):
        key = list(self.key)
        round_keys = [key[i:i + 4] for i in range(0, len(key), 4)]
        rcon = 1

        while len(round_keys) < 44:
            temp = round_keys[-1][1:] + [round_keys[-1][0]]
            temp = [s_box[b] for b in temp]
            temp[0] ^= rcon
            rcon <<= 1
            rcon &= 0xFF  # Manter rcon dentro de 1 byte
            
            # Esta linha foi corrigida para não criar um gerador
            temp = [round_keys[-4][j] ^ temp[j] for j in range(4)]
            round_keys.append(temp)

        # Combine as chaves para formar uma lista única de 176 bytes
        expanded_key = []
        for key in round_keys:
            expanded_key.extend(key)
        
        # Divida em rodadas de 16 bytes (4 palavras de 4 bytes)
        return [expanded_key[i:i + 16] for i in range(0, len(expanded_key), 16)]

    def sub_bytes(self, state):
        return [s_box[b] for b in state]

    def inv_sub_bytes(self, state):
        return [s_box_inversa[b] for b in state]

    def shift_rows(self, state):
        state = np.array(state).reshape(4, 4).T
        for i in range(4):
            state[:, i] = np.roll(state[:, i], -i)
        return state.T.flatten()

    def inv_shift_rows(self, state):
        state = np.array(state).reshape(4, 4).T
        for i in range(4):
            state[:, i] = np.roll(state[:, i], i)
        return state.T.flatten()

    def mix_columns(self, state):
        for i in range(4):
            column = state[i::4]
            state[i::4] = self.mix_single_column(column)
        return state

    def inv_mix_columns(self, state):
        for i in range(4):
            column = state[i::4]
            state[i::4] = self.inv_mix_single_column(column)
        return state

    def mix_single_column(self, column):
        def xtime(x):
            return ((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else x << 1

        def mix_single_byte(x):
            return xtime(x) ^ xtime(x) ^ xtime(x) ^ xtime(x)

        return [
            mix_single_byte(column[0]) ^ xtime(column[1]) ^ column[2] ^ column[3],
            column[0] ^ mix_single_byte(column[1]) ^ xtime(column[2]) ^ column[3],
            column[0] ^ column[1] ^ mix_single_byte(column[2]) ^ xtime(column[3]),
            xtime(column[0]) ^ column[1] ^ column[2] ^ mix_single_byte(column[3])
        ]

    def inv_mix_single_column(self, column):
        def xtime(x):
            return ((x << 1) ^ 0x1B) & 0xFF if x & 0x80 else x << 1

        def inv_mix_single_byte(x):
            return xtime(x) ^ xtime(x) ^ xtime(x) ^ xtime(x)

        return [
            inv_mix_single_byte(column[0]) ^ xtime(column[1]) ^ column[2] ^ column[3],
            column[0] ^ inv_mix_single_byte(column[1]) ^ xtime(column[2]) ^ column[3],
            column[0] ^ column[1] ^ inv_mix_single_byte(column[2]) ^ xtime(column[3]),
            xtime(column[0]) ^ column[1] ^ column[2] ^ inv_mix_single_byte(column[3])
        ]

    def add_round_key(self, state, round_key):
        return xor_bytes(state, round_key)

    def encrypt_block(self, block):
        state = list(block)
        state = self.add_round_key(state, self.round_keys[0])

        for i in range(1, 10):
            state = self.sub_bytes(state)
            state = self.shift_rows(state)
            state = self.mix_columns(state)
            state = self.add_round_key(state, self.round_keys[i])

        state = self.sub_bytes(state)
        state = self.shift_rows(state)
        state = self.add_round_key(state, self.round_keys[-1])

        return bytes(state)

    def decrypt_block(self, block):
        state = list(block)
        state = self.add_round_key(state, self.round_keys[-1])

        for i in range(9, 0, -1):
            state = self.inv_shift_rows(state)
            state = self.inv_sub_bytes(state)
            state = self.add_round_key(state, self.round_keys[i])
            state = self.inv_mix_columns(state)

        state = self.inv_shift_rows(state)
        state = self.inv_sub_bytes(state)
        state = self.add_round_key(state, self.round_keys[0])

        return bytes(state)

    def encrypt_ctr(self, plaintext, iv):
        assert len(iv) == 16

        plaintext = pad(plaintext)  # Ensure plaintext is padded
        blocks = []
        counter = iv  # Initialize counter with the IV

        for plaintext_block in split_blocks(plaintext, require_padding=False):
            # Encrypt the counter to generate the key stream
            key_stream = self.encrypt_block(counter)
            # XOR plaintext block with key stream to get the ciphertext block
            ciphertext_block = xor_bytes(plaintext_block, key_stream)
            blocks.append(ciphertext_block)
            # Increment the counter for the next block
            counter = inc_bytes(counter)

        return b''.join(blocks)

    def decrypt_ctr(self, ciphertext, iv):
        # In CTR mode, encryption and decryption are the same
        return self.encrypt_ctr(ciphertext, iv)