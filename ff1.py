import math
from typing import Tuple, List, Optional

class FF1Cipher:
    """Implementação do algoritmo FF1 (Format-Preserving Encryption) em Python puro."""
    
    # Constantes
    FEISTEL_MIN = 100
    NUM_ROUNDS = 10
    BLOCK_SIZE = 16  # 128 bits para AES
    HALF_BLOCK_SIZE = BLOCK_SIZE // 2
    
    def __init__(self, radix: int, max_tlen: int, key: bytes, tweak: bytes = b""):
        """
        Inicializa uma nova instância do cifrador FF1.
        
        Args:
            radix: Base numérica (2-65536)
            max_tlen: Comprimento máximo do tweak
            key: Chave AES (16, 24 ou 32 bytes)
            tweak: Tweak opcional
        """
        # Validar chave
        key_len = len(key)
        if key_len not in (16, 24, 32):
            raise ValueError("O comprimento da chave deve ser 128, 192 ou 256 bits")
        
        # Validar radix
        if radix < 2 or radix > 65536:  # 2^16
            raise ValueError("Radix deve estar entre 2 e 65536, inclusive")
        
        # Validar tweak
        if len(tweak) > max_tlen:
            raise ValueError("Tweak excede o comprimento máximo permitido")
        
        # Calcular comprimentos mínimo e máximo
        min_len = math.ceil(math.log(self.FEISTEL_MIN) / math.log(radix))
        max_len = 2**32 - 1  # Praticamente ilimitado
        
        if min_len < 2 or max_len < min_len:
            raise ValueError("minLen inválido, ajuste seu radix")
        
        # Armazenar parâmetros
        self.radix = radix
        self.max_tlen = max_tlen
        self.tweak = tweak
        self.min_len = min_len
        self.max_len = max_len
        
        # Chave AES
        self.key = key
        
        # Expandir chave para rodas AES
        self._expand_key()
    
    def _expand_key(self):
        """Expande a chave AES para as rodas necessárias."""
        key_len = len(self.key)
        
        if key_len == 16:
            self.nr = 10  # 10 rodas para AES-128
        elif key_len == 24:
            self.nr = 12  # 12 rodas para AES-192
        else:  # 32 bytes
            self.nr = 14  # 14 rodas para AES-256
        
        # S-box AES
        self.sbox = [
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
        
        # S-box inversa
        self.inv_sbox = [
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
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc9, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
        ]
        
        # Tabela Rcon
        self.rcon = [
            0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
            0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91
        ]
        
        # Expandir chave
        self._key_expansion()
    
    def _key_expansion(self):
        """Expande a chave AES para todas as rodas."""
        nk = len(self.key) // 4
        self.nk = nk
        self.w = [0] * (4 * (self.nr + 1))
        
        # Converter bytes para palavras de 32 bits
        for i in range(nk):
            self.w[i] = (self.key[4*i] << 24) | (self.key[4*i+1] << 16) | (self.key[4*i+2] << 8) | self.key[4*i+3]
        
        # Expandir
        for i in range(nk, 4 * (self.nr + 1)):
            temp = self.w[i-1]
            if i % nk == 0:
                temp = self._sub_word(self._rot_word(temp)) ^ (self.rcon[i//nk - 1] << 24)
            elif nk > 6 and i % nk == 4:
                temp = self._sub_word(temp)
            self.w[i] = self.w[i-nk] ^ temp
    
    def _sub_word(self, word: int) -> int:
        """Aplica S-box a cada byte de uma palavra."""
        return ((self.sbox[(word >> 24) & 0xFF] << 24) |
                (self.sbox[(word >> 16) & 0xFF] << 16) |
                (self.sbox[(word >> 8) & 0xFF] << 8) |
                self.sbox[word & 0xFF])
    
    def _rot_word(self, word: int) -> int:
        """Rotaciona uma palavra 8 bits para a esquerda."""
        return ((word << 8) & 0xFFFFFFFF) | (word >> 24)
    
    def _add_round_key(self, state: List[List[int]], round: int):
        """Adiciona chave da roda ao estado."""
        for i in range(4):
            for j in range(4):
                state[i][j] ^= (self.w[round*4 + j] >> (24 - 8*i)) & 0xFF
    
    def _sub_bytes(self, state: List[List[int]]):
        """Aplica S-box a cada byte do estado."""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.sbox[state[i][j]]
    
    def _inv_sub_bytes(self, state: List[List[int]]):
        """Aplica S-box inversa a cada byte do estado."""
        for i in range(4):
            for j in range(4):
                state[i][j] = self.inv_sbox[state[i][j]]
    
    def _shift_rows(self, state: List[List[int]]):
        """Desloca as linhas do estado."""
        # Linha 0: não desloca
        # Linha 1: desloca 1
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][1], state[1][2], state[1][3], state[1][0]
        # Linha 2: desloca 2
        state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
        # Linha 3: desloca 3
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][3], state[3][0], state[3][1], state[3][2]
    
    def _inv_shift_rows(self, state: List[List[int]]):
        """Desloca as linhas do estado inversamente."""
        # Linha 0: não desloca
        # Linha 1: desloca 1 para direita
        state[1][0], state[1][1], state[1][2], state[1][3] = state[1][3], state[1][0], state[1][1], state[1][2]
        # Linha 2: desloca 2
        state[2][0], state[2][1], state[2][2], state[2][3] = state[2][2], state[2][3], state[2][0], state[2][1]
        # Linha 3: desloca 3 para direita
        state[3][0], state[3][1], state[3][2], state[3][3] = state[3][1], state[3][2], state[3][3], state[3][0]
    
    def _mix_columns(self, state: List[List[int]]):
        """Mistura as colunas do estado."""
        for i in range(4):
            s0 = state[0][i]
            s1 = state[1][i]
            s2 = state[2][i]
            s3 = state[3][i]
            
            state[0][i] = self._gmul(0x02, s0) ^ self._gmul(0x03, s1) ^ s2 ^ s3
            state[1][i] = s0 ^ self._gmul(0x02, s1) ^ self._gmul(0x03, s2) ^ s3
            state[2][i] = s0 ^ s1 ^ self._gmul(0x02, s2) ^ self._gmul(0x03, s3)
            state[3][i] = self._gmul(0x03, s0) ^ s1 ^ s2 ^ self._gmul(0x02, s3)
    
    def _inv_mix_columns(self, state: List[List[int]]):
        """Mistura as colunas do estado inversamente."""
        for i in range(4):
            s0 = state[0][i]
            s1 = state[1][i]
            s2 = state[2][i]
            s3 = state[3][i]
            
            state[0][i] = self._gmul(0x0e, s0) ^ self._gmul(0x0b, s1) ^ self._gmul(0x0d, s2) ^ self._gmul(0x09, s3)
            state[1][i] = self._gmul(0x09, s0) ^ self._gmul(0x0e, s1) ^ self._gmul(0x0b, s2) ^ self._gmul(0x0d, s3)
            state[2][i] = self._gmul(0x0d, s0) ^ self._gmul(0x09, s1) ^ self._gmul(0x0e, s2) ^ self._gmul(0x0b, s3)
            state[3][i] = self._gmul(0x0b, s0) ^ self._gmul(0x0d, s1) ^ self._gmul(0x09, s2) ^ self._gmul(0x0e, s3)
    
    def _gmul(self, a: int, b: int) -> int:
        """Multiplicação em Galois Field (2^8)."""
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1b  # Polinômio irredutível x^8 + x^4 + x^3 + x + 1
            b >>= 1
        return p & 0xFF
    
    def _aes_encrypt_block(self, block: bytes) -> bytes:
        """Criptografa um bloco de 16 bytes usando AES."""
        # Inicializar estado
        state = [[0] * 4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                state[i][j] = block[i + 4*j]
        
        # Roda inicial
        self._add_round_key(state, 0)
        
        # Rodas principais
        for r in range(1, self.nr):
            self._sub_bytes(state)
            self._shift_rows(state)
            self._mix_columns(state)
            self._add_round_key(state, r)
        
        # Roda final
        self._sub_bytes(state)
        self._shift_rows(state)
        self._add_round_key(state, self.nr)
        
        # Converter estado para bytes
        output = bytearray(16)
        for i in range(4):
            for j in range(4):
                output[i + 4*j] = state[i][j]
        
        return bytes(output)
    
    def _aes_cbc_encrypt(self, data: bytes, iv: bytes = bytes(16)) -> bytes:
        """Criptografa dados usando AES-CBC."""
        if len(data) % 16 != 0:
            raise ValueError("Dados devem ser múltiplos de 16 bytes")
        
        blocks = [data[i:i+16] for i in range(0, len(data), 16)]
        encrypted_blocks = []
        prev_block = iv
        
        for block in blocks:
            # XOR com bloco anterior
            xored = bytes(a ^ b for a, b in zip(block, prev_block))
            # Criptografar
            encrypted = self._aes_encrypt_block(xored)
            encrypted_blocks.append(encrypted)
            prev_block = encrypted
        
        return b''.join(encrypted_blocks)
    
    def _ciph(self, input_data: bytes) -> bytes:
        """Função ciph do algoritmo FF1."""
        if len(input_data) % self.BLOCK_SIZE != 0:
            raise ValueError(f"Comprimento da entrada deve ser múltiplo de {self.BLOCK_SIZE}")
        
        # Para CBC, IV sempre é zero
        iv_zero = bytes(self.BLOCK_SIZE)
        
        # Se for um único bloco, age como ECB
        if len(input_data) == self.BLOCK_SIZE:
            return self._aes_encrypt_block(input_data)
        
        # Para múltiplos blocos, age como CBC
        return self._aes_cbc_encrypt(input_data, iv_zero)
    
    def _prf(self, input_data: bytes) -> bytes:
        """Função PRF do algoritmo FF1 (AES-CBC-MAC)."""
        encrypted = self._ciph(input_data)
        # Retornar apenas o último bloco (CBC-MAC)
        return encrypted[-self.BLOCK_SIZE:]
    
    def _str_to_int(self, s: str, radix: int) -> int:
        """Converte string para inteiro na base especificada."""
        result = 0
        for char in s:
            result = result * radix + int(char, radix)
        return result
    
    def _int_to_str(self, n: int, radix: int, length: int) -> str:
        """Converte inteiro para string na base especificada com padding."""
        if n == 0:
            return '0' * length
        
        digits = []
        while n > 0:
            digits.append(self._int_to_digit(n % radix))
            n //= radix
        
        result = ''.join(reversed(digits))
        # Padding com zeros à esquerda
        return result.zfill(length)
    
    def _int_to_digit(self, n: int) -> str:
        """Converte inteiro para dígito (suporta até base 36)."""
        if n < 10:
            return str(n)
        return chr(ord('a') + n - 10)
    
    def _digit_to_int(self, c: str) -> int:
        """Converte dígito para inteiro (suporta até base 36)."""
        if c.isdigit():
            return int(c)
        return ord(c.lower()) - ord('a') + 10
    
    def encrypt(self, plaintext: str, tweak: Optional[bytes] = None) -> str:
        """
        Criptografa um texto usando FF1.
        
        Args:
            plaintext: Texto a ser criptografado
            tweak: Tweak opcional (usa self.tweak se None)
        
        Returns:
            Texto criptografado
        """
        if tweak is None:
            tweak = self.tweak
        
        n = len(plaintext)
        t = len(tweak)
        
        # Validar comprimento
        if n < self.min_len or n > self.max_len:
            raise ValueError(f"Comprimento deve estar entre {self.min_len} e {self.max_len}")
        
        if len(tweak) > self.max_tlen:
            raise ValueError("Tweak excede o comprimento máximo")
        
        # Validar que o texto está na base especificada
        for char in plaintext:
            try:
                val = self._digit_to_int(char)
                if val >= self.radix:
                    raise ValueError(f"Caractere '{char}' não está na base {self.radix}")
            except:
                raise ValueError(f"Caractere '{char}' não está na base {self.radix}")
        
        # Calcular pontos de divisão
        u = n // 2
        v = n - u
        
        # Dividir texto
        A = plaintext[:u]
        B = plaintext[u:]
        
        # Calcular parâmetros
        b = math.ceil(math.ceil(v * math.log2(self.radix)) / 8)
        d = 4 * math.ceil(b / 4) + 4
        
        max_j = math.ceil(d / 16)
        
        num_pad = (-t - b - 1) % 16
        if num_pad < 0:
            num_pad += 16
        
        # Construir P (sempre 16 bytes)
        P = bytearray(16)
        P[0] = 0x01
        P[1] = 0x02
        P[2] = 0x01
        P[3] = 0x00  # Padding para radix
        
        # Radix em 2 bytes (big-endian)
        P[4] = (self.radix >> 8) & 0xFF
        P[5] = self.radix & 0xFF
        
        P[6] = 0x0a
        P[7] = u  # u mod 256
        
        # n em 4 bytes (big-endian)
        for i in range(4):
            P[11 - i] = (n >> (8 * i)) & 0xFF
        
        # t em 4 bytes (big-endian)
        for i in range(4):
            P[15 - i] = (t >> (8 * i)) & 0xFF
        
        # Comprimentos
        len_q = t + b + 1 + num_pad
        len_pq = 16 + len_q
        
        # Buffer para dados temporários
        buf = bytearray(len_q + len_pq + (max_j - 1) * 16)
        
        # Converter A e B para inteiros
        num_a = self._str_to_int(A, self.radix)
        num_b = self._str_to_int(B, self.radix)
        
        # Pre-calcular modulos
        mod_u = self.radix ** u
        mod_v = self.radix ** v
        
        # Rodadas Feistel
        for i in range(self.NUM_ROUNDS):
            # Construir Q
            Q = buf[:len_q]
            Q[:t] = tweak
            Q[t + num_pad] = i
            
            # Converter B para bytes
            b_bytes = num_b.to_bytes(b, 'big')
            
            # Preencher Q com zeros e depois com bytes de B
            for j in range(t + num_pad + 1, len_q):
                Q[j] = 0
            
            # Copiar bytes de B para o final de Q
            start_pos = len_q - len(b_bytes)
            Q[start_pos:start_pos + len(b_bytes)] = b_bytes
            
            # Construir PQ = P || Q
            PQ = buf[len_q:len_q + len_pq]
            PQ[:16] = P
            PQ[16:] = Q
            
            # Calcular R = PRF(PQ)
            R = self._prf(PQ)
            
            # Calcular Y
            Y_buf = buf[len_q + len_pq - 16:]
            
            # Copiar R para início de Y
            Y_buf[:16] = R
            
            # Para j > 1
            for j in range(1, max_j):
                offset = (j - 1) * 16
                
                # XOR R com j
                j_bytes = j.to_bytes(8, 'big')
                for k in range(8):
                    Y_buf[offset + 16 + k] = R[k] ^ j_bytes[k]
                for k in range(8, 16):
                    Y_buf[offset + 16 + k] = R[k] ^ 0
                
                # Criptografar bloco
                block = Y_buf[offset + 16:offset + 32]
                encrypted_block = self._ciph(block)
                Y_buf[offset + 16:offset + 32] = encrypted_block
            
            # Converter Y para inteiro
            Y_bytes = bytes(Y_buf[:d])
            num_y = int.from_bytes(Y_bytes, 'big')
            
            # Calcular C
            num_c = num_a + num_y
            
            # Aplicar módulo
            if i % 2 == 0:
                num_c %= mod_u
            else:
                num_c %= mod_v
            
            # Atualizar A e B
            num_a, num_b = num_b, num_c
        
        # Converter resultados para strings
        A_enc = self._int_to_str(num_a, self.radix, u)
        B_enc = self._int_to_str(num_b, self.radix, v)
        
        return A_enc + B_enc
    
    def decrypt(self, ciphertext: str, tweak: Optional[bytes] = None) -> str:
        """
        Descriptografa um texto usando FF1.
        
        Args:
            ciphertext: Texto a ser descriptografado
            tweak: Tweak opcional (usa self.tweak se None)
        
        Returns:
            Texto descriptografado
        """
        if tweak is None:
            tweak = self.tweak
        
        n = len(ciphertext)
        t = len(tweak)
        
        # Validações (iguais à encriptação)
        if n < self.min_len or n > self.max_len:
            raise ValueError(f"Comprimento deve estar entre {self.min_len} e {self.max_len}")
        
        if len(tweak) > self.max_tlen:
            raise ValueError("Tweak excede o comprimento máximo")
        
        for char in ciphertext:
            try:
                val = self._digit_to_int(char)
                if val >= self.radix:
                    raise ValueError(f"Caractere '{char}' não está na base {self.radix}")
            except:
                raise ValueError(f"Caractere '{char}' não está na base {self.radix}")
        
        # Calcular pontos de divisão
        u = n // 2
        v = n - u
        
        # Dividir texto
        A = ciphertext[:u]
        B = ciphertext[u:]
        
        # Calcular parâmetros (iguais à encriptação)
        b = math.ceil(math.ceil(v * math.log2(self.radix)) / 8)
        d = 4 * math.ceil(b / 4) + 4
        
        max_j = math.ceil(d / 16)
        
        num_pad = (-t - b - 1) % 16
        if num_pad < 0:
            num_pad += 16
        
        # Construir P (igual à encriptação)
        P = bytearray(16)
        P[0] = 0x01
        P[1] = 0x02
        P[2] = 0x01
        P[3] = 0x00
        
        P[4] = (self.radix >> 8) & 0xFF
        P[5] = self.radix & 0xFF
        
        P[6] = 0x0a
        P[7] = u
        
        for i in range(4):
            P[11 - i] = (n >> (8 * i)) & 0xFF
        
        for i in range(4):
            P[15 - i] = (t >> (8 * i)) & 0xFF
        
        # Comprimentos
        len_q = t + b + 1 + num_pad
        len_pq = 16 + len_q
        
        # Buffer
        buf = bytearray(len_q + len_pq + (max_j - 1) * 16)
        
        # Converter A e B para inteiros
        num_a = self._str_to_int(A, self.radix)
        num_b = self._str_to_int(B, self.radix)
        
        # Pre-calcular modulos
        mod_u = self.radix ** u
        mod_v = self.radix ** v
        
        # Rodadas Feistel em ordem inversa
        for i in range(self.NUM_ROUNDS - 1, -1, -1):
            # Construir Q (com A em vez de B)
            Q = buf[:len_q]
            Q[:t] = tweak
            Q[t + num_pad] = i
            
            # Converter A para bytes
            a_bytes = num_a.to_bytes(b, 'big')
            
            # Preencher Q
            for j in range(t + num_pad + 1, len_q):
                Q[j] = 0
            
            # Copiar bytes de A
            start_pos = len_q - len(a_bytes)
            Q[start_pos:start_pos + len(a_bytes)] = a_bytes
            
            # Construir PQ
            PQ = buf[len_q:len_q + len_pq]
            PQ[:16] = P
            PQ[16:] = Q
            
            # Calcular R
            R = self._prf(PQ)
            
            # Calcular Y (igual à encriptação)
            Y_buf = buf[len_q + len_pq - 16:]
            Y_buf[:16] = R
            
            for j in range(1, max_j):
                offset = (j - 1) * 16
                
                j_bytes = j.to_bytes(8, 'big')
                for k in range(8):
                    Y_buf[offset + 16 + k] = R[k] ^ j_bytes[k]
                for k in range(8, 16):
                    Y_buf[offset + 16 + k] = R[k] ^ 0
                
                block = Y_buf[offset + 16:offset + 32]
                encrypted_block = self._ciph(block)
                Y_buf[offset + 16:offset + 32] = encrypted_block
            
            # Converter Y para inteiro
            Y_bytes = bytes(Y_buf[:d])
            num_y = int.from_bytes(Y_bytes, 'big')
            
            # Calcular C (subtração em vez de adição)
            num_c = num_b - num_y
            
            # Aplicar módulo
            if i % 2 == 0:
                num_c %= mod_u
            else:
                num_c %= mod_v
            
            # Atualizar A e B
            num_b, num_a = num_a, num_c
        
        # Converter resultados
        A_dec = self._int_to_str(num_a, self.radix, u)
        B_dec = self._int_to_str(num_b, self.radix, v)
        
        return A_dec + B_dec


# Exemplo de uso
if __name__ == "__main__":
    # Configuração
    radix = 16  # Base decimal (0-9)
    max_tlen = 16
    key = b"0123456789abcdef"  # 16 bytes para AES-128
    tweak = b"1234"
    
    # Criar cifrador
    cipher = FF1Cipher(radix, max_tlen, key, tweak)
    
    # Texto para criptografar
    plaintext = "0123456789abcdef"
    
    # Criptografar
    encrypted = cipher.encrypt(plaintext)
    print(f"Texto original: {plaintext}")
    print(f"Criptografado:  {encrypted}")
    
    # Descriptografar
    decrypted = cipher.decrypt(encrypted)
    print(f"Descriptografado: {decrypted}")
    
    # Verificar
    print(f"Sucesso: {plaintext == decrypted}")
    
