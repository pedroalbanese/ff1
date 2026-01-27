package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/big"
	"strings"
)

// Constantes
const (
	feistelMin    = 100
	numRounds     = 10
	blockSize     = 16 // 128 bits para AES
	halfBlockSize = blockSize / 2
)

// Cipher representa uma instância do algoritmo FF1
type Cipher struct {
	tweak        []byte
	radix        int
	minLen       uint32
	maxLen       uint32
	maxTLen      int
	cbcEncryptor cipher.BlockMode
	aesBlock     cipher.Block
}

// NewCipher cria uma nova instância do cifrador FF1
func NewCipher(radix int, maxTLen int, key []byte, tweak []byte) (*Cipher, error) {
	var c Cipher

	// Validar chave
	keyLen := len(key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, errors.New("comprimento da chave deve ser 128, 192 ou 256 bits")
	}

	// Validar radix
	if radix < 2 || radix > 65536 {
		return nil, errors.New("radix deve estar entre 2 e 65536, inclusive")
	}

	// Validar tweak
	if len(tweak) > maxTLen {
		return nil, errors.New("tweak excede o comprimento máximo permitido")
	}

	// Calcular minLen
	minLen := uint32(math.Ceil(math.Log(feistelMin) / math.Log(float64(radix))))
	maxLen := uint32(math.MaxUint32)

	// Validar limites
	if minLen < 2 || maxLen < minLen {
		return nil, errors.New("minLen inválido, ajuste seu radix")
	}

	// Criar cifrador AES
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("falha ao criar bloco AES")
	}

	// Criar cifrador CBC com IV zero
	ivZero := make([]byte, blockSize)
	cbcEncryptor := cipher.NewCBCEncrypter(aesBlock, ivZero)

	// Inicializar estrutura
	c.tweak = tweak
	c.radix = radix
	c.minLen = minLen
	c.maxLen = maxLen
	c.maxTLen = maxTLen
	c.cbcEncryptor = cbcEncryptor
	c.aesBlock = aesBlock

	return &c, nil
}

// Encrypt criptografa uma string usando FF1
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	return c.EncryptWithTweak(plaintext, c.tweak)
}

// EncryptWithTweak criptografa com um tweak específico
func (c *Cipher) EncryptWithTweak(plaintext string, tweak []byte) (string, error) {
	n := uint32(len(plaintext))
	t := len(tweak)

	// Validar comprimento
	if n < c.minLen || n > c.maxLen {
		return "", errors.New("comprimento da mensagem fora dos limites")
	}

	if len(tweak) > c.maxTLen {
		return "", errors.New("tweak excede o comprimento máximo")
	}

	// Verificar se a string está no radix
	if !c.isValidString(plaintext) {
		return "", errors.New("string contém caracteres fora do radix")
	}

	// Calcular ponto de divisão
	u := n / 2
	v := n - u

	// Dividir texto
	A := plaintext[:u]
	B := plaintext[u:]

	// Calcular parâmetros
	b := int(math.Ceil(math.Ceil(float64(v)*math.Log2(float64(c.radix))) / 8))
	d := int(4*math.Ceil(float64(b)/4) + 4)

	maxJ := int(math.Ceil(float64(d) / 16))

	numPad := (-t - b - 1) % 16
	if numPad < 0 {
		numPad += 16
	}

	// Construir P (16 bytes)
	P := make([]byte, blockSize)
	P[0] = 0x01
	P[1] = 0x02
	P[2] = 0x01
	P[3] = 0x00 // Padding para radix

	// Radix em 2 bytes (big-endian)
	binary.BigEndian.PutUint16(P[4:6], uint16(c.radix))

	P[6] = 0x0a
	P[7] = byte(u) // u mod 256

	// n em 4 bytes
	binary.BigEndian.PutUint32(P[8:12], n)

	// t em 4 bytes
	binary.BigEndian.PutUint32(P[12:16], uint32(t))

	// Comprimentos
	lenQ := t + b + 1 + numPad
	lenPQ := blockSize + lenQ

	// Buffer para dados temporários
	buf := make([]byte, lenQ+lenPQ+(maxJ-1)*blockSize)

	// Converter strings para números big.Int
	numA, okA := new(big.Int).SetString(A, c.radix)
	numB, okB := new(big.Int).SetString(B, c.radix)

	if !okA || !okB {
		return "", errors.New("erro ao converter string para número")
	}

	// Pré-calcular módulos
	radixBig := big.NewInt(int64(c.radix))
	modU := new(big.Int).Exp(radixBig, big.NewInt(int64(u)), nil)
	modV := new(big.Int).Exp(radixBig, big.NewInt(int64(v)), nil)

	// Rodadas Feistel
	for i := 0; i < numRounds; i++ {
		// Construir Q
		Q := buf[:lenQ]
		copy(Q[:t], tweak)
		Q[t+numPad] = byte(i)

		// Converter B para bytes
		bBytes := numB.Bytes()

		// Zerar o restante de Q
		for j := t + numPad + 1; j < lenQ; j++ {
			Q[j] = 0x00
		}

		// Copiar bytes de B para o final de Q
		startPos := lenQ - len(bBytes)
		copy(Q[startPos:], bBytes)

		// Construir PQ = P || Q
		PQ := buf[lenQ : lenQ+lenPQ]
		copy(PQ[:blockSize], P)
		copy(PQ[blockSize:], Q)

		// Calcular R = PRF(PQ)
		R, err := c.prf(PQ)
		if err != nil {
			return "", err
		}

		// Y buffer
		Y := buf[lenQ+lenPQ-blockSize:]

		// Copiar R para início de Y
		copy(Y[:blockSize], R)

		// Para j > 1
		for j := 1; j < maxJ; j++ {
			offset := (j - 1) * blockSize

			// XOR R com j
			for k := 0; k < halfBlockSize; k++ {
				Y[offset+blockSize+k] = R[k] ^ 0x00
			}

			// J em 8 bytes (big-endian)
			jBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(jBytes, uint64(j))
			for k := 0; k < 8; k++ {
				Y[offset+blockSize+halfBlockSize+k] = R[halfBlockSize+k] ^ jBytes[k]
			}

			// Criptografar bloco
			block := Y[offset+blockSize : offset+2*blockSize]
			_, err := c.ciph(block)
			if err != nil {
				return "", err
			}
		}

		// Converter Y para big.Int
		YBytes := Y[:d]
		numY := new(big.Int).SetBytes(YBytes)

		// Calcular C = A + Y mod (radix^u ou radix^v)
		numC := new(big.Int).Add(numA, numY)

		if i%2 == 0 {
			numC.Mod(numC, modU)
		} else {
			numC.Mod(numC, modV)
		}

		// Atualizar A e B
		numA.Set(numB)
		numB.Set(numC)
	}

	// Converter números de volta para strings
	Aenc := numA.Text(c.radix)
	Benc := numB.Text(c.radix)

	// Adicionar padding
	Aenc = strings.Repeat("0", int(u)-len(Aenc)) + Aenc
	Benc = strings.Repeat("0", int(v)-len(Benc)) + Benc

	return Aenc + Benc, nil
}

// Decrypt descriptografa uma string usando FF1
func (c *Cipher) Decrypt(ciphertext string) (string, error) {
	return c.DecryptWithTweak(ciphertext, c.tweak)
}

// DecryptWithTweak descriptografa com um tweak específico
func (c *Cipher) DecryptWithTweak(ciphertext string, tweak []byte) (string, error) {
	n := uint32(len(ciphertext))
	t := len(tweak)

	// Validar comprimento
	if n < c.minLen || n > c.maxLen {
		return "", errors.New("comprimento da mensagem fora dos limites")
	}

	if len(tweak) > c.maxTLen {
		return "", errors.New("tweak excede o comprimento máximo")
	}

	// Verificar se a string está no radix
	if !c.isValidString(ciphertext) {
		return "", errors.New("string contém caracteres fora do radix")
	}

	// Calcular ponto de divisão
	u := n / 2
	v := n - u

	// Dividir texto
	A := ciphertext[:u]
	B := ciphertext[u:]

	// Calcular parâmetros
	b := int(math.Ceil(math.Ceil(float64(v)*math.Log2(float64(c.radix))) / 8))
	d := int(4*math.Ceil(float64(b)/4) + 4)

	maxJ := int(math.Ceil(float64(d) / 16))

	numPad := (-t - b - 1) % 16
	if numPad < 0 {
		numPad += 16
	}

	// Construir P (16 bytes)
	P := make([]byte, blockSize)
	P[0] = 0x01
	P[1] = 0x02
	P[2] = 0x01
	P[3] = 0x00 // Padding para radix

	// Radix em 2 bytes (big-endian)
	binary.BigEndian.PutUint16(P[4:6], uint16(c.radix))

	P[6] = 0x0a
	P[7] = byte(u) // u mod 256

	// n em 4 bytes
	binary.BigEndian.PutUint32(P[8:12], n)

	// t em 4 bytes
	binary.BigEndian.PutUint32(P[12:16], uint32(t))

	// Comprimentos
	lenQ := t + b + 1 + numPad
	lenPQ := blockSize + lenQ

	// Buffer para dados temporários
	buf := make([]byte, lenQ+lenPQ+(maxJ-1)*blockSize)

	// Converter strings para números big.Int
	numA, okA := new(big.Int).SetString(A, c.radix)
	numB, okB := new(big.Int).SetString(B, c.radix)

	if !okA || !okB {
		return "", errors.New("erro ao converter string para número")
	}

	// Pré-calcular módulos
	radixBig := big.NewInt(int64(c.radix))
	modU := new(big.Int).Exp(radixBig, big.NewInt(int64(u)), nil)
	modV := new(big.Int).Exp(radixBig, big.NewInt(int64(v)), nil)

	// Rodadas Feistel em ordem inversa
	for i := numRounds - 1; i >= 0; i-- {
		// Construir Q
		Q := buf[:lenQ]
		copy(Q[:t], tweak)
		Q[t+numPad] = byte(i)

		// Converter A para bytes
		aBytes := numA.Bytes()

		// Zerar o restante de Q
		for j := t + numPad + 1; j < lenQ; j++ {
			Q[j] = 0x00
		}

		// Copiar bytes de A para o final de Q
		startPos := lenQ - len(aBytes)
		copy(Q[startPos:], aBytes)

		// Construir PQ = P || Q
		PQ := buf[lenQ : lenQ+lenPQ]
		copy(PQ[:blockSize], P)
		copy(PQ[blockSize:], Q)

		// Calcular R = PRF(PQ)
		R, err := c.prf(PQ)
		if err != nil {
			return "", err
		}

		// Y buffer
		Y := buf[lenQ+lenPQ-blockSize:]

		// Copiar R para início de Y
		copy(Y[:blockSize], R)

		// Para j > 1
		for j := 1; j < maxJ; j++ {
			offset := (j - 1) * blockSize

			// XOR R com j
			for k := 0; k < halfBlockSize; k++ {
				Y[offset+blockSize+k] = R[k] ^ 0x00
			}

			// J em 8 bytes (big-endian)
			jBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(jBytes, uint64(j))
			for k := 0; k < 8; k++ {
				Y[offset+blockSize+halfBlockSize+k] = R[halfBlockSize+k] ^ jBytes[k]
			}

			// Criptografar bloco
			block := Y[offset+blockSize : offset+2*blockSize]
			_, err := c.ciph(block)
			if err != nil {
				return "", err
			}
		}

		// Converter Y para big.Int
		YBytes := Y[:d]
		numY := new(big.Int).SetBytes(YBytes)

		// Calcular C = B - Y mod (radix^u ou radix^v)
		numC := new(big.Int).Sub(numB, numY)

		if i%2 == 0 {
			numC.Mod(numC, modU)
		} else {
			numC.Mod(numC, modV)
		}

		// Atualizar A e B
		numB.Set(numA)
		numA.Set(numC)
	}

	// Converter números de volta para strings
	Adec := numA.Text(c.radix)
	Bdec := numB.Text(c.radix)

	// Adicionar padding
	Adec = strings.Repeat("0", int(u)-len(Adec)) + Adec
	Bdec = strings.Repeat("0", int(v)-len(Bdec)) + Bdec

	return Adec + Bdec, nil
}

// ciph implementa a função de cifragem do FF1
func (c *Cipher) ciph(input []byte) ([]byte, error) {
	if len(input)%blockSize != 0 {
		return nil, errors.New("comprimento da entrada deve ser múltiplo de 16")
	}

	// Usar CBC mode
	output := make([]byte, len(input))
	c.cbcEncryptor.CryptBlocks(output, input)

	// Resetar IV para zero
	if _, ok := c.cbcEncryptor.(cipher.BlockMode); ok {
		// O CBC encryptor do Go não tem método SetIV exposto
		// Recriamos o encryptor com IV zero
		ivZero := make([]byte, blockSize)
		c.cbcEncryptor = cipher.NewCBCEncrypter(c.aesBlock, ivZero)
	}

	return output, nil
}

// prf implementa a função PRF do FF1 (AES-CBC-MAC)
func (c *Cipher) prf(input []byte) ([]byte, error) {
	ciphertext, err := c.ciph(input)
	if err != nil {
		return nil, err
	}

	// Retornar apenas o último bloco (CBC-MAC)
	return ciphertext[len(ciphertext)-blockSize:], nil
}

// isValidString verifica se todos os caracteres estão no radix especificado
func (c *Cipher) isValidString(s string) bool {
	for _, ch := range s {
		val := c.charToValue(byte(ch))
		if val < 0 || val >= c.radix {
			return false
		}
	}
	return true
}

// charToValue converte um caractere para seu valor numérico
func (c *Cipher) charToValue(ch byte) int {
	if '0' <= ch && ch <= '9' {
		return int(ch - '0')
	}
	if 'a' <= ch && ch <= 'z' {
		return int(ch-'a') + 10
	}
	if 'A' <= ch && ch <= 'Z' {
		return int(ch-'A') + 10
	}
	return -1
}

// AES implementação manual (opcional, se não quiser usar crypto/aes)
// Esta é uma implementação básica para referência
type AES struct {
	Nr  int
	Nk  int
	key []byte
	w   []uint32
}

// NewAES cria um novo cifrador AES
func NewAES(key []byte) (*AES, error) {
	aes := &AES{}
	aes.key = key
	aes.Nk = len(key) / 4

	switch len(key) {
	case 16:
		aes.Nr = 10
	case 24:
		aes.Nr = 12
	case 32:
		aes.Nr = 14
	default:
		return nil, errors.New("comprimento da chave inválido")
	}

	aes.keyExpansion()
	return aes, nil
}

// keyExpansion expande a chave para as rodas
func (a *AES) keyExpansion() {
	// Tabela S-box
	sbox := [256]byte{
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
		0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
	}

	rcon := [11]uint32{
		0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
		0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1B000000,
		0x36000000,
	}

	a.w = make([]uint32, 4*(a.Nr+1))

	// Copiar chave inicial
	for i := 0; i < a.Nk; i++ {
		a.w[i] = uint32(a.key[4*i])<<24 | uint32(a.key[4*i+1])<<16 |
			uint32(a.key[4*i+2])<<8 | uint32(a.key[4*i+3])
	}

	// Expandir chave
	for i := a.Nk; i < 4*(a.Nr+1); i++ {
		temp := a.w[i-1]
		if i%a.Nk == 0 {
			// RotWord + SubWord + Rcon
			temp = (temp << 8) | (temp >> 24)
			temp = uint32(sbox[temp>>24])<<24 | uint32(sbox[(temp>>16)&0xFF])<<16 |
				uint32(sbox[(temp>>8)&0xFF])<<8 | uint32(sbox[temp&0xFF])
			temp ^= rcon[i/a.Nk]
		} else if a.Nk > 6 && i%a.Nk == 4 {
			// Apenas SubWord
			temp = uint32(sbox[temp>>24])<<24 | uint32(sbox[(temp>>16)&0xFF])<<16 |
				uint32(sbox[(temp>>8)&0xFF])<<8 | uint32(sbox[temp&0xFF])
		}
		a.w[i] = a.w[i-a.Nk] ^ temp
	}
}

// encryptBlock criptografa um único bloco
func (a *AES) encryptBlock(dst, src []byte) {
	// Implementação básica - na prática use crypto/aes
	// Esta é uma versão simplificada
	state := make([]uint32, 4)

	// Converter bytes para estado
	for i := 0; i < 4; i++ {
		state[i] = uint32(src[4*i])<<24 | uint32(src[4*i+1])<<16 |
			uint32(src[4*i+2])<<8 | uint32(src[4*i+3])
	}

	// Aplicar rodas
	// (Implementação completa seria longa)

	// Converter estado para bytes
	for i := 0; i < 4; i++ {
		dst[4*i] = byte(state[i] >> 24)
		dst[4*i+1] = byte(state[i] >> 16)
		dst[4*i+2] = byte(state[i] >> 8)
		dst[4*i+3] = byte(state[i])
	}
}

// Teste principal
func main() {
	// Exemplo 1: Base 10 (decimal)
	fmt.Println("=== Exemplo 1: Base 10 ===")
	key1 := []byte("0123456789ABCDEF") // 16 bytes
	tweak1 := []byte("")
	plaintext1 := "123456789012"

	cipher1, err := NewCipher(10, len(plaintext1), key1, tweak1)
	if err != nil {
		fmt.Printf("Erro ao criar cipher: %v\n", err)
		return
	}

	encrypted1, err := cipher1.Encrypt(plaintext1)
	if err != nil {
		fmt.Printf("Erro ao criptografar: %v\n", err)
		return
	}

	decrypted1, err := cipher1.Decrypt(encrypted1)
	if err != nil {
		fmt.Printf("Erro ao descriptografar: %v\n", err)
		return
	}

	fmt.Printf("Texto original: %s\n", plaintext1)
	fmt.Printf("Criptografado:  %s\n", encrypted1)
	fmt.Printf("Descriptografado: %s\n", decrypted1)
	fmt.Printf("Sucesso: %v\n\n", plaintext1 == decrypted1)

	// Exemplo 2: Base 16 (hexadecimal) - igual ao exemplo Go original
	fmt.Println("=== Exemplo 2: Base 16 ===")
	key2 := []byte("0123456789abcdef") // 16 bytes
	tweak2 := []byte("1234")
	plaintext2 := "0123456789abcdef"

	cipher2, err := NewCipher(16, len(plaintext2), key2, tweak2)
	if err != nil {
		fmt.Printf("Erro ao criar cipher: %v\n", err)
		return
	}

	encrypted2, err := cipher2.Encrypt(plaintext2)
	if err != nil {
		fmt.Printf("Erro ao criptografar: %v\n", err)
		return
	}

	decrypted2, err := cipher2.Decrypt(encrypted2)
	if err != nil {
		fmt.Printf("Erro ao descriptografar: %v\n", err)
		return
	}

	fmt.Printf("Texto original: %s\n", plaintext2)
	fmt.Printf("Criptografado:  %s\n", encrypted2)
	fmt.Printf("Descriptografado: %s\n", decrypted2)
	fmt.Printf("Sucesso: %v\n", plaintext2 == decrypted2)

	// Teste com diferentes tweaks
	fmt.Println("\n=== Teste com tweak diferente ===")
	tweak3 := []byte("different")
	encrypted3, err := cipher2.EncryptWithTweak(plaintext2, tweak3)
	if err != nil {
		fmt.Printf("Erro ao criptografar: %v\n", err)
		return
	}

	decrypted3, err := cipher2.DecryptWithTweak(encrypted3, tweak3)
	if err != nil {
		fmt.Printf("Erro ao descriptografar: %v\n", err)
		return
	}

	fmt.Printf("Com tweak 'different':\n")
	fmt.Printf("  Criptografado:  %s\n", encrypted3)
	fmt.Printf("  Descriptografado: %s\n", decrypted3)
	fmt.Printf("  Sucesso: %v\n", plaintext2 == decrypted3)
}

// Helper functions
func mathLog2(x float64) float64 {
	return math.Log2(x)
}

// Teste de validação
func testFF1() {
	fmt.Println("\n=== Testes de validação ===")

	tests := []struct {
		name      string
		radix     int
		key       string
		tweak     string
		plaintext string
	}{
		{
			name:      "Decimal curto",
			radix:     10,
			key:       "0123456789ABCDEF",
			tweak:     "",
			plaintext: "1234",
		},
		{
			name:      "Hexadecimal",
			radix:     16,
			key:       "0123456789abcdef",
			tweak:     "test",
			plaintext: "deadbeef",
		},
		{
			name:      "Base 36",
			radix:     36,
			key:       "0123456789ABCDEF0123456789ABCDEF",
			tweak:     "tweak",
			plaintext: "hello123",
		},
	}

	for _, test := range tests {
		fmt.Printf("\nTeste: %s\n", test.name)

		cipher, err := NewCipher(test.radix, len(test.tweak), []byte(test.key), []byte(test.tweak))
		if err != nil {
			fmt.Printf("  Erro ao criar cipher: %v\n", err)
			continue
		}

		encrypted, err := cipher.Encrypt(test.plaintext)
		if err != nil {
			fmt.Printf("  Erro ao criptografar: %v\n", err)
			continue
		}

		decrypted, err := cipher.Decrypt(encrypted)
		if err != nil {
			fmt.Printf("  Erro ao descriptografar: %v\n", err)
			continue
		}

		fmt.Printf("  Original: %s\n", test.plaintext)
		fmt.Printf("  Criptografado: %s\n", encrypted)
		fmt.Printf("  Descriptografado: %s\n", decrypted)
		fmt.Printf("  Sucesso: %v\n", test.plaintext == decrypted)

		// Verificar que o resultado tem o mesmo comprimento
		if len(encrypted) != len(test.plaintext) {
			fmt.Printf("  AVISO: Comprimento diferente! Original: %d, Criptografado: %d\n",
				len(test.plaintext), len(encrypted))
		}
	}
}
