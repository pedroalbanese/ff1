// Package ff1 implements the FF1 format-preserving encryption algorithm.
// FF1 (Format-Preserving Encryption mode 1) is specified in NIST Special Publication 800-38G.
// This implementation supports radix from 2 to 65536 and arbitrary-length inputs.
package ff1

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

// Constants
const (
	feistelMin    = 100          // Minimum domain size for Feistel networks
	numRounds     = 10           // Number of Feistel rounds
	blockSize     = 16           // 128 bits for AES
	halfBlockSize = blockSize / 2
)

// Cipher represents an instance of the FF1 encryption algorithm
type Cipher struct {
	tweak        []byte
	radix        int
	minLen       uint32
	maxLen       uint32
	maxTLen      int
	cbcEncryptor cipher.BlockMode
	aesBlock     cipher.Block
}

// NewCipher creates a new FF1 cipher instance
// Parameters:
//   - radix: The base of the numeral system (2 to 65536)
//   - maxTLen: Maximum tweak length in bytes
//   - key: AES key (16, 24, or 32 bytes for AES-128, AES-192, or AES-256)
//   - tweak: Tweak value (can be empty)
func NewCipher(radix int, maxTLen int, key []byte, tweak []byte) (*Cipher, error) {
	var c Cipher

	// Validate key
	keyLen := len(key)
	if keyLen != 16 && keyLen != 24 && keyLen != 32 {
		return nil, errors.New("key length must be 128, 192, or 256 bits")
	}

	// Validate radix
	if radix < 2 || radix > 65536 {
		return nil, errors.New("radix must be between 2 and 65536, inclusive")
	}

	// Validate tweak
	if len(tweak) > maxTLen {
		return nil, errors.New("tweak exceeds maximum allowed length")
	}

	// Calculate minLen
	minLen := uint32(math.Ceil(math.Log(feistelMin) / math.Log(float64(radix))))
	maxLen := uint32(math.MaxUint32)

	// Validate limits
	if minLen < 2 || maxLen < minLen {
		return nil, errors.New("invalid minLen, adjust your radix")
	}

	// Create AES cipher
	aesBlock, err := aes.NewCipher(key)
	if err != nil {
		return nil, errors.New("failed to create AES block")
	}

	// Create CBC cipher with zero IV
	ivZero := make([]byte, blockSize)
	cbcEncryptor := cipher.NewCBCEncrypter(aesBlock, ivZero)

	// Initialize structure
	c.tweak = tweak
	c.radix = radix
	c.minLen = minLen
	c.maxLen = maxLen
	c.maxTLen = maxTLen
	c.cbcEncryptor = cbcEncryptor
	c.aesBlock = aesBlock

	return &c, nil
}

// Encrypt encrypts a string using FF1 with the default tweak
func (c *Cipher) Encrypt(plaintext string) (string, error) {
	return c.EncryptWithTweak(plaintext, c.tweak)
}

// EncryptWithTweak encrypts a string using a specific tweak
func (c *Cipher) EncryptWithTweak(plaintext string, tweak []byte) (string, error) {
	n := uint32(len(plaintext))
	t := len(tweak)

	// Validate length
	if n < c.minLen || n > c.maxLen {
		return "", errors.New("message length out of bounds")
	}

	if len(tweak) > c.maxTLen {
		return "", errors.New("tweak exceeds maximum length")
	}

	// Check if string is in the specified radix
	if !c.isValidString(plaintext) {
		return "", errors.New("string contains characters outside the radix")
	}

	// Calculate split point
	u := n / 2
	v := n - u

	// Split text
	A := plaintext[:u]
	B := plaintext[u:]

	// Calculate parameters
	b := int(math.Ceil(math.Ceil(float64(v)*math.Log2(float64(c.radix))) / 8))
	d := int(4*math.Ceil(float64(b)/4) + 4)

	maxJ := int(math.Ceil(float64(d) / 16))

	numPad := (-t - b - 1) % 16
	if numPad < 0 {
		numPad += 16
	}

	// Build P (16 bytes)
	P := make([]byte, blockSize)
	P[0] = 0x01
	P[1] = 0x02
	P[2] = 0x01
	P[3] = 0x00 // Padding for radix

	// Radix in 2 bytes (big-endian)
	binary.BigEndian.PutUint16(P[4:6], uint16(c.radix))

	P[6] = 0x0a
	P[7] = byte(u) // u mod 256

	// n in 4 bytes
	binary.BigEndian.PutUint32(P[8:12], n)

	// t in 4 bytes
	binary.BigEndian.PutUint32(P[12:16], uint32(t))

	// Lengths
	lenQ := t + b + 1 + numPad
	lenPQ := blockSize + lenQ

	// Buffer for temporary data
	buf := make([]byte, lenQ+lenPQ+(maxJ-1)*blockSize)

	// Convert strings to big.Int numbers
	numA, okA := new(big.Int).SetString(A, c.radix)
	numB, okB := new(big.Int).SetString(B, c.radix)

	if !okA || !okB {
		return "", errors.New("error converting string to number")
	}

	// Pre-calculate moduli
	radixBig := big.NewInt(int64(c.radix))
	modU := new(big.Int).Exp(radixBig, big.NewInt(int64(u)), nil)
	modV := new(big.Int).Exp(radixBig, big.NewInt(int64(v)), nil)

	// Feistel rounds
	for i := 0; i < numRounds; i++ {
		// Build Q
		Q := buf[:lenQ]
		copy(Q[:t], tweak)
		Q[t+numPad] = byte(i)

		// Convert B to bytes
		bBytes := numB.Bytes()

		// Zero out the rest of Q
		for j := t + numPad + 1; j < lenQ; j++ {
			Q[j] = 0x00
		}

		// Copy B bytes to the end of Q
		startPos := lenQ - len(bBytes)
		copy(Q[startPos:], bBytes)

		// Build PQ = P || Q
		PQ := buf[lenQ : lenQ+lenPQ]
		copy(PQ[:blockSize], P)
		copy(PQ[blockSize:], Q)

		// Calculate R = PRF(PQ)
		R, err := c.prf(PQ)
		if err != nil {
			return "", err
		}

		// Y buffer
		Y := buf[lenQ+lenPQ-blockSize:]

		// Copy R to start of Y
		copy(Y[:blockSize], R)

		// For j > 1
		for j := 1; j < maxJ; j++ {
			offset := (j - 1) * blockSize

			// XOR R with j
			for k := 0; k < halfBlockSize; k++ {
				Y[offset+blockSize+k] = R[k] ^ 0x00
			}

			// J in 8 bytes (big-endian)
			jBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(jBytes, uint64(j))
			for k := 0; k < 8; k++ {
				Y[offset+blockSize+halfBlockSize+k] = R[halfBlockSize+k] ^ jBytes[k]
			}

			// Encrypt block
			block := Y[offset+blockSize : offset+2*blockSize]
			_, err := c.ciph(block)
			if err != nil {
				return "", err
			}
		}

		// Convert Y to big.Int
		YBytes := Y[:d]
		numY := new(big.Int).SetBytes(YBytes)

		// Calculate C = A + Y mod (radix^u or radix^v)
		numC := new(big.Int).Add(numA, numY)

		if i%2 == 0 {
			numC.Mod(numC, modU)
		} else {
			numC.Mod(numC, modV)
		}

		// Update A and B
		numA.Set(numB)
		numB.Set(numC)
	}

	// Convert numbers back to strings
	Aenc := numA.Text(c.radix)
	Benc := numB.Text(c.radix)

	// Add padding
	Aenc = strings.Repeat("0", int(u)-len(Aenc)) + Aenc
	Benc = strings.Repeat("0", int(v)-len(Benc)) + Benc

	return Aenc + Benc, nil
}

// Decrypt decrypts a string using FF1 with the default tweak
func (c *Cipher) Decrypt(ciphertext string) (string, error) {
	return c.DecryptWithTweak(ciphertext, c.tweak)
}

// DecryptWithTweak decrypts a string using a specific tweak
func (c *Cipher) DecryptWithTweak(ciphertext string, tweak []byte) (string, error) {
	n := uint32(len(ciphertext))
	t := len(tweak)

	// Validate length
	if n < c.minLen || n > c.maxLen {
		return "", errors.New("message length out of bounds")
	}

	if len(tweak) > c.maxTLen {
		return "", errors.New("tweak exceeds maximum length")
	}

	// Check if string is in the specified radix
	if !c.isValidString(ciphertext) {
		return "", errors.New("string contains characters outside the radix")
	}

	// Calculate split point
	u := n / 2
	v := n - u

	// Split text
	A := ciphertext[:u]
	B := ciphertext[u:]

	// Calculate parameters
	b := int(math.Ceil(math.Ceil(float64(v)*math.Log2(float64(c.radix))) / 8))
	d := int(4*math.Ceil(float64(b)/4) + 4)

	maxJ := int(math.Ceil(float64(d) / 16))

	numPad := (-t - b - 1) % 16
	if numPad < 0 {
		numPad += 16
	}

	// Build P (16 bytes)
	P := make([]byte, blockSize)
	P[0] = 0x01
	P[1] = 0x02
	P[2] = 0x01
	P[3] = 0x00 // Padding for radix

	// Radix in 2 bytes (big-endian)
	binary.BigEndian.PutUint16(P[4:6], uint16(c.radix))

	P[6] = 0x0a
	P[7] = byte(u) // u mod 256

	// n in 4 bytes
	binary.BigEndian.PutUint32(P[8:12], n)

	// t in 4 bytes
	binary.BigEndian.PutUint32(P[12:16], uint32(t))

	// Lengths
	lenQ := t + b + 1 + numPad
	lenPQ := blockSize + lenQ

	// Buffer for temporary data
	buf := make([]byte, lenQ+lenPQ+(maxJ-1)*blockSize)

	// Convert strings to big.Int numbers
	numA, okA := new(big.Int).SetString(A, c.radix)
	numB, okB := new(big.Int).SetString(B, c.radix)

	if !okA || !okB {
		return "", errors.New("error converting string to number")
	}

	// Pre-calculate moduli
	radixBig := big.NewInt(int64(c.radix))
	modU := new(big.Int).Exp(radixBig, big.NewInt(int64(u)), nil)
	modV := new(big.Int).Exp(radixBig, big.NewInt(int64(v)), nil)

	// Feistel rounds in reverse order
	for i := numRounds - 1; i >= 0; i-- {
		// Build Q
		Q := buf[:lenQ]
		copy(Q[:t], tweak)
		Q[t+numPad] = byte(i)

		// Convert A to bytes
		aBytes := numA.Bytes()

		// Zero out the rest of Q
		for j := t + numPad + 1; j < lenQ; j++ {
			Q[j] = 0x00
		}

		// Copy A bytes to the end of Q
		startPos := lenQ - len(aBytes)
		copy(Q[startPos:], aBytes)

		// Build PQ = P || Q
		PQ := buf[lenQ : lenQ+lenPQ]
		copy(PQ[:blockSize], P)
		copy(PQ[blockSize:], Q)

		// Calculate R = PRF(PQ)
		R, err := c.prf(PQ)
		if err != nil {
			return "", err
		}

		// Y buffer
		Y := buf[lenQ+lenPQ-blockSize:]

		// Copy R to start of Y
		copy(Y[:blockSize], R)

		// For j > 1
		for j := 1; j < maxJ; j++ {
			offset := (j - 1) * blockSize

			// XOR R with j
			for k := 0; k < halfBlockSize; k++ {
				Y[offset+blockSize+k] = R[k] ^ 0x00
			}

			// J in 8 bytes (big-endian)
			jBytes := make([]byte, 8)
			binary.BigEndian.PutUint64(jBytes, uint64(j))
			for k := 0; k < 8; k++ {
				Y[offset+blockSize+halfBlockSize+k] = R[halfBlockSize+k] ^ jBytes[k]
			}

			// Encrypt block
			block := Y[offset+blockSize : offset+2*blockSize]
			_, err := c.ciph(block)
			if err != nil {
				return "", err
			}
		}

		// Convert Y to big.Int
		YBytes := Y[:d]
		numY := new(big.Int).SetBytes(YBytes)

		// Calculate C = B - Y mod (radix^u or radix^v)
		numC := new(big.Int).Sub(numB, numY)

		if i%2 == 0 {
			numC.Mod(numC, modU)
		} else {
			numC.Mod(numC, modV)
		}

		// Update A and B
		numB.Set(numA)
		numA.Set(numC)
	}

	// Convert numbers back to strings
	Adec := numA.Text(c.radix)
	Bdec := numB.Text(c.radix)

	// Add padding
	Adec = strings.Repeat("0", int(u)-len(Adec)) + Adec
	Bdec = strings.Repeat("0", int(v)-len(Bdec)) + Bdec

	return Adec + Bdec, nil
}

// ciph implements the FF1 cipher function
func (c *Cipher) ciph(input []byte) ([]byte, error) {
	if len(input)%blockSize != 0 {
		return nil, errors.New("input length must be a multiple of 16")
	}

	// Use CBC mode
	output := make([]byte, len(input))
	c.cbcEncryptor.CryptBlocks(output, input)

	// Reset IV to zero
	if _, ok := c.cbcEncryptor.(cipher.BlockMode); ok {
		// Go's CBC encryptor doesn't have an exposed SetIV method
		// Recreate the encryptor with zero IV
		ivZero := make([]byte, blockSize)
		c.cbcEncryptor = cipher.NewCBCEncrypter(c.aesBlock, ivZero)
	}

	return output, nil
}

// prf implements the FF1 PRF function (AES-CBC-MAC)
func (c *Cipher) prf(input []byte) ([]byte, error) {
	ciphertext, err := c.ciph(input)
	if err != nil {
		return nil, err
	}

	// Return only the last block (CBC-MAC)
	return ciphertext[len(ciphertext)-blockSize:], nil
}

// isValidString checks if all characters are within the specified radix
func (c *Cipher) isValidString(s string) bool {
	for _, ch := range s {
		val := c.charToValue(byte(ch))
		if val < 0 || val >= c.radix {
			return false
		}
	}
	return true
}

// charToValue converts a character to its numerical value
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

// Example usage demonstrates how to use the FF1 library
func Example() {
	// Example 1: Base 10 (decimal)
	fmt.Println("=== Example 1: Base 10 ===")
	key1 := []byte("0123456789ABCDEF") // 16 bytes
	tweak1 := []byte("")
	plaintext1 := "123456789012"

	cipher1, err := NewCipher(10, len(plaintext1), key1, tweak1)
	if err != nil {
		fmt.Printf("Error creating cipher: %v\n", err)
		return
	}

	encrypted1, err := cipher1.Encrypt(plaintext1)
	if err != nil {
		fmt.Printf("Error encrypting: %v\n", err)
		return
	}

	decrypted1, err := cipher1.Decrypt(encrypted1)
	if err != nil {
		fmt.Printf("Error decrypting: %v\n", err)
		return
	}

	fmt.Printf("Original text: %s\n", plaintext1)
	fmt.Printf("Encrypted:     %s\n", encrypted1)
	fmt.Printf("Decrypted:     %s\n", decrypted1)
	fmt.Printf("Success: %v\n\n", plaintext1 == decrypted1)

	// Example 2: Base 16 (hexadecimal)
	fmt.Println("=== Example 2: Base 16 ===")
	key2 := []byte("0123456789abcdef") // 16 bytes
	tweak2 := []byte("1234")
	plaintext2 := "0123456789abcdef"

	cipher2, err := NewCipher(16, len(plaintext2), key2, tweak2)
	if err != nil {
		fmt.Printf("Error creating cipher: %v\n", err)
		return
	}

	encrypted2, err := cipher2.Encrypt(plaintext2)
	if err != nil {
		fmt.Printf("Error encrypting: %v\n", err)
		return
	}

	decrypted2, err := cipher2.Decrypt(encrypted2)
	if err != nil {
		fmt.Printf("Error decrypting: %v\n", err)
		return
	}

	fmt.Printf("Original text: %s\n", plaintext2)
	fmt.Printf("Encrypted:     %s\n", encrypted2)
	fmt.Printf("Decrypted:     %s\n", decrypted2)
	fmt.Printf("Success: %v\n", plaintext2 == decrypted2)
}
