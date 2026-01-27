<?php
/**
 * PHP Implementation of FF1 (Format-Preserving Encryption)
 * Based on NIST SP 800-38G
 * Implementação pura PHP com apenas BCMath + AES implementado manualmente
 */

class FF1Cipher {
    // Constants
    const FEISTEL_MIN = 100;
    const NUM_ROUNDS = 10;
    const BLOCK_SIZE = 16; // 128 bits for AES
    const NB = 4; // Number of columns (32-bit words) comprising the State
    
    private $tweak;
    private $radix;
    private $minLen;
    private $maxLen;
    private $maxTLen;
    private $aesKey;
    private $Nr;  // Number of rounds
    private $Nk;  // Number of 32-bit words in key
    private $w;   // Expanded key
    
    /**
     * Create a new FF1 cipher instance
     */
    public function __construct($radix, $maxTLen, $key, $tweak = '') {
        // Validate key
        $keyLen = strlen($key);
        if (!in_array($keyLen, [16, 24, 32])) {
            throw new Exception("Key length must be 128, 192 or 256 bits (16, 24, or 32 bytes)");
        }
        
        // Validate radix
        if ($radix < 2 || $radix > 65536) {
            throw new Exception("Radix must be between 2 and 65536 inclusive");
        }
        
        // Validate tweak
        if (strlen($tweak) > $maxTLen) {
            throw new Exception("Tweak exceeds maximum allowed length");
        }
        
        // Calculate minLen
        $minLen = max(2, (int)ceil(log(self::FEISTEL_MIN) / log($radix)));
        $maxLen = pow(2, 32) - 1;
        
        // Validate limits
        if ($minLen < 2 || $maxLen < $minLen) {
            throw new Exception("Invalid minLen, adjust your radix");
        }
        
        // Store parameters
        $this->tweak = $tweak;
        $this->radix = $radix;
        $this->minLen = $minLen;
        $this->maxLen = $maxLen;
        $this->maxTLen = $maxTLen;
        $this->aesKey = $key;
        
        // AES parameters based on key length
        $this->Nk = $keyLen / 4; // 4, 6, or 8
        $this->Nr = $this->Nk + 6; // 10, 12, or 14 rounds
        
        // Check for bcmath
        if (!extension_loaded('bcmath')) {
            throw new Exception("BCMath extension is required");
        }
        
        // Expand key
        $this->keyExpansion();
    }
    
    /**
     * AES Key Expansion
     */
    private function keyExpansion() {
        // S-box
        static $sbox = array(
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
        );
        
        // Rcon
        static $rcon = array(
            0x00000000, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
            0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000,
            0x36000000, 0x6c000000, 0xd8000000, 0xab000000, 0x4d000000,
            0x9a000000, 0x2f000000, 0x5e000000, 0xbc000000, 0x63000000,
            0xc6000000, 0x97000000, 0x35000000, 0x6a000000, 0xd4000000
        );
        
        // Initialize expanded key array
        $this->w = array_fill(0, 4 * ($this->Nr + 1), 0);
        
        // Copy initial key
        for ($i = 0; $i < $this->Nk; $i++) {
            $this->w[$i] = (ord($this->aesKey[4 * $i]) << 24) |
                          (ord($this->aesKey[4 * $i + 1]) << 16) |
                          (ord($this->aesKey[4 * $i + 2]) << 8) |
                          ord($this->aesKey[4 * $i + 3]);
        }
        
        // Expand key
        for ($i = $this->Nk; $i < 4 * ($this->Nr + 1); $i++) {
            $temp = $this->w[$i - 1];
            
            if ($i % $this->Nk == 0) {
                // RotWord
                $temp = (($temp << 8) & 0xFFFFFFFF) | ($temp >> 24);
                
                // SubWord
                $temp = ($sbox[($temp >> 24) & 0xFF] << 24) |
                       ($sbox[($temp >> 16) & 0xFF] << 16) |
                       ($sbox[($temp >> 8) & 0xFF] << 8) |
                       $sbox[$temp & 0xFF];
                
                // XOR with Rcon
                $temp ^= $rcon[$i / $this->Nk];
            } elseif ($this->Nk > 6 && $i % $this->Nk == 4) {
                // SubWord only for 256-bit keys
                $temp = ($sbox[($temp >> 24) & 0xFF] << 24) |
                       ($sbox[($temp >> 16) & 0xFF] << 16) |
                       ($sbox[($temp >> 8) & 0xFF] << 8) |
                       $sbox[$temp & 0xFF];
            }
            
            $this->w[$i] = $this->w[$i - $this->Nk] ^ $temp;
        }
    }
    
    /**
     * AES SubBytes transformation
     */
    private function subBytes(&$state) {
        static $sbox = array(
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
        );
        
        for ($i = 0; $i < 4; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $state[$i][$j] = $sbox[$state[$i][$j]];
            }
        }
    }
    
    /**
     * AES ShiftRows transformation
     */
    private function shiftRows(&$state) {
        // Row 0: no shift
        // Row 1: shift left 1
        $temp = $state[1][0];
        $state[1][0] = $state[1][1];
        $state[1][1] = $state[1][2];
        $state[1][2] = $state[1][3];
        $state[1][3] = $temp;
        
        // Row 2: shift left 2
        $temp = $state[2][0];
        $state[2][0] = $state[2][2];
        $state[2][2] = $temp;
        $temp = $state[2][1];
        $state[2][1] = $state[2][3];
        $state[2][3] = $temp;
        
        // Row 3: shift left 3 (or right 1)
        $temp = $state[3][3];
        $state[3][3] = $state[3][2];
        $state[3][2] = $state[3][1];
        $state[3][1] = $state[3][0];
        $state[3][0] = $temp;
    }
    
    /**
     * AES MixColumns transformation
     */
    private function mixColumns(&$state) {
        for ($i = 0; $i < 4; $i++) {
            $s0 = $state[0][$i];
            $s1 = $state[1][$i];
            $s2 = $state[2][$i];
            $s3 = $state[3][$i];
            
            $state[0][$i] = $this->gmul(0x02, $s0) ^ $this->gmul(0x03, $s1) ^ $s2 ^ $s3;
            $state[1][$i] = $s0 ^ $this->gmul(0x02, $s1) ^ $this->gmul(0x03, $s2) ^ $s3;
            $state[2][$i] = $s0 ^ $s1 ^ $this->gmul(0x02, $s2) ^ $this->gmul(0x03, $s3);
            $state[3][$i] = $this->gmul(0x03, $s0) ^ $s1 ^ $s2 ^ $this->gmul(0x02, $s3);
        }
    }
    
    /**
     * Galois Field multiplication
     */
    private function gmul($a, $b) {
        $p = 0;
        for ($i = 0; $i < 8; $i++) {
            if ($b & 1) {
                $p ^= $a;
            }
            $hi_bit_set = $a & 0x80;
            $a <<= 1;
            if ($hi_bit_set) {
                $a ^= 0x1b; // irreducible polynomial
            }
            $b >>= 1;
        }
        return $p & 0xFF;
    }
    
    /**
     * AES AddRoundKey transformation
     */
    private function addRoundKey(&$state, $round) {
        for ($i = 0; $i < 4; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $state[$i][$j] ^= ($this->w[$round * 4 + $j] >> (24 - 8 * $i)) & 0xFF;
            }
        }
    }
    
    /**
     * AES Encrypt a single 128-bit block
     */
    private function aesEncryptBlock($block) {
        // Initialize state
        $state = array_fill(0, 4, array_fill(0, 4, 0));
        
        // Fill state column-major order
        for ($i = 0; $i < 4; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $state[$j][$i] = ord($block[$i * 4 + $j]);
            }
        }
        
        // Initial round
        $this->addRoundKey($state, 0);
        
        // Main rounds
        for ($round = 1; $round < $this->Nr; $round++) {
            $this->subBytes($state);
            $this->shiftRows($state);
            $this->mixColumns($state);
            $this->addRoundKey($state, $round);
        }
        
        // Final round (no MixColumns)
        $this->subBytes($state);
        $this->shiftRows($state);
        $this->addRoundKey($state, $this->Nr);
        
        // Convert state back to bytes
        $output = '';
        for ($i = 0; $i < 4; $i++) {
            for ($j = 0; $j < 4; $j++) {
                $output .= chr($state[$j][$i]);
            }
        }
        
        return $output;
    }
    
    /**
     * Cipher function (AES-CBC)
     */
    private function ciph($input) {
        if (strlen($input) % self::BLOCK_SIZE != 0) {
            throw new Exception("Input length must be multiple of 16");
        }
        
        // CBC mode with zero IV (as per FF1 specification)
        $iv = str_repeat("\0", self::BLOCK_SIZE);
        $blocks = str_split($input, self::BLOCK_SIZE);
        $output = '';
        $prev = $iv;
        
        foreach ($blocks as $block) {
            // XOR with previous ciphertext (or IV for first block)
            $xored = '';
            for ($i = 0; $i < self::BLOCK_SIZE; $i++) {
                $xored .= chr(ord($block[$i]) ^ ord($prev[$i]));
            }
            
            // AES encrypt
            $encrypted = $this->aesEncryptBlock($xored);
            $output .= $encrypted;
            $prev = $encrypted;
        }
        
        return $output;
    }
    
    /**
     * PRF function (AES-CBC-MAC)
     */
    private function prf($input) {
        $encrypted = $this->ciph($input);
        // Return only the last block (CBC-MAC)
        return substr($encrypted, -self::BLOCK_SIZE);
    }
    
    /**
     * String to big integer usando bcmath
     */
    private function strToBigInt($str, $radix) {
        if (!extension_loaded('bcmath')) {
            throw new Exception("BCMath extension is required");
        }
        
        $result = '0';
        $len = strlen($str);
        $radixStr = (string)$radix;
        
        for ($i = 0; $i < $len; $i++) {
            $char = $str[$i];
            $val = $this->charToValue($char);
            
            $result = bcmul($result, $radixStr);
            $result = bcadd($result, (string)$val);
        }
        
        return $result;
    }
    
    /**
     * Big integer to string usando bcmath
     */
    private function bigIntToStr($num, $radix, $length) {
        if (!extension_loaded('bcmath')) {
            throw new Exception("BCMath extension is required");
        }
        
        if (bccomp($num, '0') == 0) {
            return str_repeat('0', $length);
        }
        
        $result = '';
        $radixStr = (string)$radix;
        
        while (bccomp($num, '0') > 0) {
            $remainder = bcmod($num, $radixStr);
            $result = $this->valueToChar((int)$remainder) . $result;
            $num = bcdiv($num, $radixStr, 0);
        }
        
        // Pad with zeros
        while (strlen($result) < $length) {
            $result = '0' . $result;
        }
        
        return $result;
    }
    
    /**
     * Power function com bcmath
     */
    private function powMod($base, $exponent) {
        if (!extension_loaded('bcmath')) {
            throw new Exception("BCMath extension is required");
        }
        
        $result = '1';
        $baseStr = (string)$base;
        
        for ($i = 0; $i < $exponent; $i++) {
            $result = bcmul($result, $baseStr);
        }
        
        return $result;
    }
    
    /**
     * Encrypt with a specific tweak
     */
    public function encryptWithTweak($plaintext, $tweak = null) {
        if ($tweak === null) {
            $tweak = $this->tweak;
        }
        
        $n = strlen($plaintext);
        $t = strlen($tweak);
        
        // Validate length
        if ($n < $this->minLen || $n > $this->maxLen) {
            throw new Exception("Message length out of bounds (min: {$this->minLen}, max: {$this->maxLen}, actual: {$n})");
        }
        
        if (strlen($tweak) > $this->maxTLen) {
            throw new Exception("Tweak exceeds maximum length");
        }
        
        // Check if string is within radix
        if (!$this->isValidString($plaintext)) {
            throw new Exception("String contains characters outside the radix");
        }
        
        // Calculate split point
        $u = (int)floor($n / 2);
        $v = $n - $u;
        
        // Split text
        $A = substr($plaintext, 0, $u);
        $B = substr($plaintext, $u);
        
        // Calculate parameters
        $b = (int)ceil(ceil($v * log($this->radix, 2)) / 8);
        $d = (int)(4 * ceil($b / 4) + 4);
        
        $maxJ = (int)ceil($d / 16);
        
        $numPad = (-$t - $b - 1) % 16;
        if ($numPad < 0) {
            $numPad += 16;
        }
        
        // Build P (16 bytes)
        $P = str_repeat("\0", 16);
        $P[0] = chr(0x01);
        $P[1] = chr(0x02);
        $P[2] = chr(0x01);
        $P[3] = chr(0x00); // Padding
        
        // Radix em 2 bytes big-endian
        $P[4] = chr(($this->radix >> 8) & 0xFF);
        $P[5] = chr($this->radix & 0xFF);
        
        $P[6] = chr(0x0a);
        $P[7] = chr($u); // u mod 256
        
        // n em 4 bytes big-endian
        $P[8] = chr(($n >> 24) & 0xFF);
        $P[9] = chr(($n >> 16) & 0xFF);
        $P[10] = chr(($n >> 8) & 0xFF);
        $P[11] = chr($n & 0xFF);
        
        // t em 4 bytes big-endian
        $P[12] = chr(($t >> 24) & 0xFF);
        $P[13] = chr(($t >> 16) & 0xFF);
        $P[14] = chr(($t >> 8) & 0xFF);
        $P[15] = chr($t & 0xFF);
        
        // Comprimentos
        $lenQ = $t + $b + 1 + $numPad;
        
        // Converter strings para números
        $numA = $this->strToBigInt($A, $this->radix);
        $numB = $this->strToBigInt($B, $this->radix);
        
        // Pré-calcular módulos
        $modU = $this->powMod($this->radix, $u);
        $modV = $this->powMod($this->radix, $v);
        
        // Feistel rounds
        for ($i = 0; $i < self::NUM_ROUNDS; $i++) {
            // Build Q
            $Q = str_repeat("\0", $lenQ);
            
            // Copy tweak
            if ($t > 0) {
                for ($j = 0; $j < $t; $j++) {
                    $Q[$j] = $tweak[$j];
                }
            }
            
            $Q[$t + $numPad] = chr($i);
            
            // Converter B para bytes
            $bBytes = $this->bigIntToBytes($numB, $b);
            
            // Zerar o restante
            for ($j = $t + $numPad + 1; $j < $lenQ - strlen($bBytes); $j++) {
                $Q[$j] = "\0";
            }
            
            // Copiar bytes de B para o final de Q
            $startPos = $lenQ - strlen($bBytes);
            for ($j = 0; $j < strlen($bBytes); $j++) {
                $Q[$startPos + $j] = $bBytes[$j];
            }
            
            // Build PQ = P || Q
            $PQ = $P . $Q;
            
            // Calculate R = PRF(PQ)
            $R = $this->prf($PQ);
            
            // Y buffer
            $Y = str_repeat("\0", $d);
            
            // Copiar R para início de Y
            $copyLen = min(16, $d);
            for ($j = 0; $j < $copyLen; $j++) {
                $Y[$j] = $R[$j];
            }
            
            // Para j > 1
            for ($j = 1; $j < $maxJ; $j++) {
                $offset = ($j - 1) * 16;
                
                if ($offset + 16 >= $d) {
                    break;
                }
                
                // XOR R com j
                $block = str_repeat("\0", 16);
                $jBytes = pack('J', $j); // 8 bytes para j
                
                for ($k = 0; $k < 8; $k++) {
                    $block[$k] = chr(ord($R[$k]) ^ ord($jBytes[$k]));
                }
                for ($k = 8; $k < 16; $k++) {
                    $block[$k] = $R[$k];
                }
                
                // Criptografar bloco
                $encryptedBlock = $this->ciph($block);
                
                // Copiar para Y
                $copyLen = min(16, $d - $offset);
                for ($k = 0; $k < $copyLen; $k++) {
                    $Y[$offset + $k] = $encryptedBlock[$k];
                }
            }
            
            // Converter Y para número
            $numY = $this->bytesToBigInt($Y);
            
            // Calcular C = A + Y mod (radix^u ou radix^v)
            if ($i % 2 == 0) {
                // $numC = ($numA + $numY) % $modU
                $sum = bcadd($numA, $numY);
                $numC = bcmod($sum, $modU);
            } else {
                $sum = bcadd($numA, $numY);
                $numC = bcmod($sum, $modV);
            }
            
            // Atualizar A e B
            $numA = $numB;
            $numB = $numC;
        }
        
        // Converter números de volta para strings
        $Aenc = $this->bigIntToStr($numA, $this->radix, $u);
        $Benc = $this->bigIntToStr($numB, $this->radix, $v);
        
        return $Aenc . $Benc;
    }
    
    /**
     * Decrypt with a specific tweak
     */
    public function decryptWithTweak($ciphertext, $tweak = null) {
        if ($tweak === null) {
            $tweak = $this->tweak;
        }
        
        $n = strlen($ciphertext);
        $t = strlen($tweak);
        
        // Validate length
        if ($n < $this->minLen || $n > $this->maxLen) {
            throw new Exception("Message length out of bounds (min: {$this->minLen}, max: {$this->maxLen}, actual: {$n})");
        }
        
        if (strlen($tweak) > $this->maxTLen) {
            throw new Exception("Tweak exceeds maximum length");
        }
        
        // Check if string is within radix
        if (!$this->isValidString($ciphertext)) {
            throw new Exception("String contains characters outside the radix");
        }
        
        // Calculate split point
        $u = (int)floor($n / 2);
        $v = $n - $u;
        
        // Split text
        $A = substr($ciphertext, 0, $u);
        $B = substr($ciphertext, $u);
        
        // Calculate parameters
        $b = (int)ceil(ceil($v * log($this->radix, 2)) / 8);
        $d = (int)(4 * ceil($b / 4) + 4);
        
        $maxJ = (int)ceil($d / 16);
        
        $numPad = (-$t - $b - 1) % 16;
        if ($numPad < 0) {
            $numPad += 16;
        }
        
        // Build P (16 bytes)
        $P = str_repeat("\0", 16);
        $P[0] = chr(0x01);
        $P[1] = chr(0x02);
        $P[2] = chr(0x01);
        $P[3] = chr(0x00);
        
        $P[4] = chr(($this->radix >> 8) & 0xFF);
        $P[5] = chr($this->radix & 0xFF);
        
        $P[6] = chr(0x0a);
        $P[7] = chr($u);
        
        $P[8] = chr(($n >> 24) & 0xFF);
        $P[9] = chr(($n >> 16) & 0xFF);
        $P[10] = chr(($n >> 8) & 0xFF);
        $P[11] = chr($n & 0xFF);
        
        $P[12] = chr(($t >> 24) & 0xFF);
        $P[13] = chr(($t >> 16) & 0xFF);
        $P[14] = chr(($t >> 8) & 0xFF);
        $P[15] = chr($t & 0xFF);
        
        // Comprimentos
        $lenQ = $t + $b + 1 + $numPad;
        
        // Converter strings para números
        $numA = $this->strToBigInt($A, $this->radix);
        $numB = $this->strToBigInt($B, $this->radix);
        
        // Pré-calcular módulos
        $modU = $this->powMod($this->radix, $u);
        $modV = $this->powMod($this->radix, $v);
        
        // Feistel rounds em ordem inversa
        for ($i = self::NUM_ROUNDS - 1; $i >= 0; $i--) {
            // Build Q (com A em vez de B)
            $Q = str_repeat("\0", $lenQ);
            
            // Copy tweak
            if ($t > 0) {
                for ($j = 0; $j < $t; $j++) {
                    $Q[$j] = $tweak[$j];
                }
            }
            
            $Q[$t + $numPad] = chr($i);
            
            // Converter A para bytes
            $aBytes = $this->bigIntToBytes($numA, $b);
            
            // Zerar o restante
            for ($j = $t + $numPad + 1; $j < $lenQ - strlen($aBytes); $j++) {
                $Q[$j] = "\0";
            }
            
            // Copiar bytes de A para o final de Q
            $startPos = $lenQ - strlen($aBytes);
            for ($j = 0; $j < strlen($aBytes); $j++) {
                $Q[$startPos + $j] = $aBytes[$j];
            }
            
            // Build PQ = P || Q
            $PQ = $P . $Q;
            
            // Calculate R = PRF(PQ)
            $R = $this->prf($PQ);
            
            // Y buffer
            $Y = str_repeat("\0", $d);
            
            // Copiar R para início de Y
            $copyLen = min(16, $d);
            for ($j = 0; $j < $copyLen; $j++) {
                $Y[$j] = $R[$j];
            }
            
            // Para j > 1
            for ($j = 1; $j < $maxJ; $j++) {
                $offset = ($j - 1) * 16;
                
                if ($offset + 16 >= $d) {
                    break;
                }
                
                // XOR R com j
                $block = str_repeat("\0", 16);
                $jBytes = pack('J', $j);
                
                for ($k = 0; $k < 8; $k++) {
                    $block[$k] = chr(ord($R[$k]) ^ ord($jBytes[$k]));
                }
                for ($k = 8; $k < 16; $k++) {
                    $block[$k] = $R[$k];
                }
                
                // Criptografar bloco
                $encryptedBlock = $this->ciph($block);
                
                // Copiar para Y
                $copyLen = min(16, $d - $offset);
                for ($k = 0; $k < $copyLen; $k++) {
                    $Y[$offset + $k] = $encryptedBlock[$k];
                }
            }
            
            // Converter Y para número
            $numY = $this->bytesToBigInt($Y);
            
            // Calcular C = B - Y mod (radix^u ou radix^v)
            if ($i % 2 == 0) {
                // $numC = ($numB - $numY) % $modU
                $diff = bcsub($numB, $numY);
                $numC = bcmod($diff, $modU);
                if (bccomp($numC, '0') < 0) {
                    $numC = bcadd($numC, $modU);
                }
            } else {
                $diff = bcsub($numB, $numY);
                $numC = bcmod($diff, $modV);
                if (bccomp($numC, '0') < 0) {
                    $numC = bcadd($numC, $modV);
                }
            }
            
            // Atualizar A e B
            $numB = $numA;
            $numA = $numC;
        }
        
        // Converter números de volta para strings
        $Adec = $this->bigIntToStr($numA, $this->radix, $u);
        $Bdec = $this->bigIntToStr($numB, $this->radix, $v);
        
        return $Adec . $Bdec;
    }
    
    /**
     * Encrypt a string using FF1
     */
    public function encrypt($plaintext) {
        return $this->encryptWithTweak($plaintext, $this->tweak);
    }
    
    /**
     * Decrypt a string using FF1
     */
    public function decrypt($ciphertext) {
        return $this->decryptWithTweak($ciphertext, $this->tweak);
    }
    
    /**
     * Check if all characters in string are within radix
     */
    private function isValidString($s) {
        for ($i = 0; $i < strlen($s); $i++) {
            $ch = $s[$i];
            $val = $this->charToValue($ch);
            if ($val < 0 || $val >= $this->radix) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Convert character to numeric value (suporta até base 36)
     */
    private function charToValue($ch) {
        $ord = ord($ch);
        
        if ($ord >= 48 && $ord <= 57) { // '0'-'9'
            return $ord - 48;
        }
        
        if ($ord >= 97 && $ord <= 122) { // 'a'-'z'
            return $ord - 97 + 10;
        }
        
        if ($ord >= 65 && $ord <= 90) { // 'A'-'Z'
            return $ord - 65 + 10;
        }
        
        return -1;
    }
    
    /**
     * Convert value to character (suporta até base 36)
     */
    private function valueToChar($val) {
        if ($val < 10) {
            return chr(48 + $val); // '0'-'9'
        } else {
            return chr(97 + ($val - 10)); // 'a'-'z'
        }
    }
    
    /**
     * Convert big integer to bytes (big-endian)
     */
    private function bigIntToBytes($num, $bytes) {
        if (!extension_loaded('bcmath')) {
            throw new Exception("BCMath extension is required");
        }
        
        $result = '';
        
        for ($i = $bytes - 1; $i >= 0; $i--) {
            // Calcular byte = floor($num / 256^$i) mod 256
            $pow = bcpow('256', (string)$i);
            $quotient = bcdiv($num, $pow, 0);
            $byte = bcmod($quotient, '256');
            $result .= chr((int)$byte);
            
            // Subtrair do número: $num = $num - $byte * 256^$i
            $subtract = bcmul($byte, $pow);
            $num = bcsub($num, $subtract);
        }
        
        return $result;
    }
    
    /**
     * Convert bytes to big integer
     */
    private function bytesToBigInt($bytes) {
        if (!extension_loaded('bcmath')) {
            throw new Exception("BCMath extension is required");
        }
        
        $result = '0';
        $len = strlen($bytes);
        
        for ($i = 0; $i < $len; $i++) {
            $result = bcmul($result, '256');
            $result = bcadd($result, (string)ord($bytes[$i]));
        }
        
        return $result;
    }
    
    /**
     * Get minimum length for given radix
     */
    public function getMinLength() {
        return $this->minLen;
    }
    
    /**
     * Get maximum length
     */
    public function getMaxLength() {
        return $this->maxLen;
    }
}

// =============================================
// Test and Example Usage
// =============================================

/**
 * Main test function
 */
function main() {
    echo "=== Test 1: Base 10 (decimal) ===\n";
    
    $key1 = "0123456789ABCDEF"; // 16 bytes
    $tweak1 = "";
    $plaintext1 = "123456789012";
    
    try {
        $cipher1 = new FF1Cipher(10, strlen($plaintext1), $key1, $tweak1);
        
        echo "minLen: " . $cipher1->getMinLength() . "\n";
        echo "maxLen: " . $cipher1->getMaxLength() . "\n";
        echo "Plaintext length: " . strlen($plaintext1) . "\n\n";
        
        $encrypted1 = $cipher1->encrypt($plaintext1);
        $decrypted1 = $cipher1->decrypt($encrypted1);
        
        echo "Original text: $plaintext1\n";
        echo "Encrypted:     $encrypted1\n";
        echo "Decrypted:     $decrypted1\n";
        echo "Success: " . (($plaintext1 == $decrypted1) ? "YES" : "NO") . "\n\n";
        
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
    }
    
    echo "=== Test 2: Base 16 (hexadecimal) ===\n";
    
    $key2 = "0123456789abcdef"; // 16 bytes
    $tweak2 = "1234";
    $plaintext2 = "0123456789abcdef";
    
    try {
        $cipher2 = new FF1Cipher(16, strlen($plaintext2), $key2, $tweak2);
        
        echo "minLen: " . $cipher2->getMinLength() . "\n";
        echo "maxLen: " . $cipher2->getMaxLength() . "\n\n";
        
        $encrypted2 = $cipher2->encrypt($plaintext2);
        $decrypted2 = $cipher2->decrypt($encrypted2);
        
        echo "Original text: $plaintext2\n";
        echo "Encrypted:     $encrypted2\n";
        echo "Decrypted:     $decrypted2\n";
        echo "Success: " . (($plaintext2 == $decrypted2) ? "YES" : "NO") . "\n";
        
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
    }
}

// Run if called directly
if (basename(__FILE__) == basename($_SERVER['PHP_SELF'])) {
    if (PHP_SAPI === 'cli') {
        main();
    } else {
        echo "<pre>";
        main();
        echo "</pre>";
    }
}
