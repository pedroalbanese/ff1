<?php
/**
 * PHP Implementation of FF1 (Format-Preserving Encryption)
 * Based on NIST SP 800-38G
 * Versão compatível com implementações Python e Go
 */

class FF1Cipher {
    // Constants
    const FEISTEL_MIN = 100;
    const NUM_ROUNDS = 10;
    const BLOCK_SIZE = 16; // 128 bits for AES
    
    private $tweak;
    private $radix;
    private $minLen;
    private $maxLen;
    private $maxTLen;
    private $aesKey;
    private $aes;
    
    /**
     * Create a new FF1 cipher instance
     */
    public function __construct($radix, $maxTLen, $key, $tweak = '') {
        // Validate key
        $keyLen = strlen($key);
        if (!in_array($keyLen, [16, 24, 32])) {
            throw new Exception("Key length must be 128, 192 or 256 bits (16, 24, or 32 bytes)");
        }
        
        // Validate radix - aumentado para 65536 como nas outras implementações
        if ($radix < 2 || $radix > 65536) {
            throw new Exception("Radix must be between 2 and 65536 inclusive");
        }
        
        // Validate tweak
        if (strlen($tweak) > $maxTLen) {
            throw new Exception("Tweak exceeds maximum allowed length");
        }
        
        // Calculate minLen - seguindo o padrão Python
        $minLen = max(2, (int)ceil(log(self::FEISTEL_MIN) / log($radix)));
        $maxLen = pow(2, 32) - 1; // Praticamente ilimitado
        
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
        
        // Create AES cipher
        if (!extension_loaded('openssl')) {
            throw new Exception("OpenSSL extension is required");
        }
        
        $this->aes = $key;
    }
    
    /**
     * Helper para log2
     */
    private function log2($n) {
        return log($n, 2);
    }
    
    /**
     * String to big integer usando bcmath para suportar números grandes
     */
    private function strToBigInt($str, $radix) {
        if (!extension_loaded('bcmath')) {
            return $this->strToIntFallback($str, $radix);
        }
        
        $result = '0';
        $len = strlen($str);
        
        for ($i = 0; $i < $len; $i++) {
            $char = $str[$i];
            $val = $this->charToValue($char);
            
            // $result = $result * $radix + $val
            $result = bcmul($result, (string)$radix);
            $result = bcadd($result, (string)$val);
        }
        
        return $result;
    }
    
    /**
     * Fallback para quando bcmath não está disponível
     */
    private function strToIntFallback($str, $radix) {
        $result = 0;
        $len = strlen($str);
        
        for ($i = 0; $i < $len; $i++) {
            $char = $str[$i];
            $val = $this->charToValue($char);
            $result = $result * $radix + $val;
            
            // Verificar overflow
            if ($result > PHP_INT_MAX / $radix && $i < $len - 1) {
                throw new Exception("Number too large, install bcmath extension");
            }
        }
        
        return $result;
    }
    
    /**
     * Big integer to string usando bcmath
     */
    private function bigIntToStr($num, $radix, $length) {
        if (!extension_loaded('bcmath')) {
            return $this->intToStrFallback($num, $radix, $length);
        }
        
        if (bccomp($num, '0') == 0) {
            return str_repeat('0', $length);
        }
        
        $result = '';
        $radixStr = (string)$radix;
        
        while (bccomp($num, '0') > 0) {
            // $remainder = $num % $radix
            $remainder = bcmod($num, $radixStr);
            $result = $this->valueToChar((int)$remainder) . $result;
            // $num = floor($num / $radix)
            $num = bcdiv($num, $radixStr, 0);
        }
        
        // Pad with zeros
        while (strlen($result) < $length) {
            $result = '0' . $result;
        }
        
        return $result;
    }
    
    /**
     * Fallback para quando bcmath não está disponível
     */
    private function intToStrFallback($num, $radix, $length) {
        if ($num == 0) {
            return str_repeat('0', $length);
        }
        
        $result = '';
        
        while ($num > 0) {
            $remainder = $num % $radix;
            $result = $this->valueToChar($remainder) . $result;
            $num = intdiv($num, $radix);
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
            return pow($base, $exponent);
        }
        
        $result = '1';
        $baseStr = (string)$base;
        
        for ($i = 0; $i < $exponent; $i++) {
            $result = bcmul($result, $baseStr);
        }
        
        return $result;
    }
    
    /**
     * Cipher function (AES-CBC)
     */
    private function ciph($input) {
        if (strlen($input) % self::BLOCK_SIZE != 0) {
            throw new Exception("Input length must be multiple of 16");
        }
        
        // CBC mode com IV zero
        $iv = str_repeat("\0", self::BLOCK_SIZE);
        $ciphertext = openssl_encrypt(
            $input,
            'AES-128-CBC',
            $this->aesKey,
            OPENSSL_RAW_DATA | OPENSSL_ZERO_PADDING,
            $iv
        );
        
        return $ciphertext;
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
        
        // Build P (16 bytes) - formato correto
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
            if (extension_loaded('bcmath')) {
                $bBytes = $this->bigIntToBytes($numB, $b);
            } else {
                $bBytes = $this->intToBytes($numB, $b);
            }
            
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
            if (extension_loaded('bcmath')) {
                if ($i % 2 == 0) {
                    // $numC = ($numA + $numY) % $modU
                    $sum = bcadd($numA, $numY);
                    $numC = bcmod($sum, $modU);
                } else {
                    $sum = bcadd($numA, $numY);
                    $numC = bcmod($sum, $modV);
                }
            } else {
                if ($i % 2 == 0) {
                    $numC = ($numA + $numY) % $modU;
                } else {
                    $numC = ($numA + $numY) % $modV;
                }
            }
            
            // Atualizar A e B
            $numA = $numB;
            $numB = $numC;
        }
        
        // Converter números de volta para strings
        if (extension_loaded('bcmath')) {
            $Aenc = $this->bigIntToStr($numA, $this->radix, $u);
            $Benc = $this->bigIntToStr($numB, $this->radix, $v);
        } else {
            $Aenc = $this->intToStrFallback($numA, $this->radix, $u);
            $Benc = $this->intToStrFallback($numB, $this->radix, $v);
        }
        
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
            if (extension_loaded('bcmath')) {
                $aBytes = $this->bigIntToBytes($numA, $b);
            } else {
                $aBytes = $this->intToBytes($numA, $b);
            }
            
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
            if (extension_loaded('bcmath')) {
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
            } else {
                if ($i % 2 == 0) {
                    $numC = ($numB - $numY) % $modU;
                    if ($numC < 0) {
                        $numC += $modU;
                    }
                } else {
                    $numC = ($numB - $numY) % $modV;
                    if ($numC < 0) {
                        $numC += $modV;
                    }
                }
            }
            
            // Atualizar A e B
            $numB = $numA;
            $numA = $numC;
        }
        
        // Converter números de volta para strings
        if (extension_loaded('bcmath')) {
            $Adec = $this->bigIntToStr($numA, $this->radix, $u);
            $Bdec = $this->bigIntToStr($numB, $this->radix, $v);
        } else {
            $Adec = $this->intToStrFallback($numA, $this->radix, $u);
            $Bdec = $this->intToStrFallback($numB, $this->radix, $v);
        }
        
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
            return $this->intToBytes($num, $bytes);
        }
        
        $result = '';
        $num = $num;
        
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
     * Convert integer to bytes (fallback)
     */
    private function intToBytes($num, $bytes) {
        $result = '';
        
        for ($i = $bytes - 1; $i >= 0; $i--) {
            $byte = ($num >> (8 * $i)) & 0xFF;
            $result .= chr($byte);
        }
        
        return $result;
    }
    
    /**
     * Convert bytes to big integer
     */
    private function bytesToBigInt($bytes) {
        if (!extension_loaded('bcmath')) {
            return $this->bytesToInt($bytes);
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
     * Convert bytes to integer (fallback)
     */
    private function bytesToInt($bytes) {
        $result = 0;
        $len = strlen($bytes);
        
        for ($i = 0; $i < $len; $i++) {
            $result = ($result << 8) | ord($bytes[$i]);
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
    echo "=== Test 1: Base 16 (hexadecimal) ===\n";
    
    $key1 = "0123456789abcdef"; // 16 bytes
    $tweak1 = "test";
    $plaintext1 = "deadbeef";
    
    try {
        $cipher1 = new FF1Cipher(16, strlen($tweak1), $key1, $tweak1);
        
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
    
    echo "=== Test 2: Base 10 (decimal) ===\n";
    
    $key2 = "0123456789ABCDEF"; // 16 bytes
    $tweak2 = "";
    $plaintext2 = "1234567890";
    
    try {
        $cipher2 = new FF1Cipher(10, 16, $key2, $tweak2);
        
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
    
    echo "\n=== Test 3: Base 36 ===\n";
    
    $key3 = "0123456789ABCDEF0123456789ABCDEF"; // 32 bytes
    $tweak3 = "tweak";
    $plaintext3 = "abc123xyz";
    
    try {
        $cipher3 = new FF1Cipher(36, strlen($tweak3), $key3, $tweak3);
        
        echo "minLen: " . $cipher3->getMinLength() . "\n";
        echo "maxLen: " . $cipher3->getMaxLength() . "\n\n";
        
        $encrypted3 = $cipher3->encrypt($plaintext3);
        $decrypted3 = $cipher3->decrypt($encrypted3);
        
        echo "Original text: $plaintext3\n";
        echo "Encrypted:     $encrypted3\n";
        echo "Decrypted:     $decrypted3\n";
        echo "Success: " . (($plaintext3 == $decrypted3) ? "YES" : "NO") . "\n";
        
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
    }
    
    echo "\n=== Test 4: Com tweak diferente ===\n";
    
    $tweak4 = "mytweak";
    
    try {
        // Criar um novo cipher com maxTLen maior para suportar o tweak de 7 caracteres
        $cipher4 = new FF1Cipher(16, max(16, strlen($tweak4)), $key1, $tweak1);
        
        $encrypted4 = $cipher4->encryptWithTweak($plaintext1, $tweak4);
        $decrypted4 = $cipher4->decryptWithTweak($encrypted4, $tweak4);
        
        echo "With tweak '$tweak4':\n";
        echo "  Original:  $plaintext1\n";
        echo "  Encrypted: $encrypted4\n";
        echo "  Decrypted: $decrypted4\n";
        echo "  Success: " . (($plaintext1 == $decrypted4) ? "YES" : "NO") . "\n";
        
        // Teste adicional: verificar que o mesmo texto com tweaks diferentes produz resultados diferentes
        echo "\n  Teste de unicidade do tweak:\n";
        $encrypted_with_tweak1 = $cipher4->encryptWithTweak($plaintext1, $tweak1);
        echo "  Com tweak 'test':     $encrypted_with_tweak1\n";
        echo "  Com tweak 'mytweak':  $encrypted4\n";
        echo "  São diferentes: " . (($encrypted_with_tweak1 != $encrypted4) ? "SIM ✓" : "NÃO ✗") . "\n";
        
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
    }
    
    echo "\n=== Test 5: Verificação de integridade ===\n";
    
    try {
        // Testar vários tweaks com o mesmo cipher
        $cipher5 = new FF1Cipher(16, 32, $key1, ""); // maxTLen grande o suficiente
        
        $testCases = [
            "test" => "deadbeef",
            "mytweak" => "deadbeef",
            "longertweak123" => "deadbeef",
            "" => "deadbeef",
        ];
        
        $results = [];
        foreach ($testCases as $tweak => $plaintext) {
            $encrypted = $cipher5->encryptWithTweak($plaintext, $tweak);
            $decrypted = $cipher5->decryptWithTweak($encrypted, $tweak);
            
            $results[$tweak] = [
                'encrypted' => $encrypted,
                'decrypted' => $decrypted,
                'success' => ($plaintext == $decrypted),
                'same_length' => (strlen($encrypted) == strlen($plaintext))
            ];
        }
        
        echo "Testando vários tweaks com o mesmo texto:\n";
        foreach ($results as $tweak => $result) {
            $tweakDisplay = $tweak === "" ? "(vazio)" : "'$tweak'";
            echo "  Tweak $tweakDisplay:\n";
            echo "    Criptografado: {$result['encrypted']}\n";
            echo "    Sucesso: " . ($result['success'] ? "SIM ✓" : "NÃO ✗") . "\n";
            echo "    Mesmo comprimento: " . ($result['same_length'] ? "SIM ✓" : "NÃO ✗") . "\n";
        }
        
        // Verificar que todos os resultados criptografados são diferentes
        $encryptedValues = array_column($results, 'encrypted');
        $uniqueValues = array_unique($encryptedValues);
        echo "\n  Todos os resultados são únicos: " . 
             (count($uniqueValues) == count($encryptedValues) ? "SIM ✓" : "NÃO ✗") . "\n";
        
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
