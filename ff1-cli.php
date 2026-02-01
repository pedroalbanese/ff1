#!/usr/bin/env php
<?php
/**
 * CLI Interface for FF1Cipher
 * Format-Preserving Encryption Command Line Tool
 */

require_once __DIR__ . '/ff1.php';

/**
 * Display help information
 */
function showHelp() {
    echo <<<HELP
FF1 Format-Preserving Encryption Tool
=====================================

Usage:
  php ff1.php encrypt [options]
  php ff1.php decrypt [options]
  php ff1.php test [options]

Commands:
  encrypt     Encrypt a message using FF1
  decrypt     Decrypt a message using FF1
  test        Run test suite

Options:
  --radix=NUM        Numeric base (2-65536, default: 10)
  --key=STRING       Encryption key (16, 24, or 32 bytes)
  --tweak=STRING     Tweak value (optional)
  --input=STRING     Input text to process
  --file=FILE        Read input from file
  --output=FILE      Write output to file
  --max-tlen=NUM     Maximum tweak length (default: 32)
  --help             Show this help message

Examples:
  php ff1.php encrypt --radix=10 --key="0123456789ABCDEF" --input="1234567890"
  php ff1.php decrypt --radix=16 --key="0123456789abcdef" --tweak="test" --input="ba9ae7de"
  php ff1.php test --radix=10 --key="0123456789ABCDEF"

HELP;
}

/**
 * Parse command line arguments
 */
function parseArgs($argv) {
    $args = [
        'command' => null,
        'radix' => 10,
        'key' => null,
        'tweak' => '',
        'input' => null,
        'file' => null,
        'output' => null,
        'max_tlen' => 32,
        'help' => false
    ];
    
    if (count($argv) < 2) {
        return $args;
    }
    
    $args['command'] = $argv[1];
    
    for ($i = 2; $i < count($argv); $i++) {
        $arg = $argv[$i];
        
        if ($arg === '--help' || $arg === '-h') {
            $args['help'] = true;
            continue;
        }
        
        if (strpos($arg, '--') === 0) {
            $parts = explode('=', $arg, 2);
            $key = substr($parts[0], 2);
            $value = isset($parts[1]) ? $parts[1] : true;
            
            switch ($key) {
                case 'radix':
                    $args['radix'] = (int)$value;
                    break;
                case 'key':
                    $args['key'] = $value;
                    break;
                case 'tweak':
                    $args['tweak'] = $value;
                    break;
                case 'input':
                    $args['input'] = $value;
                    break;
                case 'file':
                    $args['file'] = $value;
                    break;
                case 'output':
                    $args['output'] = $value;
                    break;
                case 'max-tlen':
                    $args['max_tlen'] = (int)$value;
                    break;
            }
        }
    }
    
    return $args;
}

/**
 * Read input from file or stdin
 */
function readInput($args) {
    if ($args['file']) {
        if (!file_exists($args['file'])) {
            throw new Exception("File not found: " . $args['file']);
        }
        return trim(file_get_contents($args['file']));
    }
    
    if ($args['input']) {
        return $args['input'];
    }
    
    // Read from stdin if no input specified
    echo "Enter text (press Ctrl+D when done):\n";
    $input = '';
    while (!feof(STDIN)) {
        $input .= fread(STDIN, 1024);
    }
    return trim($input);
}

/**
 * Write output to file or stdout
 */
function writeOutput($output, $args) {
    if ($args['output']) {
        file_put_contents($args['output'], $output);
        echo "Output written to: " . $args['output'] . "\n";
    } else {
        echo $output . "\n";
    }
}

/**
 * Validate input parameters
 */
function validateArgs($args) {
    if ($args['help']) {
        return true;
    }
    
    if (!in_array($args['command'], ['encrypt', 'decrypt', 'test'])) {
        throw new Exception("Invalid command. Use 'encrypt', 'decrypt', or 'test'");
    }
    
    if (!$args['key'] && $args['command'] !== 'test') {
        throw new Exception("Encryption key is required");
    }
    
    if ($args['radix'] < 2 || $args['radix'] > 65536) {
        throw new Exception("Radix must be between 2 and 65536");
    }
    
    if ($args['max_tlen'] < strlen($args['tweak'])) {
        throw new Exception("Tweak length exceeds maximum allowed");
    }
    
    return true;
}

/**
 * Encrypt command
 */
function commandEncrypt($args) {
    $input = readInput($args);
    
    if (empty($input)) {
        throw new Exception("No input provided");
    }
    
    $cipher = new FF1Cipher(
        $args['radix'],
        $args['max_tlen'],
        $args['key'],
        $args['tweak']
    );
    
    $encrypted = $cipher->encrypt($input);
    
    if ($args['output']) {
        writeOutput($encrypted, $args);
    } else {
        echo "Encrypted text: " . $encrypted . "\n";
        echo "Length: " . strlen($encrypted) . " characters\n";
    }
    
    return $encrypted;
}

/**
 * Decrypt command
 */
function commandDecrypt($args) {
    $input = readInput($args);
    
    if (empty($input)) {
        throw new Exception("No input provided");
    }
    
    $cipher = new FF1Cipher(
        $args['radix'],
        $args['max_tlen'],
        $args['key'],
        $args['tweak']
    );
    
    $decrypted = $cipher->decrypt($input);
    
    if ($args['output']) {
        writeOutput($decrypted, $args);
    } else {
        echo "Decrypted text: " . $decrypted . "\n";
        echo "Length: " . strlen($decrypted) . " characters\n";
    }
    
    return $decrypted;
}

/**
 * Test command
 */
function commandTest($args) {
    echo "=== FF1Cipher Test Suite ===\n\n";
    
    $testKey = $args['key'] ? $args['key'] : "0123456789ABCDEF";
    $testRadix = $args['radix'];
    $testTweak = $args['tweak'];
    
    $tests = [
        [
            'name' => 'Basic encryption/decryption',
            'radix' => $testRadix,
            'key' => $testKey,
            'tweak' => $testTweak,
            'plaintext' => '1234567890'
        ],
        [
            'name' => 'Hexadecimal',
            'radix' => 16,
            'key' => '0123456789abcdef',
            'tweak' => 'test',
            'plaintext' => 'deadbeef'
        ],
        [
            'name' => 'Base 36',
            'radix' => 36,
            'key' => '0123456789ABCDEF0123456789ABCDEF',
            'tweak' => 'tweak',
            'plaintext' => 'abc123xyz'
        ],
        [
            'name' => 'Different tweaks',
            'radix' => 10,
            'key' => $testKey,
            'tweak' => '',
            'plaintext' => '9876543210'
        ]
    ];
    
    $allPassed = true;
    
    foreach ($tests as $test) {
        echo "Test: {$test['name']}\n";
        echo "  Radix: {$test['radix']}\n";
        echo "  Plaintext: {$test['plaintext']}\n";
        
        try {
            $cipher = new FF1Cipher(
                $test['radix'],
                max(32, strlen($test['tweak'])),
                $test['key'],
                $test['tweak']
            );
            
            $encrypted = $cipher->encrypt($test['plaintext']);
            $decrypted = $cipher->decrypt($encrypted);
            
            $passed = ($test['plaintext'] === $decrypted);
            $allPassed = $allPassed && $passed;
            
            echo "  Encrypted: $encrypted\n";
            echo "  Decrypted: $decrypted\n";
            echo "  Status: " . ($passed ? "✓ PASS" : "✗ FAIL") . "\n\n";
            
        } catch (Exception $e) {
            echo "  Error: " . $e->getMessage() . "\n";
            echo "  Status: ✗ FAIL\n\n";
            $allPassed = false;
        }
    }
    
    // Additional consistency tests
    echo "=== Additional Tests ===\n\n";
    
    // Test same input with different tweaks produces different output
    echo "Test: Tweak uniqueness\n";
    try {
        $cipher = new FF1Cipher(10, 32, $testKey, '');
        $plaintext = '1234567890';
        
        $results = [];
        $tweaks = ['', 'tweak1', 'tweak2', 'longertweak'];
        
        foreach ($tweaks as $tweak) {
            $encrypted = $cipher->encryptWithTweak($plaintext, $tweak);
            $decrypted = $cipher->decryptWithTweak($encrypted, $tweak);
            
            $results[$tweak] = [
                'encrypted' => $encrypted,
                'decrypted' => $decrypted,
                'valid' => ($plaintext === $decrypted)
            ];
        }
        
        // Check all decryptions are correct
        $allValid = true;
        foreach ($results as $tweak => $result) {
            if (!$result['valid']) {
                $allValid = false;
                break;
            }
        }
        
        // Check all encrypted results are different
        $encryptedValues = array_column($results, 'encrypted');
        $uniqueValues = array_unique($encryptedValues);
        $allUnique = (count($uniqueValues) === count($encryptedValues));
        
        echo "  All decryptions correct: " . ($allValid ? "✓ YES" : "✗ NO") . "\n";
        echo "  All outputs unique: " . ($allUnique ? "✓ YES" : "✗ NO") . "\n";
        echo "  Status: " . (($allValid && $allUnique) ? "✓ PASS" : "✗ FAIL") . "\n\n";
        
        $allPassed = $allPassed && $allValid && $allUnique;
        
    } catch (Exception $e) {
        echo "  Error: " . $e->getMessage() . "\n";
        echo "  Status: ✗ FAIL\n\n";
        $allPassed = false;
    }
    
    // Test length preservation
    echo "Test: Length preservation\n";
    try {
        $cipher = new FF1Cipher(10, 32, $testKey, '');
        $testCases = ['1', '12', '123', '1234', '12345', '123456'];
        
        $allPreserved = true;
        foreach ($testCases as $plaintext) {
            $encrypted = $cipher->encrypt($plaintext);
            if (strlen($encrypted) !== strlen($plaintext)) {
                $allPreserved = false;
                echo "  FAIL: '{$plaintext}' => '{$encrypted}' (length changed)\n";
            }
        }
        
        echo "  All lengths preserved: " . ($allPreserved ? "✓ YES" : "✗ NO") . "\n";
        echo "  Status: " . ($allPreserved ? "✓ PASS" : "✗ FAIL") . "\n\n";
        
        $allPassed = $allPassed && $allPreserved;
        
    } catch (Exception $e) {
        echo "  Error: " . $e->getMessage() . "\n";
        echo "  Status: ✗ FAIL\n\n";
        $allPassed = false;
    }
    
    // Summary
    echo "=== Test Summary ===\n";
    echo "Overall result: " . ($allPassed ? "✓ ALL TESTS PASSED" : "✗ SOME TESTS FAILED") . "\n";
    
    return $allPassed;
}

/**
 * Interactive mode
 */
function interactiveMode() {
    echo "=== FF1Cipher Interactive Mode ===\n\n";
    
    // Get parameters
    echo "Enter parameters:\n";
    
    echo "Radix (2-65536, default 10): ";
    $radix = trim(fgets(STDIN));
    $radix = empty($radix) ? 10 : (int)$radix;
    
    echo "Encryption key (16, 24, or 32 bytes): ";
    $key = trim(fgets(STDIN));
    
    echo "Tweak (optional, press Enter to skip): ";
    $tweak = trim(fgets(STDIN));
    
    echo "Max tweak length (default 32): ";
    $maxTlen = trim(fgets(STDIN));
    $maxTlen = empty($maxTlen) ? 32 : (int)$maxTlen;
    
    // Create cipher
    try {
        $cipher = new FF1Cipher($radix, $maxTlen, $key, $tweak);
        echo "\nCipher created successfully!\n";
        echo "Min length: " . $cipher->getMinLength() . "\n";
        echo "Max length: " . $cipher->getMaxLength() . "\n\n";
    } catch (Exception $e) {
        echo "Error creating cipher: " . $e->getMessage() . "\n";
        return;
    }
    
    // Main loop
    while (true) {
        echo "\nChoose operation:\n";
        echo "1. Encrypt\n";
        echo "2. Decrypt\n";
        echo "3. Change parameters\n";
        echo "4. Exit\n";
        echo "Choice: ";
        
        $choice = trim(fgets(STDIN));
        
        switch ($choice) {
            case '1':
                echo "Enter text to encrypt: ";
                $plaintext = trim(fgets(STDIN));
                try {
                    $encrypted = $cipher->encrypt($plaintext);
                    echo "Encrypted: $encrypted\n";
                    echo "Length: " . strlen($encrypted) . " characters\n";
                } catch (Exception $e) {
                    echo "Error: " . $e->getMessage() . "\n";
                }
                break;
                
            case '2':
                echo "Enter text to decrypt: ";
                $ciphertext = trim(fgets(STDIN));
                try {
                    $decrypted = $cipher->decrypt($ciphertext);
                    echo "Decrypted: $decrypted\n";
                    echo "Length: " . strlen($decrypted) . " characters\n";
                } catch (Exception $e) {
                    echo "Error: " . $e->getMessage() . "\n";
                }
                break;
                
            case '3':
                return; // Restart interactive mode
                
            case '4':
                echo "Goodbye!\n";
                exit(0);
                
            default:
                echo "Invalid choice.\n";
        }
    }
}

/**
 * Main CLI entry point
 */
function mainCLI($argv) {
    // Check if running in CLI
    if (PHP_SAPI !== 'cli') {
        die("This script must be run from the command line.\n");
    }
    
    // Parse arguments
    $args = parseArgs($argv);
    
    // Show help if requested or no command provided
    if ($args['help'] || !$args['command']) {
        showHelp();
        
        // If no command but we have a key, offer interactive mode
        if (!$args['command'] && $args['key']) {
            echo "\nWould you like to enter interactive mode? (y/n): ";
            $response = trim(fgets(STDIN));
            if (strtolower($response) === 'y') {
                interactiveMode();
            }
        }
        exit(0);
    }
    
    try {
        // Validate arguments
        validateArgs($args);
        
        // Execute command
        switch ($args['command']) {
            case 'encrypt':
                commandEncrypt($args);
                break;
                
            case 'decrypt':
                commandDecrypt($args);
                break;
                
            case 'test':
                commandTest($args);
                break;
                
            default:
                showHelp();
                exit(1);
        }
        
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage() . "\n";
        echo "Use --help for usage information.\n";
        exit(1);
    }
}

// Run the CLI application
if (isset($argv)) {
    mainCLI($argv);
}
