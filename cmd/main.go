package main

import (
	"bufio"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"

	ff1 "github.com/pedroalbanese/ff1"
)

const (
	defaultRadix   = 10
	defaultMaxTLen = 32
	version        = "1.0.0"
)

// Config holds the command-line configuration
type Config struct {
	command     string
	radix       int
	key         string
	tweak       string
	input       string
	file        string
	output      string
	maxTLen     int
	help        bool
	version     bool
	interactive bool
}

// Display help information
func showHelp() {
	fmt.Printf(`FF1 Format-Preserving Encryption Tool
=====================================

Usage:
  ff1 encrypt [options]
  ff1 decrypt [options]
  ff1 test [options]
  ff1 interactive

Commands:
  encrypt      Encrypt a message using FF1
  decrypt      Decrypt a message using FF1
  test         Run test suite
  interactive  Enter interactive mode

Options:
  --radix=NUM        Numeric base (2-65536, default: %d)
  --key=STRING       Encryption key (16, 24, or 32 bytes)
  --tweak=STRING     Tweak value (optional)
  --input=STRING     Input text to process
  --file=FILE        Read input from file
  --output=FILE      Write output to file
  --max-tlen=NUM     Maximum tweak length (default: %d)
  --help             Show this help message
  --version          Show version information
  --interactive      Enter interactive mode

Examples:
  ff1 encrypt --radix=10 --key="0123456789ABCDEF" --input="1234567890"
  ff1 decrypt --radix=16 --key="0123456789abcdef" --tweak="test" --input="ba9ae7de"
  ff1 test --radix=10 --key="0123456789ABCDEF"
  ff1 interactive
`, defaultRadix, defaultMaxTLen)
}

// Parse command line arguments
func parseArgs() Config {
	config := Config{
		radix:   defaultRadix,
		maxTLen: defaultMaxTLen,
	}

	if len(os.Args) < 2 {
		return config
	}

	config.command = os.Args[1]

	// Create flag set
	fs := flag.NewFlagSet(os.Args[0], flag.ExitOnError)
	fs.IntVar(&config.radix, "radix", defaultRadix, "Numeric base (2-65536)")
	fs.StringVar(&config.key, "key", "", "Encryption key (16, 24, or 32 bytes)")
	fs.StringVar(&config.tweak, "tweak", "", "Tweak value (optional)")
	fs.StringVar(&config.input, "input", "", "Input text to process")
	fs.StringVar(&config.file, "file", "", "Read input from file")
	fs.StringVar(&config.output, "output", "", "Write output to file")
	fs.IntVar(&config.maxTLen, "max-tlen", defaultMaxTLen, "Maximum tweak length")
	fs.BoolVar(&config.help, "help", false, "Show help message")
	fs.BoolVar(&config.version, "version", false, "Show version information")
	fs.BoolVar(&config.interactive, "interactive", false, "Enter interactive mode")

	// Parse flags starting from position 2
	if len(os.Args) > 2 {
		fs.Parse(os.Args[2:])
	}

	// If interactive flag is set, override command
	if config.interactive {
		config.command = "interactive"
	}

	return config
}

// Read input from file or stdin
func readInput(config Config) (string, error) {
	if config.file != "" {
		data, err := os.ReadFile(config.file)
		if err != nil {
			return "", fmt.Errorf("file not found: %s", config.file)
		}
		return strings.TrimSpace(string(data)), nil
	}

	if config.input != "" {
		return config.input, nil
	}

	// Read from stdin if no input specified
	fmt.Println("Enter text (press Ctrl+D when done):")
	var input strings.Builder
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		input.WriteString(scanner.Text())
		input.WriteString("\n")
	}

	// Remove trailing newline
	text := input.String()
	if len(text) > 0 && text[len(text)-1] == '\n' {
		text = text[:len(text)-1]
	}

	return text, scanner.Err()
}

// Write output to file or stdout
func writeOutput(output string, config Config) error {
	if config.output != "" {
		err := os.WriteFile(config.output, []byte(output), 0644)
		if err != nil {
			return fmt.Errorf("failed to write output file: %w", err)
		}
		fmt.Printf("Output written to: %s\n", config.output)
	} else {
		fmt.Println(output)
	}
	return nil
}

// Validate input parameters
func validateConfig(config Config) error {
	if config.help {
		return nil
	}

	if !contains([]string{"encrypt", "decrypt", "test", "interactive"}, config.command) {
		return fmt.Errorf("invalid command. Use 'encrypt', 'decrypt', 'test', or 'interactive'")
	}

	if config.command != "test" && config.command != "interactive" && config.key == "" {
		return fmt.Errorf("encryption key is required")
	}

	if config.radix < 2 || config.radix > 65536 {
		return fmt.Errorf("radix must be between 2 and 65536")
	}

	if config.maxTLen < len(config.tweak) {
		return fmt.Errorf("tweak length exceeds maximum allowed")
	}

	return nil
}

// Helper function to check if slice contains value
func contains(slice []string, value string) bool {
	for _, v := range slice {
		if v == value {
			return true
		}
	}
	return false
}

// Encrypt command
func commandEncrypt(config Config) error {
	input, err := readInput(config)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	if input == "" {
		return fmt.Errorf("no input provided")
	}

	cipher, err := ff1.NewCipher(config.radix, config.maxTLen, []byte(config.key), []byte(config.tweak))
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	encrypted, err := cipher.Encrypt(input)
	if err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	if config.output != "" {
		err = writeOutput(encrypted, config)
		if err != nil {
			return err
		}
	} else {
		fmt.Printf("Encrypted text: %s\n", encrypted)
		fmt.Printf("Length: %d characters\n", len(encrypted))
	}

	return nil
}

// Decrypt command
func commandDecrypt(config Config) error {
	input, err := readInput(config)
	if err != nil {
		return fmt.Errorf("failed to read input: %w", err)
	}

	if input == "" {
		return fmt.Errorf("no input provided")
	}

	cipher, err := ff1.NewCipher(config.radix, config.maxTLen, []byte(config.key), []byte(config.tweak))
	if err != nil {
		return fmt.Errorf("failed to create cipher: %w", err)
	}

	decrypted, err := cipher.Decrypt(input)
	if err != nil {
		return fmt.Errorf("decryption failed: %w", err)
	}

	if config.output != "" {
		err = writeOutput(decrypted, config)
		if err != nil {
			return err
		}
	} else {
		fmt.Printf("Decrypted text: %s\n", decrypted)
		fmt.Printf("Length: %d characters\n", len(decrypted))
	}

	return nil
}

// Test command
func commandTest(config Config) error {
	fmt.Println("=== FF1 Cipher Test Suite ===")

	testKey := config.key
	if testKey == "" {
		testKey = "0123456789ABCDEF"
	}
	testRadix := config.radix
	testTweak := config.tweak

	tests := []struct {
		name      string
		radix     int
		key       string
		tweak     string
		plaintext string
	}{
		{
			name:      "Basic encryption/decryption",
			radix:     testRadix,
			key:       testKey,
			tweak:     testTweak,
			plaintext: "1234567890",
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
			plaintext: "abc123xyz",
		},
		{
			name:      "Different tweaks",
			radix:     10,
			key:       testKey,
			tweak:     "",
			plaintext: "9876543210",
		},
	}

	allPassed := true

	for _, test := range tests {
		fmt.Printf("\nTest: %s\n", test.name)
		fmt.Printf("  Radix: %d\n", test.radix)
		fmt.Printf("  Plaintext: %s\n", test.plaintext)

		cipher, err := ff1.NewCipher(test.radix, max(32, len(test.tweak)), []byte(test.key), []byte(test.tweak))
		if err != nil {
			fmt.Printf("  Error creating cipher: %v\n", err)
			fmt.Printf("  Status: ✗ FAIL\n")
			allPassed = false
			continue
		}

		encrypted, err := cipher.Encrypt(test.plaintext)
		if err != nil {
			fmt.Printf("  Error encrypting: %v\n", err)
			fmt.Printf("  Status: ✗ FAIL\n")
			allPassed = false
			continue
		}

		decrypted, err := cipher.Decrypt(encrypted)
		if err != nil {
			fmt.Printf("  Error decrypting: %v\n", err)
			fmt.Printf("  Status: ✗ FAIL\n")
			allPassed = false
			continue
		}

		passed := test.plaintext == decrypted
		allPassed = allPassed && passed

		fmt.Printf("  Encrypted: %s\n", encrypted)
		fmt.Printf("  Decrypted: %s\n", decrypted)
		if passed {
			fmt.Printf("  Status: ✓ PASS\n")
		} else {
			fmt.Printf("  Status: ✗ FAIL\n")
		}
	}

	// Additional consistency tests
	fmt.Println("\n=== Additional Tests ===")

	// Test same input with different tweaks produces different output
	fmt.Println("\nTest: Tweak uniqueness")
	cipher, err := ff1.NewCipher(10, 32, []byte(testKey), []byte(""))
	if err != nil {
		fmt.Printf("  Error creating cipher: %v\n", err)
		fmt.Printf("  Status: ✗ FAIL\n")
		allPassed = false
	} else {
		plaintext := "1234567890"
		results := make(map[string]struct {
			encrypted string
			decrypted string
			valid     bool
		})
		tweaks := []string{"", "tweak1", "tweak2", "longertweak"}

		for _, tweak := range tweaks {
			encrypted, err := cipher.EncryptWithTweak(plaintext, []byte(tweak))
			if err != nil {
				fmt.Printf("  Error with tweak '%s': %v\n", tweak, err)
				allPassed = false
				continue
			}

			decrypted, err := cipher.DecryptWithTweak(encrypted, []byte(tweak))
			if err != nil {
				fmt.Printf("  Error decrypting with tweak '%s': %v\n", tweak, err)
				allPassed = false
				continue
			}

			results[tweak] = struct {
				encrypted string
				decrypted string
				valid     bool
			}{
				encrypted: encrypted,
				decrypted: decrypted,
				valid:     plaintext == decrypted,
			}
		}

		// Check all decryptions are correct
		allValid := true
		encryptedValues := make([]string, 0, len(results))
		for tweak, result := range results {
			if !result.valid {
				allValid = false
				fmt.Printf("  Decryption failed for tweak '%s'\n", tweak)
			}
			encryptedValues = append(encryptedValues, result.encrypted)
		}

		// Check all encrypted results are different
		uniqueValues := make(map[string]bool)
		for _, val := range encryptedValues {
			uniqueValues[val] = true
		}
		allUnique := len(uniqueValues) == len(encryptedValues)

		if allValid {
			fmt.Printf("  All decryptions correct: ✓ YES\n")
		} else {
			fmt.Printf("  All decryptions correct: ✗ NO\n")
		}
		if allUnique {
			fmt.Printf("  All outputs unique: ✓ YES\n")
		} else {
			fmt.Printf("  All outputs unique: ✗ NO\n")
		}
		if allValid && allUnique {
			fmt.Printf("  Status: ✓ PASS\n")
		} else {
			fmt.Printf("  Status: ✗ FAIL\n")
		}

		allPassed = allPassed && allValid && allUnique
	}

	// Test length preservation
	fmt.Println("\nTest: Length preservation")
	cipher2, err := ff1.NewCipher(10, 32, []byte(testKey), []byte(""))
	if err != nil {
		fmt.Printf("  Error creating cipher: %v\n", err)
		fmt.Printf("  Status: ✗ FAIL\n")
		allPassed = false
	} else {
		testCases := []string{"1", "12", "123", "1234", "12345", "123456"}
		allPreserved := true

		for _, plaintext := range testCases {
			encrypted, err := cipher2.Encrypt(plaintext)
			if err != nil {
				allPreserved = false
				fmt.Printf("  Error encrypting '%s': %v\n", plaintext, err)
				continue
			}
			if len(encrypted) != len(plaintext) {
				allPreserved = false
				fmt.Printf("  FAIL: '%s' => '%s' (length changed %d -> %d)\n",
					plaintext, encrypted, len(plaintext), len(encrypted))
			}
		}

		if allPreserved {
			fmt.Printf("  All lengths preserved: ✓ YES\n")
			fmt.Printf("  Status: ✓ PASS\n")
		} else {
			fmt.Printf("  All lengths preserved: ✗ NO\n")
			fmt.Printf("  Status: ✗ FAIL\n")
		}

		allPassed = allPassed && allPreserved
	}

	// Summary
	fmt.Println("\n=== Test Summary ===")
	if allPassed {
		fmt.Println("Overall result: ✓ ALL TESTS PASSED")
	} else {
		fmt.Println("Overall result: ✗ SOME TESTS FAILED")
	}

	return nil
}

// Interactive mode
func commandInteractive() error {
	reader := bufio.NewReader(os.Stdin)

	fmt.Println("=== FF1 Cipher Interactive Mode ===")

	// Get parameters
	fmt.Println("\nEnter parameters:")

	fmt.Print("Radix (2-65536, default 10): ")
	radixStr, _ := reader.ReadString('\n')
	radixStr = strings.TrimSpace(radixStr)
	radix := defaultRadix
	if radixStr != "" {
		var err error
		radix, err = strconv.Atoi(radixStr)
		if err != nil || radix < 2 || radix > 65536 {
			return fmt.Errorf("invalid radix: %s", radixStr)
		}
	}

	fmt.Print("Encryption key (16, 24, or 32 bytes): ")
	key, _ := reader.ReadString('\n')
	key = strings.TrimSpace(key)

	fmt.Print("Tweak (optional, press Enter to skip): ")
	tweak, _ := reader.ReadString('\n')
	tweak = strings.TrimSpace(tweak)

	fmt.Print("Max tweak length (default 32): ")
	maxTlenStr, _ := reader.ReadString('\n')
	maxTlenStr = strings.TrimSpace(maxTlenStr)
	maxTlen := defaultMaxTLen
	if maxTlenStr != "" {
		var err error
		maxTlen, err = strconv.Atoi(maxTlenStr)
		if err != nil || maxTlen < 0 {
			return fmt.Errorf("invalid max tweak length: %s", maxTlenStr)
		}
	}

	// Create cipher
	cipher, err := ff1.NewCipher(radix, maxTlen, []byte(key), []byte(tweak))
	if err != nil {
		return fmt.Errorf("error creating cipher: %w", err)
	}

	fmt.Printf("\nCipher created successfully!\n")
	fmt.Printf("Min length: %d\n", getMinLength(radix))
	fmt.Printf("Max length: %d\n\n", getMaxLength())

	// Main loop
	for {
		fmt.Println("\nChoose operation:")
		fmt.Println("1. Encrypt")
		fmt.Println("2. Decrypt")
		fmt.Println("3. Change parameters")
		fmt.Println("4. Exit")
		fmt.Print("Choice: ")

		choiceStr, _ := reader.ReadString('\n')
		choice := strings.TrimSpace(choiceStr)

		switch choice {
		case "1":
			fmt.Print("Enter text to encrypt: ")
			plaintext, _ := reader.ReadString('\n')
			plaintext = strings.TrimSpace(plaintext)

			encrypted, err := cipher.Encrypt(plaintext)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Printf("Encrypted: %s\n", encrypted)
				fmt.Printf("Length: %d characters\n", len(encrypted))
			}

		case "2":
			fmt.Print("Enter text to decrypt: ")
			ciphertext, _ := reader.ReadString('\n')
			ciphertext = strings.TrimSpace(ciphertext)

			decrypted, err := cipher.Decrypt(ciphertext)
			if err != nil {
				fmt.Printf("Error: %v\n", err)
			} else {
				fmt.Printf("Decrypted: %s\n", decrypted)
				fmt.Printf("Length: %d characters\n", len(decrypted))
			}

		case "3":
			return commandInteractive() // Restart interactive mode

		case "4":
			fmt.Println("Goodbye!")
			return nil

		default:
			fmt.Println("Invalid choice.")
		}
	}
}

// Helper functions
func getMinLength(radix int) uint32 {
	minLen := uint32(math.Ceil(math.Log(100) / math.Log(float64(radix))))
	if minLen < 2 {
		minLen = 2
	}
	return minLen
}

func getMaxLength() uint32 {
	return math.MaxUint32
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

// Main CLI entry point
func main() {
	config := parseArgs()

	if config.version {
		fmt.Printf("FF1 CLI Tool v%s\n", version)
		return
	}

	if config.help || config.command == "" {
		showHelp()

		// If no command but we have a key, offer interactive mode
		if config.command == "" && config.key != "" {
			fmt.Print("\nWould you like to enter interactive mode? (y/n): ")
			reader := bufio.NewReader(os.Stdin)
			response, _ := reader.ReadString('\n')
			if strings.ToLower(strings.TrimSpace(response)) == "y" {
				config.command = "interactive"
			} else {
				return
			}
		} else if config.command == "" {
			return
		}
	}

	err := validateConfig(config)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		fmt.Println("Use --help for usage information.")
		os.Exit(1)
	}

	var executionErr error
	switch config.command {
	case "encrypt":
		executionErr = commandEncrypt(config)
	case "decrypt":
		executionErr = commandDecrypt(config)
	case "test":
		executionErr = commandTest(config)
	case "interactive":
		executionErr = commandInteractive()
	default:
		showHelp()
		os.Exit(1)
	}

	if executionErr != nil {
		fmt.Printf("Error: %v\n", executionErr)
		os.Exit(1)
	}
}
