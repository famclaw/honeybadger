// Package scan provides common scanning utilities.
package scan

import (
	"unicode/utf8"
)

// IsExecutable reports whether data looks like an executable file.
// It checks for common executable magic bytes (ELF, Mach-O, PE, Wasm) or a shebang line.
func IsExecutable(data []byte) bool {
	if len(data) < 2 {
		return false
	}

	// Check for shebang (script executable)
	if data[0] == '#' && data[1] == '!' {
		return true
	}

	if len(data) < 4 {
		return false
	}

	// Check for ELF magic bytes: 0x7f 'E' 'L' 'F'
	if data[0] == 0x7f && data[1] == 'E' && data[2] == 'L' && data[3] == 'F' {
		return true
	}

	// Check for Mach-O magic bytes
	// MH_MAGIC: 0xFEEDFACE, MH_CIGAM: 0xCEFAEDFE (big/little endian)
	if (data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA && data[3] == 0xCE) ||
		(data[0] == 0xCE && data[1] == 0xFA && data[2] == 0xED && data[3] == 0xFE) {
		return true
	}
	// MH_MAGIC_64: 0xFEEDFACF, MH_CIGAM_64: 0xCFFFAEDF
	if (data[0] == 0xFE && data[1] == 0xED && data[2] == 0xFA && data[3] == 0xCF) ||
		(data[0] == 0xCF && data[1] == 0xFF && data[3] == 0xED) {
		return true
	}

	// Check for PE (Windows executable) magic bytes: 'M' 'Z'
	if data[0] == 'M' && data[1] == 'Z' {
		return true
	}

	// Check for WebAssembly magic bytes: 0x00 0x61 0x73 0x6D ("\0asm")
	if data[0] == 0x00 && data[1] == 'a' && data[2] == 's' && data[3] == 'm' {
		return true
	}

	return false
}

// IsBinary reports whether data appears to be binary (non-text).
// It returns true if a null byte is found in the first 512 bytes or if the data is not valid UTF-8.
func IsBinary(data []byte) bool {
	const scanLen = 512
	if len(data) > scanLen {
		data = data[:scanLen]
	}

	// Check for null byte
	for _, b := range data {
		if b == 0 {
			return true
		}
	}

	// Check for valid UTF-8
	if !utf8.Valid(data) {
		return true
	}

	return false
}