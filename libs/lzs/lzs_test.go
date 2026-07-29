package lzs

import (
	"testing"
)

func TestDecompress_Empty(t *testing.T) {
	result, err := Decompress(nil)
	if err != nil {
		t.Fatalf("Decompress(nil) error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty output, got %d bytes", len(result))
	}

	result, err = Decompress([]byte{})
	if err != nil {
		t.Fatalf("Decompress([]) error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty output, got %d bytes", len(result))
	}
}

func TestDecompress_LiteralBytes(t *testing.T) {
	// Encode "A" (0x41 = 01000001) as a single literal byte.
	// Format: 0 (literal flag) + 01000001 (8 data bits) = 9 bits.
	// Bits (MSB first): 0 0 1 0 0 0 0 0 1
	// Packed into bytes: 0x20, 0x80
	input := []byte{0x20, 0x80}

	result, err := Decompress(input)
	if err != nil {
		t.Fatalf("Decompress() error: %v", err)
	}
	if len(result) != 1 {
		t.Fatalf("expected 1 byte, got %d: %v", len(result), result)
	}
	if result[0] != 'A' {
		t.Errorf("expected 'A' (0x41), got 0x%02X", result[0])
	}
}

func TestDecompress_TwoLiterals(t *testing.T) {
	// Encode "AB" as two literal bytes.
	// "A": 0 (literal) + 01000001 = 9 bits
	// "B": 0 (literal) + 01000010 = 9 bits
	// Total: 18 bits
	// Full stream: 0,0,1,0,0,0,0,0,1, 0,0,1,0,0,0,0,1,0
	// Byte 0 (bits 0-7):   00100000 = 0x20
	// Byte 1 (bits 8-15):  10010000 = 0x90
	// Byte 2 (bits 16-17): 10.. = 0x80
	input := []byte{0x20, 0x90, 0x80}

	result, err := Decompress(input)
	if err != nil {
		t.Fatalf("Decompress() error: %v", err)
	}
	if len(result) != 2 {
		t.Fatalf("expected 2 bytes, got %d: %v", len(result), result)
	}
	if string(result) != "AB" {
		t.Errorf("expected 'AB', got %q", string(result))
	}
}

func TestDecompress_BackReference(t *testing.T) {
	// Encode "AAA": first 'A' as literal, second+third via back-reference.
	//
	// Byte 0: literal 'A': 0 + 01000001 (9 bits)
	// Bytes 1-2: back-ref: 1 (flag) + 1 (short offset) + 0000001 (offset=1) + 00 (lenField=0 → length=2)
	// Total: 20 bits
	//
	// Stream: 0,0,1,0,0,0,0,0,1,  1,1,  0,0,0,0,0,0,1,  0,0
	// Byte 0 (bits 0-7):   00100000 = 0x20
	// Byte 1 (bits 8-15):  11100000 = 0xE0
	// Byte 2 (bits 16-19): 0100.... = 0x40
	input := []byte{0x20, 0xE0, 0x40}

	result, err := Decompress(input)
	if err != nil {
		t.Fatalf("Decompress() error: %v", err)
	}
	if len(result) < 3 {
		t.Errorf("expected at least 3 bytes, got %d: %v", len(result), result)
	}
	if string(result) != "AAA" {
		t.Errorf("expected 'AAA', got %q", string(result))
	}
}

func TestDecompress_ValidateNotEmpty(t *testing.T) {
	err := ValidateDecompress([]byte{0x20, 0x80}, []byte{})
	if err == nil {
		t.Error("ValidateDecompress should error on empty decompressed output")
	}
}

func TestDecompress_ValidateUnreasonable(t *testing.T) {
	input := make([]byte, 10)
	output := make([]byte, 2000)
	err := ValidateDecompress(input, output)
	if err == nil {
		t.Error("ValidateDecompress should error on unreasonable expansion")
	}
}

func TestDecompress_ValidateOK(t *testing.T) {
	err := ValidateDecompress([]byte{0x20, 0x80}, []byte("A"))
	if err != nil {
		t.Errorf("ValidateDecompress should not error: %v", err)
	}
}

func TestDecompressChunk(t *testing.T) {
	// Create input where valid data starts at offset 4
	input := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x20, 0x80}
	result, err := DecompressChunk(input, 4)
	if err != nil {
		t.Fatalf("DecompressChunk() error: %v", err)
	}
	if len(result) != 1 || result[0] != 'A' {
		t.Errorf("expected 'A', got %q", string(result))
	}
}

func TestDecompressChunk_OffsetOutOfBounds(t *testing.T) {
	result, err := DecompressChunk([]byte{0x20, 0x80}, 10)
	if err != nil {
		t.Fatalf("DecompressChunk() error: %v", err)
	}
	if len(result) != 0 {
		t.Errorf("expected empty output, got %d bytes", len(result))
	}
}

func TestBitReader_ReadBit(t *testing.T) {
	reader := newBitReader([]byte{0x80}) // 10000000
	bit, ok := reader.readBit()
	if !ok || !bit {
		t.Error("first bit should be 1 (true)")
	}
	bit, ok = reader.readBit()
	if !ok || bit {
		t.Error("second bit should be 0 (false)")
	}
}

func TestBitReader_ReadBits(t *testing.T) {
	reader := newBitReader([]byte{0xFF, 0xFF})
	value, ok := reader.readBits(16)
	if !ok {
		t.Fatal("readBits(16) failed")
	}
	if value != 0xFFFF {
		t.Errorf("readBits(16) = 0x%04X, want 0xFFFF", value)
	}
}

func TestBitReader_ReadByte(t *testing.T) {
	reader := newBitReader([]byte{0x41}) // 'A'
	byteValue, ok := reader.readByte()
	if !ok {
		t.Fatal("readByte() failed")
	}
	if byteValue != 0x41 {
		t.Errorf("readByte() = 0x%02X, want 0x41", byteValue)
	}
}

func TestBitReader_Exhausted(t *testing.T) {
	reader := newBitReader([]byte{0xFF})
	reader.readBits(8) // Consume all
	_, ok := reader.readBit()
	if ok {
		t.Error("readBit() should return false when exhausted")
	}
}
