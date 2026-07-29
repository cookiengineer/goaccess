package lzs

import "fmt"

// ringBuffer implements a fixed-size ring buffer for the LZS sliding window.
// It records bytes in insertion order, allowing access from the end via negative offset.
type ringBuffer struct {
	data    []byte
	size    int // logical number of elements (≤ capacity)
	writePos int
	capacity int
}

func newRingBuffer(capacity int) *ringBuffer {
	return &ringBuffer{
		data:     make([]byte, capacity),
		capacity: capacity,
	}
}

func (buffer *ringBuffer) append(byteValue byte) {
	buffer.data[buffer.writePos] = byteValue
	buffer.writePos = (buffer.writePos + 1) % buffer.capacity
	if buffer.size < buffer.capacity {
		buffer.size++
	}
}

// getFromEnd returns the element at distance offset from the end.
// offset=1 returns the last element, offset=2 returns second-to-last, etc.
func (buffer *ringBuffer) getFromEnd(offset int) byte {
	// The last element is at writePos-1.
	// The element offset positions from the end is at writePos-offset.
	index := (buffer.writePos - offset) % buffer.capacity
	if index < 0 {
		index += buffer.capacity
	}
	return buffer.data[index]
}

// Decompress performs LZS (Lempel-Ziv-Stac) decompression on the input data.
//
// The algorithm uses a bit-stream reader and a 2048-byte sliding window.
// This is a direct port of the Python implementation from RouterSploit.
//
// The format encodes:
//   - Literal bytes: preceded by a 0 bit, followed by 8 bits of data
//   - Back-references: preceded by a 1 bit, with variable-length offset
//     (11 bits for short, 7 bits for long) and variable-length length encoding
func Decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}

	reader := newBitReader(data)
	result := make([]byte, 0, len(data)*2)
	window := newRingBuffer(2048)

	for {
		bit, ok := reader.readBit()
		if !ok {
			break
		}

		if !bit {
			// Literal byte
			byteValue, ok := reader.readByte()
			if !ok {
				break
			}
			result = append(result, byteValue)
			window.append(byteValue)
		} else {
			// Back-reference
			secondBit, ok := reader.readBit()
			if !ok {
				break
			}

			var offset int

			if secondBit {
				// Short offset: 7 bits
				shortOffset, ok := reader.readBits(7)
				if !ok {
					break
				}
				if shortOffset == 0 {
					break // EOF
				}
				offset = shortOffset
			} else {
				// Long offset: 11 bits
				longOffset, ok := reader.readBits(11)
				if !ok {
					break
				}
				if longOffset == 0 {
					break
				}
				offset = longOffset
			}

			lengthField, ok := reader.readBits(2)
			if !ok {
				break
			}

			var length int

			if lengthField < 3 {
				length = lengthField + 2
			} else {
				lengthField <<= 2
				extra, ok := reader.readBits(2)
				if !ok {
					break
				}
				lengthField += extra

				if lengthField < 15 {
					length = (lengthField & 0x0f) + 5
				} else {
				counter := 0
				nibble, ok := reader.readBits(4)
				if !ok {
					break
				}
				for nibble == 15 {
					nibble, ok = reader.readBits(4)
					if !ok {
						break
					}
					counter++
				}
				length = 15*counter + 8 + nibble
			}
			}

			for copyIndex := 0; copyIndex < length; copyIndex++ {
				byteValue := window.getFromEnd(offset)
				result = append(result, byteValue)
				window.append(byteValue)
			}
		}
	}

	return result, nil
}

// DecompressChunk decompresses data starting at a specific offset.
func DecompressChunk(data []byte, offset int) ([]byte, error) {
	if offset >= len(data) {
		return nil, nil
	}
	return Decompress(data[offset:])
}

// bitReader provides bit-by-bit MSB-first access to a byte slice.
type bitReader struct {
	data    []byte
	bytePos int
	bitPos  int // 7 down to 0 (MSB first)
}

func newBitReader(data []byte) *bitReader {
	return &bitReader{
		data:    data,
		bytePos: 0,
		bitPos:  7,
	}
}

func (reader *bitReader) readBit() (bool, bool) {
	if reader.bytePos >= len(reader.data) {
		return false, false
	}

	byteValue := reader.data[reader.bytePos]
	bit := (byteValue >> reader.bitPos) & 1
	reader.bitPos--

	if reader.bitPos < 0 {
		reader.bitPos = 7
		reader.bytePos++
	}

	return bit == 1, true
}

func (reader *bitReader) readByte() (byte, bool) {
	value, ok := reader.readBits(8)
	if !ok {
		return 0, false
	}
	return byte(value), true
}

func (reader *bitReader) readBits(count int) (int, bool) {
	if count <= 0 {
		return 0, true
	}

	value := 0
	for index := 0; index < count; index++ {
		bit, ok := reader.readBit()
		if !ok {
			return 0, false
		}
		value = (value << 1)
		if bit {
			value |= 1
		}
	}
	return value, true
}

// ValidateDecompress sanity-checks a decompression result.
func ValidateDecompress(original []byte, decompressed []byte) error {
	if len(original) == 0 && len(decompressed) == 0 {
		return nil
	}
	if len(decompressed) == 0 {
		return fmt.Errorf("lzs: decompression produced empty output from %d input bytes", len(original))
	}
	if len(decompressed) > len(original)*100 {
		return fmt.Errorf("lzs: decompression produced unreasonably large output (%d bytes from %d input)", len(decompressed), len(original))
	}
	return nil
}
