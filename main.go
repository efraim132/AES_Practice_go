package main

// This is simply a
//<b> AES-128 recreation</b>

import (
	"fmt"

	"github.com/charmbracelet/log"
)

var RCON = [10]byte{0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36}

type word [4]byte

type roundkey [4]word

// block stores AES state in column-major order: block[column][row].
type block [4][4]byte

// AES S-box (forward substitution box) as defined by the AES-128 standard.
// Values are listed in hexadecimal row-major order.
var sBox = [256]byte{
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

// substituteByte applies the AES S-box substitution to a single byte.
func substituteByte(b byte) byte {
	return sBox[b]
}

// substituteWord applies the S-box to each byte in a 4-byte word.
func (w word) substituteWord() word {
	var out word
	for i := 0; i < 4; i++ {
		out[i] = substituteByte(w[i])
	}
	return out
}

// substituteBytes applies the S-box to every byte of the state/block.
func (b block) substituteBytes() block {
	var out block
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			out[i][j] = substituteByte(b[i][j])
		}
	}
	return out
}

func getBlock(data [16]byte) (error, block) {
	output := block{}
	for col := 0; col < 4; col++ {
		output[col] = [4]byte{
			data[col*4],
			data[col*4+1],
			data[col*4+2],
			data[col*4+3],
		}
	}
	return nil, output
}

func (r roundkey) getBlock() block {
	var out block
	out[0] = r[0]
	out[1] = r[1]
	out[2] = r[2]
	out[3] = r[3]
	return out
}

func (b block) prettyPrintBlock() {
	// Print the state row by row while reading from the column-major layout.
	fmt.Println("+------------------+")
	for row := 0; row < 4; row++ {
		fmt.Print("|")
		for col := 0; col < 4; col++ {
			fmt.Printf("%02X | ", b[col][row])
		}
		fmt.Println()
	}
	fmt.Println("+------------------+")
}

func (w word) xor(B word) word {
	output := word{}
	for b := 0; b < 4; b++ {
		output[b] = w[b] ^ B[b]
	}
	return output
}

func (w word) rotateWord() word {
	return word{w[1], w[2], w[3], w[0]}
}

func generateRoundKey(previousKey roundkey, round int) (error, roundkey) {
	if round < 1 || round > 10 {
		return fmt.Errorf("round must be between 1 and 10, got %d", round), roundkey{}
	}

	output := roundkey{}

	firstWord := previousKey[3]
	firstWord = firstWord.rotateWord()
	firstWord = firstWord.substituteWord()
	firstWord = firstWord.xor([4]byte{RCON[round-1], 0x00, 0x00, 0x00}) // XOR Rcon
	firstWord = firstWord.xor(previousKey[0])

	output[0] = firstWord
	output[1] = output[0].xor(previousKey[1])
	output[2] = output[1].xor(previousKey[2])
	output[3] = output[2].xor(previousKey[3])

	return nil, output
}

func generateRoundKeys(originalKey [16]byte) (error, []roundkey) {
	var outputKeys []roundkey
	err, originalKeyBlockForm := getBlock(originalKey)
	log.Info("Converting Original Key", "originalKey", originalKey, "originalKeyBlockForm", originalKeyBlockForm)
	if err != nil {
		return fmt.Errorf("original key must be 16 bytes long"), nil
	}
	// Convert the original key into a roundkey form
	var originalRoundWordForm roundkey
	for col := 0; col < 4; col++ {
		originalRoundWordForm[col] = originalKeyBlockForm[col] // Copy entire column
	}
	outputKeys = append(outputKeys, originalRoundWordForm)

	for round := 1; round <= 10; round++ {
		err, newRoundKey := generateRoundKey(outputKeys[round-1], round)
		if err != nil {
			return err, nil
		}
		outputKeys = append(outputKeys, newRoundKey)
	}

	return nil, outputKeys
}

func (b block) shiftRows() block {
	output := block{}
	for row := 0; row < 4; row++ {
		for col := 0; col < 4; col++ {
			sourceCol := (col + row) % 4
			output[col][row] = b[sourceCol][row]
		}
	}

	return output
}

func mul2(data byte) byte {
	output := data << 1
	if data&0x80 != 0 { // overflow protection, check if the most significant bit was 1. 0x80 is a bit mask
		output ^= 0x1b // reduction from the AES standard todo figure out why
	}
	return output
}

func mul3(data byte) byte {
	return mul2(data) ^ data
}

func mixColumn(column [4]byte) [4]byte {
	return [4]byte{
		mul2(column[0]) ^ mul3(column[1]) ^ column[2] ^ column[3],
		column[0] ^ mul2(column[1]) ^ mul3(column[2]) ^ column[3],
		column[0] ^ column[1] ^ mul2(column[2]) ^ mul3(column[3]),
		mul3(column[0]) ^ column[1] ^ column[2] ^ mul2(column[3]),
	}
}

func (b block) mixBlock() block {
	output := block{}
	for col := 0; col < 4; col++ {
		output[col] = mixColumn(b[col])
	}
	return output
}

//func demoBlock() {
//	log.Info("Started", "Demonstration", "blockFormatting")
//	input := []byte{}
//	switch mode {
//	case "release":
//		fmt.Println("Release mode, enter input:")
//		_, err := fmt.Scanln(&input)
//		if err != nil {
//			log.Fatal("Error reading input:", err)
//		}
//	case "dev":
//		input = []byte{49, 50, 51, 52, 53, 54, 55, 56, 57, 65, 66, 67, 68, 69, 70, 71}
//	}
//	log.Info("Processing", "Input", input)
//	var arr [16]byte
//	copy(arr[:], input)
//	err, output := getBlock(arr)
//	if err != nil {
//		fmt.Println(err)
//	}
//	output.prettyPrintBlock()
//	log.Info("Demonstration block finished")
//}

//func demoRoundkey() {
//	log.Info("Started", "Demonstration", "roundKeyGeneration")
//	PrimaryKey := [16]byte{
//		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f}
//	log.Info("Processing", "PrimaryKey", PrimaryKey)
//
//	err, roundKeys := generateRoundKeys(PrimaryKey)
//	if err != nil {
//		panic(err)
//	}
//
//	for i, roundKey := range roundKeys {
//		log.Info(fmt.Sprintf("Result [%v]", i), "RoundKey", roundKey)
//	}
//
//}

func main() {
	log.Info("Starting AES-128 recreation")
}
