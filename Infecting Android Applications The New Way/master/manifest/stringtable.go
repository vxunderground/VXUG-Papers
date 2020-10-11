package manifest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"math"
	"path/filepath"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	stringFlagSorted = 0x00000001
	stringFlagUtf8   = 0x00000100
)

var StringCnt uint32
var ManifestStringsDmp, _ = filepath.Abs("manifest_strings.dmp")
var StringTableEndPos int

type stringTable struct {
	isUtf8        bool
	stringOffsets []byte
	data          []byte
	cache         map[uint32]string
}

func parseStringTableWithChunk(r io.Reader) (res stringTable, err error) {
	id, _, totalLen, err := parseChunkHeader(r)
	if err != nil {
		return
	}

	if id != chunkStringTable {
		err = fmt.Errorf("Invalid chunk id 0x%08x, expected 0x%08x", id, chunkStringTable)
		return
	}

	return parseStringTable(&io.LimitedReader{R: r, N: int64(totalLen - chunkHeaderSize)})
}

func check(e error) {
	if e != nil {
		panic(e)
	}
}

func dumpStrings(data []byte) {
	err := ioutil.WriteFile(ManifestStringsDmp, data, 0644)
	check(err)
}

func parseStringTable(r *io.LimitedReader) (stringTable, error) {
	var err error
	var stringOffset, flags uint32
	var res stringTable
	// stringCnt - STRING COUNT
	if err := binary.Read(r, binary.LittleEndian, &StringCnt); err != nil {
		return res, fmt.Errorf("error reading stringCnt: %s", err.Error())
	}

	// skip styles count
	if _, err = io.CopyN(ioutil.Discard, r, 4); err != nil {
		return res, fmt.Errorf("error reading styleCnt: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &flags); err != nil {
		return res, fmt.Errorf("error reading flags: %s", err.Error())
	}

	res.isUtf8 = (flags & stringFlagUtf8) != 0
	if res.isUtf8 {
		flags &^= stringFlagUtf8
	}
	flags &^= stringFlagSorted // just ignore

	if flags != 0 {
		return res, fmt.Errorf("Unknown string flag: 0x%08x", flags)
	}

	if err := binary.Read(r, binary.LittleEndian, &stringOffset); err != nil {
		return res, fmt.Errorf("error reading stringOffset: %s", err.Error())
	}

	// skip styles offset
	if _, err = io.CopyN(ioutil.Discard, r, 4); err != nil {
		return res, fmt.Errorf("error reading styleOffset: %s", err.Error())
	}

	// Read lengths
	if StringCnt >= 2*1024*1024 {
		return res, fmt.Errorf("Too many strings in this file (%d).", StringCnt)
	}
	// allocate memory for each offset. 1 offset for 1 string. 1 offset = 4 bytes
	res.stringOffsets = make([]byte, 4*StringCnt)
	// fill stringOffssets array with offsets. Read from manifest
	if _, err := io.ReadFull(r, res.stringOffsets); err != nil {
		return res, fmt.Errorf("Failed to read string offsets data: %s", err.Error())
	}

	remainder := int64(stringOffset) - 7*4 - 4*int64(StringCnt)
	if remainder < 0 {
		return res, fmt.Errorf("Wrong string offset (got remainder %d)", remainder)
	} else if remainder > 0 {
		if _, err = io.CopyN(ioutil.Discard, r, remainder); err != nil {
			return res, fmt.Errorf("error reading styleArray: %s", err.Error())
		}
	}

	// read STRINGS
	// TODO Здесь в r.N попал resourceID, а это не должно быть
	res.data = make([]byte, r.N)
	if _, err := io.ReadFull(r, res.data); err != nil {
		return res, fmt.Errorf("Failed to read string table data: %s", err.Error())
	}
	// write res.data to stdout. res.data contains = resource strings and manifest in plaintext
	if mr, ok := r.R.(myRead); ok {
		StringTableEndPos = mr.GetRead()
	}
	dumpStrings(res.data)

	res.cache = make(map[uint32]string)
	return res, nil
}

func (t *stringTable) parseString16(r io.Reader) (string, error) {
	var strCharacters uint32
	var strCharactersLow, strCharactersHigh uint16

	if err := binary.Read(r, binary.LittleEndian, &strCharactersHigh); err != nil {
		return "", fmt.Errorf("error reading string char count: %s", err.Error())
	}

	if (strCharactersHigh & 0x8000) != 0 {
		if err := binary.Read(r, binary.LittleEndian, &strCharactersLow); err != nil {
			return "", fmt.Errorf("error reading string char count: %s", err.Error())
		}

		strCharacters = (uint32(strCharactersHigh&0x7FFF) << 16) | uint32(strCharactersLow)
	} else {
		strCharacters = uint32(strCharactersHigh)
	}

	buf := make([]uint16, int64(strCharacters))
	if err := binary.Read(r, binary.LittleEndian, &buf); err != nil {
		return "", fmt.Errorf("error reading string : %s", err.Error())
	}

	decoded := utf16.Decode(buf)
	for len(decoded) != 0 && decoded[len(decoded)-1] == 0 {
		decoded = decoded[:len(decoded)-1]
	}

	return string(decoded), nil
}

func (t *stringTable) parseString8Len(r io.Reader) (int64, error) {
	var strCharacters int64
	var strCharactersLow, strCharactersHigh uint8

	if err := binary.Read(r, binary.LittleEndian, &strCharactersHigh); err != nil {
		return 0, fmt.Errorf("error reading string char count: %s", err.Error())
	}

	if (strCharactersHigh & 0x80) != 0 {
		if err := binary.Read(r, binary.LittleEndian, &strCharactersLow); err != nil {
			return 0, fmt.Errorf("error reading string char count: %s", err.Error())
		}
		strCharacters = (int64(strCharactersHigh&0x7F) << 8) | int64(strCharactersLow)
	} else {
		strCharacters = int64(strCharactersHigh)
	}
	return strCharacters, nil
}

func (t *stringTable) parseString8(r io.Reader) (string, error) {
	// Length of the string in UTF16
	_, err := t.parseString8Len(r)
	if err != nil {
		return "", err
	}

	len8, err := t.parseString8Len(r)
	if err != nil {
		return "", err
	}

	buf := make([]uint8, len8)
	if err := binary.Read(r, binary.LittleEndian, &buf); err != nil {
		return "", fmt.Errorf("error reading string : %s", err.Error())
	}

	for len(buf) != 0 && buf[len(buf)-1] == 0 {
		buf = buf[:len(buf)-1]
	}

	return string(buf), nil
}

func (t *stringTable) get(idx uint32) (string, error) {
	if idx == math.MaxUint32 {
		return "", nil
	} else if idx >= uint32(len(t.stringOffsets)/4) {
		return "", fmt.Errorf("String with idx %d not found!", idx)
	}

	if str, prs := t.cache[idx]; prs {
		return str, nil
	}

	offset := binary.LittleEndian.Uint32(t.stringOffsets[4*idx : 4*idx+4])
	if offset >= uint32(len(t.data)) {
		return "", fmt.Errorf("String offset for idx %d is out of bounds (%d >= %d).", idx, offset, len(t.data))
	}

	r := bytes.NewReader(t.data[offset:])

	var err error
	var res string
	if t.isUtf8 {
		res, err = t.parseString8(r)
	} else {
		res, err = t.parseString16(r)
	}

	if err != nil {
		return "", err
	}

	if !utf8.ValidString(res) || strings.ContainsRune(res, 0) {
		res = strings.Map(func(r rune) rune {
			switch r {
			case 0, utf8.RuneError:
				return '\uFFFE'
			default:
				return r
			}
		}, res)
	}

	t.cache[idx] = res
	return res, nil
}

func (t *stringTable) isEmpty() bool {
	return t.cache == nil
}
