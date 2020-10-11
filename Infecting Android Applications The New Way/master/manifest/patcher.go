package manifest

import (
	"bytes"
	"common"
	"encoding/binary"
	"encoding/xml"
	"golang.org/x/text/encoding/unicode"
	"io/ioutil"
	"log"
	"path/filepath"
)

const (
	fileLenOffset        = 0x4
	offsetTableOffset    = 0x24
	offsetStringTableLen = 0xc
	stringTableInfoSizeOffset = 0x1c

	// Name of application in our stub dex
	// It is MUST be longer than any average name
	newAppNameUTF8    = "aaaaaaaa.aaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.aaaaaaaaaaaaaaaaaaaaaa.InjectedApp"
	newAppNameUTF8Len = uint8(len(newAppNameUTF8))
)

var alignCount uint32
var oldAppNameUTF16 string
var newAppNameUTF16 string
var OldAppNameUTF8 string
var PlainPath, _ = filepath.Abs("AndroidManifest_plaintext.xml")

func patchApplication() ([]byte, int) {

	log.Printf("Getting original application name...")
	OldAppNameUTF8 = getAppName()
	log.Printf("Original applciation name = %s\n", OldAppNameUTF8)

	if OldAppNameUTF8 == "" {
		log.Panic("Application name wasn't found")
		//TODO if not found - we should add our
	}

	// read bytes from binary xml
	androidManifestRaw, err := ioutil.ReadFile(common.ManifestBinaryPath)
	if err != nil {
		log.Panicf("Failed to read %s", common.ManifestBinaryPath)
	}

	log.Printf("Original manifest (binary) size = 0x%0x\n", len(androidManifestRaw))

	// encode name to UTF-16
	encoder := unicode.UTF16(unicode.LittleEndian, unicode.IgnoreBOM).NewEncoder()
	oldAppNameUTF16, err = encoder.String(OldAppNameUTF8)

	// searching application name position in binary manifest
	pos := bytes.Index(androidManifestRaw, []byte(oldAppNameUTF16))

	//get lenght of string
	originalLen := int(androidManifestRaw[pos-2]) * 2

	log.Printf("pos = 0x%0x, original applciation name length = 0x%0x\n", pos, originalLen)

	//patch length with new value. length = characters count
	// pos-2 - because every string is followed by len
	androidManifestRaw[pos-2] = newAppNameUTF8Len

	//patch application name with new name
	// do not forget about alignment!
	newAppNameUTF16, err = encoder.String(newAppNameUTF8)
	newAppNameUTF16Len := len(newAppNameUTF16)

	// how many bytes we add to manifest
	lenDiff := newAppNameUTF16Len - originalLen

	//// we need enough space to insert our name
	androidManifestRawNew := make([]byte, len(androidManifestRaw)+newAppNameUTF16Len-originalLen)

	log.Printf("new applciation name = %s, new application length = 0x%0x\n",
		newAppNameUTF8, newAppNameUTF16Len)

	// copy everything until application name string
	copy(androidManifestRawNew, androidManifestRaw[:pos])

	// copy our name
	copy(androidManifestRawNew[pos:], []byte(newAppNameUTF16))

	// copy everything after name
	copy(androidManifestRawNew[pos+len([]byte(newAppNameUTF16)):], androidManifestRaw[pos+originalLen:])

	// calc position where we should insert alignment bytes
	alignPos := (newAppNameUTF16Len - originalLen) + StringTableEndPos

	log.Printf("alignPos = 0x%0x\n", alignPos)

	// how many bytes we should insert?
	// The main idea - data after string table should be
	// aligned to 4 bytes
	alignCount = uint32(alignPos % 4)

	log.Printf("align = %d\n", alignCount)

	if alignCount != 0 {
		var alignSlice = make([]byte, alignCount)

		// insert byte alignment
		androidManifestRawNew = append(androidManifestRawNew[:alignPos], append(alignSlice, androidManifestRawNew[alignPos:]...)...)

	}

	return androidManifestRawNew, lenDiff
}

// we should find from what offset in StringOffsets
// we should start changing offsets by incrementing them to
// number of characters application name expanded
// manifest_strings.dmp contains all strings
// we should count strings after application name
// it will be position of offset

func getAppNameOffset() uint32 {

	// position in string offset
	//var appNameOff uint32 = 1
	var pos uint32

	data, err := ioutil.ReadFile(ManifestStringsDmp)
	if err != nil {
		panic(err)
	}

	// searching application name position in string dump
	// we substract 2 because real offset is the offset to strLen + str
	// but we found offset to just str
	pos = uint32(bytes.Index(data, []byte(oldAppNameUTF16)) - 2)

	log.Printf("application name position in string dump = 0x%x", pos)

	return pos
}

func patchOffsetTable(data []byte, appNameOff, lenDiff uint32) {

	var offset uint32

	offsetTableReader := bytes.NewReader(data)

	var j uint32 = 0
	for i := uint32(1); i <= StringCnt - appNameOff; i++ {

		//read offset
		err := binary.Read(offsetTableReader, binary.LittleEndian, &offset)
		if err != nil {
			log.Panic("Failed to read offset", err)
		}

		log.Printf("Original offset = 0x%x", offset)

		//increment it to length of symbol added
		offset += lenDiff

		log.Printf("New offset = 0x%x", offset)

		binary.LittleEndian.PutUint32(data[j:], offset)
		j += 4
	}
}

func patchStringTableLen(data []byte) {

	var stringTableLen uint32

	stringTableLenReader := bytes.NewReader(data)

	err := binary.Read(stringTableLenReader, binary.LittleEndian, &stringTableLen)
	if err != nil {
		log.Panic("Failed to read offset", err)
	}

	// calc how many bytes we added to manifest
	// it's a difference between new name and old name
	// *2 - because they are in UTF-16
	// IMPORTANT! stringTableLen - must be 4 byte aligned
	newLen := len(newAppNameUTF16)
	oldLen := len(oldAppNameUTF16)
	stringTableLenNew := uint32(int(stringTableLen) + newLen - oldLen)

	// align
	stringTableLenNew += alignCount

	binary.LittleEndian.PutUint32(data, stringTableLenNew)
}

func Patch() {

	var androidManifestRaw, lenDiff = patchApplication()

	log.Printf("New manifest len = 0x%0x\n", len(androidManifestRaw))

	// after we insert new application name we need to increase length of manifest len
	binary.LittleEndian.PutUint32(androidManifestRaw[fileLenOffset:], uint32(len(androidManifestRaw)))

	var appNameOff = getAppNameOffset()

	// search offset in manifest
	appNameOffArr := make([]byte, 4)
	binary.LittleEndian.PutUint32(appNameOffArr, appNameOff)

	pos := uint32(bytes.Index(androidManifestRaw, appNameOffArr))

	log.Printf("application name offset in manifest = 0x%x", pos)

	// we step to next offset after our found app name offset
	pos += 4

	// locate the end of stringTableOffset (equals to the start of strings)
	var stringTableInfoSize uint32
	var stringOffsetTableEnd uint32

	stringTableInfoSizeReader := bytes.NewReader(androidManifestRaw[stringTableInfoSizeOffset:])

	err := binary.Read(stringTableInfoSizeReader, binary.LittleEndian, &stringTableInfoSize)
	if err != nil {
		log.Panic("Failed to read offset", err)
	}

	log.Printf("stringTableInfoSize = 0x%x", stringTableInfoSize)

	// 0x8 - start of StringTableInfo section
	stringOffsetTableEnd = 0x8 + stringTableInfoSize

	log.Printf("stringOffsetTableEnd = 0x%x", stringOffsetTableEnd)

	//start reading & patching
	offsetTableReader := bytes.NewReader(androidManifestRaw[pos:])

	var j = pos
	var offset uint32
	for i := pos; i < stringOffsetTableEnd; {

		//read offset
		err := binary.Read(offsetTableReader, binary.LittleEndian, &offset)
		if err != nil {
			log.Panic("Failed to read offset", err)
		}

		//log.Printf("Original offset = 0x%x", offset)

		//increment it to length of symbol added
		offset += uint32(lenDiff)

		//log.Printf("New offset = 0x%x", offset)

		//patch with new value
		binary.LittleEndian.PutUint32(androidManifestRaw[j:], offset)
		j += 4
		i += 4
	}

	patchStringTableLen(androidManifestRaw[offsetStringTableLen:])

	common.WriteChanges(androidManifestRaw, common.ManifestBinaryPath)
}

// Search application name in decoded android manifest
func getAppName() string {

	// read manifest to byte array
	content, err := ioutil.ReadFile(PlainPath)
	if err != nil {
		panic(err)
	}

	//defer func() {
	//	err = os.Remove(manifestPlainPath)
	//
	//	if err != nil {
	//		panic(err)
	//	}
	//} ()

	// structs for XML nodes
	type Application struct {
		Name string `xml:"name,attr"`
	}

	type Result struct {
		XMLName     xml.Name    `xml:"manifest"`
		Application Application `xml:"application"`
	}

	v := new(Result)

	err = xml.Unmarshal(content, v)
	if err != nil {
		log.Panic("Failed to unmarshal XML", err)
		return ""
	}

	return v.Application.Name
}
