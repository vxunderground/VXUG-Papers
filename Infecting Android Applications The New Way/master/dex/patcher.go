package mydex

import (
	"bytes"
	"common"
	"crypto/sha1"
	"encoding/binary"
	"hash/adler32"
	"io/ioutil"
	"log"
	"manifest"
	"path/filepath"
	"strings"
)


const (
	// DEX structure offsets
	fileSizeOff              = 0x20
	mapOff                   = 0x34
	dataSizeOff              = 0x68
	signatureOff             = 0x20
	checksumOff              = 0xc
	stringIdsCount           = 0x3 //how many stringIds we should change
	classDataOffOff			 = 0xe4 //map->class_def_item->class_data_off
	classDataItemOffOff		 = 0x29c //map->class_data_item->offset
	annotationOffItemOff	 = 0x2a8 //map->annotation_set_item->entries->annotation_off_item
	mapListOffOff			 = 0x2b4 //map->map_list->offset
	posStringIdsChangedOff = 0x84
)

// this name is patched so we should make it
// as short as possible
//var placeholder = "La/a/a;"
var placeholder = "Lz/z/z;"
var placeholderLength = len(placeholder) + 1
var placeholderOff int
var dexPath, _ = filepath.Abs("InjectedApp.dex")
var dexPathNew, _ = filepath.Abs("InjectedApp_patched.dex")

// SHA-1 signature (hash) of the rest of the file (everything but magic, checksum, and this field); used to uniquely identify files
func patchSignature(data []byte) {

	signature := sha1.Sum(data[signatureOff:])

	log.Printf("New DEX Signature = %x\n", signature)

	// patch signature
	for i := 0; i < 20; i++ {
		data[0xc+i] = signature[i]
	}
}

// adler32 checksum of the rest of the file (everything but magic and this field); used to detect file corruption
func patchChecksum(data []byte) {
	checksum := adler32.Checksum(data[checksumOff:])

	log.Printf("New DEX Checksum = %x\n", checksum)

	// patch checksum
	binary.LittleEndian.PutUint32(data[0x8:], checksum)
}

// Yes, dex uses sleb and uleb data types not uint32
// But we use our predictable DEX so we can ignore it

// What is changed in DEX after patching parent class?
// DEX format doc: https://source.android.com/devices/tech/dalvik/dex-format
/*
	header_item->checksum
	header_item->signature
	header_item->file_size
	header_item->map_off
	header_item->data_size
	string_id_item->string_data_off
	map->class_def_item->class_data_off
	string_data_item->utf16_size
	map->class_data_item->offset
	map->annotation_set_item->entries->annotation_off_item
	map->map_list->offset

 */
// Do not forget about alignment of some structures!

func Patch() {

	data, err := ioutil.ReadFile(dexPath)
	if err != nil {
		log.Panicf("DEX Failed to read %s", dexPath)
	}

	// calc offset to placeholder
	placeholderOff = bytes.Index(data, []byte(placeholder))

	log.Printf("placeholderOff = 0x%x\n", placeholderOff)

	// we should add "L" and ";", and convert "."->"/" to be a normal DEX string
	//tmpName := "z.z.zzzzzzzzzzzzzzzz"
	oldAppNameNormalized := "L" + strings.ReplaceAll(manifest.OldAppNameUTF8, ".", "/") + ";"
	//oldAppNameNormalized := "L" + strings.ReplaceAll(tmpName, ".", "/") + ";"
	newAppName := oldAppNameNormalized + "\x00"

	// patch string len (string_data_item->utf16_size)
	// -1 - it's a position of len before every string in dex
	data[placeholderOff - 1] = uint8(len(oldAppNameNormalized))

	// how many bytes we added to DEX?
	var sizeDiff uint32
	sizeDiff = uint32(len(newAppName) - placeholderLength)
	log.Printf("sizeDiff =0x%x", sizeDiff)

	// how many align bytes we should add
	var alignCount uint32
	alignCount = 4 - (sizeDiff % 4)

	if alignCount == 4 {
		alignCount = 0
	}
	log.Printf("alignCount = 0x%x", alignCount)

	// patch mapOff (header_item->map_off)
	var oldMapOff uint32
	oldMapOff = binary.LittleEndian.Uint32(data[mapOff:])
	newMapOff := oldMapOff + sizeDiff + alignCount
	binary.LittleEndian.PutUint32(data[mapOff:], newMapOff)
	log.Printf("old mapOff = 0x%0x | new mapOff = 0x%0x\n", oldMapOff, newMapOff)

	// patch datasize (header_item->data_size)
	var oldDataSize uint32
	oldDataSize = binary.LittleEndian.Uint32(data[dataSizeOff:])
	newDataSize := oldDataSize + sizeDiff + alignCount
	binary.LittleEndian.PutUint32(data[dataSizeOff:], newDataSize)
	log.Printf("old dataSize = 0x%0x | new dataSize = 0x%0x\n", oldDataSize, newDataSize)

	// patch stringIds (string_id_item->string_data_off)
	// stringIds - table of offsets to strings
	// offsets counted from the start (0x0)
	// posStringIdsChangedOff - position in our DEX from which we start changing

	// we hardcoded it because we use our predictable DEX
	var oldId uint32
	stringIdsReader := bytes.NewReader(data[posStringIdsChangedOff:])

	j := 0

	for i := 0; i < stringIdsCount; i++ {

		err = binary.Read(stringIdsReader, binary.LittleEndian, &oldId)
		if err != nil {
			log.Panic("Failed to read stringId", err)
		}

		newId := oldId + sizeDiff
		binary.LittleEndian.PutUint32(data[posStringIdsChangedOff + j:], newId)
		j += 4
	}

	// patch map->class_def_item->class_data_off (4 byte)
	classDataOff := binary.LittleEndian.Uint32(data[classDataOffOff:])
	newClassDataOff := classDataOff + sizeDiff
	binary.LittleEndian.PutUint32(data[classDataOffOff:], newClassDataOff)

	log.Printf("off = 0x%x | classDataOff = 0x%x | newClassDataOff = 0x%x",
		classDataOffOff, classDataOff, newClassDataOff)

	// patch map->class_data_item->offset (dont apply alignment)
	classDataItemOff := binary.LittleEndian.Uint32(data[classDataItemOffOff:])
	newClassDataItemOff := classDataItemOff + sizeDiff
	binary.LittleEndian.PutUint32(data[classDataItemOffOff:], newClassDataItemOff)
	log.Printf("off = 0x%x | classDataItemOff = 0x%x | newClassDataItemOff = 0x%x",
		classDataItemOffOff, classDataItemOff, newClassDataItemOff)

	// patch map->annotation_set_item->entries->annotation_off_item
	annotationOffItem := binary.LittleEndian.Uint32(data[annotationOffItemOff:])
	newAnnotationOffItem := annotationOffItem + sizeDiff + alignCount
	binary.LittleEndian.PutUint32(data[annotationOffItemOff:], newAnnotationOffItem)
	log.Printf("off = 0x%x | annotationOffItem = 0x%x | newAnnotationOffItem = 0x%x",
		annotationOffItemOff, annotationOffItem, newAnnotationOffItem)

	//patch map->map_list->offset
	mapListOff := binary.LittleEndian.Uint32(data[mapListOffOff:])
	newMapListOff := mapListOff + sizeDiff + alignCount
	binary.LittleEndian.PutUint32(data[mapListOffOff:], newMapListOff)
	log.Printf("off = 0x%x | mapListOff = 0x%x | newMapListOff = 0x%x",
		mapListOffOff, mapListOff, newMapListOff)

	// from now we start patching second half of DEX (after array of strings)
	// but first we need to insert alignment bytes
	if alignCount != 0 {
		var alignSlice = make([]byte, alignCount)
		var alignPos uint32 = 0x220
		// insert byte alignment
		data = append(data[:alignPos], append(alignSlice, data[alignPos:]...)...)
	}

	// insert new parent application name
	data = append(data[:placeholderOff], append([]byte(newAppName), data[placeholderOff + placeholderLength:]...)...)

	// patch new fileSize (header_item->file_size)
	var fileSize = uint32(len(data))
	binary.LittleEndian.PutUint32(data[fileSizeOff:], fileSize)

	log.Printf("fileSize = 0x%x", fileSize)

	patchSignature(data[0:])
	patchChecksum(data[0:])

	common.WriteChanges(data, dexPathNew)
}
