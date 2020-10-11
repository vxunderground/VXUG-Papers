package manifest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"math"
	"strings"
	"unicode/utf16"
)

var ErrUnknownResourceDataType = errors.New("Unknown resource data type")

// Contains parsed resources.arsc file.
type ResourceTable struct {
	mainStrings   stringTable
	nextPackageId uint32
	packages      map[uint32]*packageGroup
}

type packageGroup struct {
	Name     string
	Id       uint32
	Packages []*resourcePackage

	table         *ResourceTable
	largestTypeId uint8
	types         map[uint8][]resourceTypeSpec
}

type resourcePackage struct {
	Id   uint32
	Name string

	typeIdOffset uint32
	typeStrings  stringTable
	keyStrings   stringTable
}

type resourceTypeSpec struct {
	Id      uint8
	Entries []uint32
	Package *resourcePackage

	Configs []*resourceType
}

type resourceType struct {
	chunkData    []byte
	entryCount   uint32
	entriesStart uint32
	indexesStart uint32

	// ResTable_config config;
}

const (
	tableEntryComplex = 0x0001
	tableEntryPublic  = 0x0002
	tableEntryWeak    = 0x0004
)

// Describes one resource entry, for example @drawable/icon in the original XML, in one particular config option.
type ResourceEntry struct {
	size  uint16
	flags uint16

	ResourceType string
	Key          string
	Package      string

	value ResourceValue
}

// Handle to the resource's actual value.
type ResourceValue struct {
	dataType AttrType
	data     uint32

	globalStringTable *stringTable
	convertedData     interface{}
}

// Resource config option to pick from options - when @drawable/icon is referenced,
// use /res/drawable-xhdpi/icon.png or use /res/drawable-mdpi/icon.png?
//
// This is not fully implemented, so you can pick only first seen or last seen option.
type ResourceConfigOption int

const (
	ConfigFirst ResourceConfigOption = iota // Usually the smallest
	ConfigLast                              // Usually the biggest

	// Try to find the biggest png icon, otherwise same as ConfigLast.
	//
	// Deprecated: use GetIconPng
	ConfigPngIcon
)

// Parses the resources.arsc file
func ParseResourceTable(r io.Reader) *ResourceTable {
	res := ResourceTable{
		nextPackageId: 2,
		packages:      make(map[uint32]*packageGroup),
	}

	id, hdrLen, totalLen, err := parseChunkHeader(r)
	if err != nil {
		log.Panic("parseChunkHeader() failed", err)
	}

	var packageCurrent, packagesCnt uint32
	if err = binary.Read(r, binary.LittleEndian, &packagesCnt); err != nil {
		log.Panic("Failed to read packagesCnt", err)
	}

	if hdrLen < chunkHeaderSize+4 {
		log.Panicf("Invalid header length: %d", hdrLen)
	}

	totalLen -= uint32(hdrLen)
	hdrLen -= chunkHeaderSize + 4

	if _, err = io.CopyN(ioutil.Discard, r, int64(hdrLen)); err != nil {
		log.Panic("Failed to read header padding: %s", err.Error())
	}

	var len uint32
	var lastId uint16
	for i := uint32(0); i < totalLen; i += len {
		id, hdrLen, len, err = parseChunkHeader(r)
		if err != nil {
			log.Panicf("Error parsing header at 0x%08x of 0x%08x %08x: %s", i, totalLen, lastId, err.Error())
		}

		lastId = id

		lm := &io.LimitedReader{R: r, N: int64(len) - chunkHeaderSize}

		switch id {
		case chunkStringTable:
			if res.mainStrings.isEmpty() {
				res.mainStrings, err = parseStringTable(lm)
			}
		case chunkTablePackage:
			if packageCurrent >= packagesCnt {
				log.Panicf("Chunk: 0x%08x: Too many package chunks", id)
			}

			err = res.parsePackage(lm, hdrLen)
			packageCurrent++
		default:
			err = fmt.Errorf("Unknown chunk: 0x%08x at %d.", id, i+chunkHeaderSize+4)
			//_, err = io.CopyN(ioutil.Discard, lm, lm.N)
		}

		if err != nil {
			log.Panicf("Chunk: 0x%08x: %s", id, err.Error())
		} else if lm.N != 0 {
			log.Panicf("Chunk: 0x%08x: was not fully read", id)
		}
	}
	return &res
}

func (x *ResourceTable) parsePackage(r *io.LimitedReader, hdrLen uint16) error {
	pkgBlock, err := ioutil.ReadAll(r)
	if err != nil {
		return fmt.Errorf("error reading package block: %s", err.Error())
	}

	pkgReader := bytes.NewReader(pkgBlock)

	const valsSize = chunkHeaderSize + 4 + 2*128 + 4*5
	vals := struct {
		Id             uint32
		Name           [128]uint16
		TypeStrings    uint32
		LastPublicType uint32
		KeyStrings     uint32
		LastPublicKey  uint32
		TypeIdOffset   uint32
	}{}

	if err := binary.Read(pkgReader, binary.LittleEndian, &vals); err != nil {
		return fmt.Errorf("error reading values: %s", err.Error())
	}

	if vals.Id >= 256 {
		return fmt.Errorf("package id out of range: %d", vals.Id)
	}

	if vals.Id == 0 {
		vals.Id = x.nextPackageId
		x.nextPackageId++
	}

	pkg := &resourcePackage{
		Id: vals.Id,
	}

	// TypeIdOffset was added later and may not be present (frameworks/base@f90f2f8dc36e7243b85e0b6a7fd5a590893c827e)
	if hdrLen >= valsSize {
		pkg.typeIdOffset = vals.TypeIdOffset
	}

	pkg.Name = string(utf16.Decode(vals.Name[:]))
	if idx := strings.IndexRune(pkg.Name, 0); idx != -1 {
		pkg.Name = pkg.Name[:idx]
	}

	if vals.TypeStrings < chunkHeaderSize || vals.KeyStrings <= chunkHeaderSize {
		return fmt.Errorf("Invalid strings offset: %d %d", vals.TypeStrings, vals.KeyStrings)
	}

	vals.TypeStrings -= chunkHeaderSize
	vals.KeyStrings -= chunkHeaderSize

	if _, err := pkgReader.Seek(int64(vals.TypeStrings), io.SeekStart); err != nil {
		return err
	}

	if pkg.typeStrings, err = parseStringTableWithChunk(pkgReader); err != nil {
		return err
	}

	if _, err := pkgReader.Seek(int64(vals.KeyStrings), io.SeekStart); err != nil {
		return err
	}

	if pkg.keyStrings, err = parseStringTableWithChunk(pkgReader); err != nil {
		return err
	}

	group, prs := x.packages[pkg.Id]
	if !prs {
		group = &packageGroup{
			Id:    pkg.Id,
			Name:  pkg.Name,
			table: x,
			types: make(map[uint8][]resourceTypeSpec),
		}
		x.packages[pkg.Id] = group

		/*
			// Find all packages that reference this package
			size_t N = mpackageGroups.size();
			for (size_t i = 0; i < N; i++) {
				mpackageGroups[i]->dynamicRefTable.addMapping(
				group->name, static_cast<uint8_t>(group->id));
			}
		*/
	}

	group.Packages = append(group.Packages, pkg)

	if _, err := pkgReader.Seek(int64(hdrLen-chunkHeaderSize), io.SeekStart); err != nil {
		return err
	}

	for {
		chunkStartOffset, _ := pkgReader.Seek(0, io.SeekCurrent)

		id, hdrLen, totalLen, err := parseChunkHeader(pkgReader)
		if err == io.EOF {
			break
		} else if err != nil {
			return fmt.Errorf("Error parsing package internal header: %s", err.Error())
		}

		// Sample: 7e97541191621e72bd794b5b2d60eb2f68669ea8782421e54ec719ccda06c8a4
		if chunkStartOffset+int64(totalLen) >= int64(len(pkgBlock)) {
			totalLen = uint32(int64(len(pkgBlock)) - chunkStartOffset)
		}

		lm := &io.LimitedReader{R: pkgReader, N: int64(totalLen) - chunkHeaderSize}

		switch id {
		case chunkTableTypeSpec:
			err = x.parseTypeSpec(lm, pkg, group)
		case chunkTableType:
			block := pkgBlock[chunkStartOffset : chunkStartOffset+int64(totalLen)]
			if err = x.parseType(lm, pkg, group, block, hdrLen); err != nil {
				break
			}
			fallthrough
		default:
			_, err = io.CopyN(ioutil.Discard, lm, lm.N)
		}

		if err != nil {
			return fmt.Errorf("Chunk: 0x%08x: %s", id, err.Error())
		} else if lm.N != 0 {
			return fmt.Errorf("Chunk: 0x%08x: was not fully read", id)
		}
	}

	return nil
}

func (x *ResourceTable) parseTypeSpec(r io.Reader, pkg *resourcePackage, group *packageGroup) error {
	var id uint8
	if err := binary.Read(r, binary.LittleEndian, &id); err != nil {
		return fmt.Errorf("Failed to read type spec id: %s", err.Error())
	}

	if id == 0 {
		return fmt.Errorf("Invalid type spec id: %d", id)
	}

	if _, err := io.CopyN(ioutil.Discard, r, 1+2); err != nil {
		return fmt.Errorf("Failed to skip padding: %s", err.Error())
	}

	var entryCount uint32
	if err := binary.Read(r, binary.LittleEndian, &entryCount); err != nil {
		return fmt.Errorf("Failed to read entryCount: %s", err.Error())
	}

	if entryCount > 0 {
		var entries []uint32
		for i := uint32(0); i < entryCount; i++ {
			var e uint32
			if err := binary.Read(r, binary.LittleEndian, &e); err != nil {
				return fmt.Errorf("Failed to read type spec entry: %s", err.Error())
			}
			entries = append(entries, e)
		}

		group.types[id] = append(group.types[id], resourceTypeSpec{
			Id:      id,
			Entries: entries,
			Package: pkg,
		})

		if id > group.largestTypeId {
			group.largestTypeId = id
		}
	}
	return nil
}

func (x *ResourceTable) parseType(r io.Reader, pkg *resourcePackage, group *packageGroup, chunkData []byte, hdrLen uint16) error {
	vals := struct {
		Id   uint8
		Res0 uint8
		Res1 uint16

		EntryCount   uint32
		EntriesStart uint32

		//ResTable_config config;
	}{}

	if err := binary.Read(r, binary.LittleEndian, &vals); err != nil {
		return fmt.Errorf("error reading values: %s", err.Error())
	}

	if vals.Id == 0 {
		return fmt.Errorf("Invalid type id: %d", vals.Id)
	}

	if vals.EntryCount > 0 {
		typeList := group.types[vals.Id]
		if len(typeList) == 0 {
			return fmt.Errorf("No spec entry for type %d", vals.Id)
		}

		i := len(typeList) - 1
		typeList[i].Configs = append(typeList[i].Configs, &resourceType{
			chunkData:    chunkData,
			entryCount:   vals.EntryCount,
			entriesStart: vals.EntriesStart,
			indexesStart: uint32(hdrLen),
		})
	}
	return nil
}

// Converts the resource id to readable name including the package name like "@drawable:com.example.app.icon".
func (x *ResourceTable) GetResourceName(resId uint32) (string, error) {
	pkgId := (resId >> 24)
	typ := ((resId >> 16) & 0xFF) - 1
	entryId := (resId & 0xFFFF)

	group := x.packages[pkgId]
	if group == nil {
		return "", fmt.Errorf("Invalid package identifier.")
	}

	entry, err := x.getEntry(group, typ, entryId, ConfigFirst)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("@%s:%s.%s", entry.ResourceType, group.Name, entry.Key), nil
}

// Returns the resource entry for resId and the first configuration option it finds.
func (x *ResourceTable) GetResourceEntry(resId uint32) (*ResourceEntry, error) {
	return x.GetResourceEntryEx(resId, ConfigFirst)
}

// Returns the resource entry for resId and config configuration option.
func (x *ResourceTable) GetResourceEntryEx(resId uint32, config ResourceConfigOption) (*ResourceEntry, error) {
	if config == ConfigPngIcon {
		return x.GetIconPng(resId)
	}

	pkgId := (resId >> 24)
	typ := ((resId >> 16) & 0xFF) - 1
	entryId := (resId & 0xFFFF)

	group := x.packages[pkgId]
	if group == nil {
		return nil, fmt.Errorf("Invalid package identifier.")
	}

	return x.getEntry(group, typ, entryId, config)
}

// Return the biggest last config ending with .png. Falls back to GetResourceEntry() if none found.
func (x *ResourceTable) GetIconPng(resId uint32) (*ResourceEntry, error) {
	pkgId := (resId >> 24)
	typ := ((resId >> 16) & 0xFF) - 1
	entryId := (resId & 0xFFFF)

	group := x.packages[pkgId]
	if group == nil {
		return nil, fmt.Errorf("Invalid package identifier.")
	}

	entries, err := x.getEntryConfigs(group, typ, entryId, 256)
	if len(entries) == 0 {
		return nil, err
	}

	var res *ResourceEntry
	for i := 0; i < len(entries) && i < 1024; i++ {
		e := entries[i]
		if e.value.dataType == AttrTypeReference {
			pkgId = (e.value.data >> 24)
			typ = ((e.value.data >> 16) & 0xFF) - 1
			entryId = (e.value.data & 0xFFFF)

			if more, _ := x.getEntryConfigs(group, typ, entryId, 256); len(more) != 0 {
				entries = append(entries, more...)
			}
		} else if val, _ := e.value.String(); strings.HasSuffix(val, ".png") {
			res = e
		}
	}

	if res == nil {
		return x.GetResourceEntry(resId)
	}
	return res, nil
}

func (x *ResourceTable) getEntry(group *packageGroup, typeId, entry uint32, config ResourceConfigOption) (*ResourceEntry, error) {
	limit := 1024
	if config == ConfigFirst {
		limit = 1
	}

	entries, err := x.getEntryConfigs(group, typeId, entry, limit)
	if len(entries) == 0 {
		return nil, err
	}
	res := entries[len(entries)-1]
	return res, err
}

func (x *ResourceTable) getEntryConfigs(group *packageGroup, typeId, entry uint32, limit int) ([]*ResourceEntry, error) {
	typeList := group.types[uint8(typeId+1)]
	if len(typeList) == 0 {
		return nil, fmt.Errorf("Invalid type: %d", typeId)
	}

	var lastErr error
	var entries []*ResourceEntry
	for _, typ := range typeList {
		for _, thisType := range typ.Configs {
			if entry >= thisType.entryCount {
				continue
			}

			r := bytes.NewReader(thisType.chunkData)
			if _, err := r.Seek(int64(thisType.indexesStart+entry*4), io.SeekStart); err != nil {
				return nil, err
			}

			var thisOffset uint32
			if err := binary.Read(r, binary.LittleEndian, &thisOffset); err != nil {
				return nil, fmt.Errorf("Failed to read this type offset: %s", err.Error())
			}

			if thisOffset == math.MaxUint32 {
				continue
			}

			offset := thisType.entriesStart + thisOffset

			if int(offset) >= len(thisType.chunkData) || ((offset & 0x03) != 0) {
				return nil, fmt.Errorf("Invalid entry 0x%04x offset: %d!", entry, offset)
			}

			if _, err := r.Seek(int64(offset), io.SeekStart); err != nil {
				return nil, err
			}

			res, err := x.parseEntry(r, typ.Package, typeId)
			if err != nil {
				lastErr = err
			} else {
				entries = append(entries, res)
			}

			if len(entries) >= limit {
				goto exit
			}
		}
	}

	if len(entries) == 0 {
		return nil, fmt.Errorf("No entry found.")
	}
exit:
	return entries, lastErr
}

func (x *ResourceTable) parseEntry(r io.Reader, pkg *resourcePackage, typeId uint32) (*ResourceEntry, error) {
	var err error
	var res ResourceEntry
	var keyIndex uint32

	if err := binary.Read(r, binary.LittleEndian, &res.size); err != nil {
		return nil, fmt.Errorf("Failed to read entry size: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &res.flags); err != nil {
		return nil, fmt.Errorf("Failed to read entry flags: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &keyIndex); err != nil {
		return nil, fmt.Errorf("Failed to read entry key index: %s", err.Error())
	}

	res.Package = pkg.Name

	res.ResourceType, err = pkg.typeStrings.get(typeId - pkg.typeIdOffset)
	if err != nil {
		return nil, fmt.Errorf("Invalid typeString: %s", err.Error())
	}

	res.Key, err = pkg.keyStrings.get(keyIndex)
	if err != nil {
		return nil, fmt.Errorf("Invalid keyString: %s", err.Error())
	}

	if !res.IsComplex() {
		var size uint16
		if err := binary.Read(r, binary.LittleEndian, &size); err != nil {
			return nil, fmt.Errorf("Failed to read entry value size: %s", err.Error())
		}

		if size < 8 {
			return nil, fmt.Errorf("Invalid Res_value size: %d!", size)
		}

		if _, err := io.CopyN(ioutil.Discard, r, 1); err != nil {
			return nil, fmt.Errorf("Failed to read entry value res0: %s", err.Error())
		}

		if err := binary.Read(r, binary.LittleEndian, &res.value.dataType); err != nil {
			return nil, fmt.Errorf("Failed to read entry value data type: %s", err.Error())
		}

		if err := binary.Read(r, binary.LittleEndian, &res.value.data); err != nil {
			return nil, fmt.Errorf("Failed to read entry value data: %s", err.Error())
		}

		res.value.globalStringTable = &x.mainStrings

	} else {
		// NYI
	}

	return &res, nil
}

// Returns true if the resource entry is complex (for example arrays, string plural arrays...).
//
// Complex ResourceEntries are not yet supported.
func (e *ResourceEntry) IsComplex() bool {
	return (e.flags & tableEntryComplex) != 0
}

// Returns the resource value handle
func (e *ResourceEntry) GetValue() *ResourceValue {
	return &e.value
}

// Returns the resource data type
func (v *ResourceValue) Type() AttrType {
	return v.dataType
}

// Returns the raw data of the resource
func (v *ResourceValue) RawData() uint32 {
	return v.data
}

// Returns the data converted to their native type (e.g. AttrTypeString to string).
//
// Returns ErrUnknownResourceDataType if the type is not handled by this library
func (v *ResourceValue) Data() (interface{}, error) {
	if v.convertedData != nil {
		return v.convertedData, nil
	}

	var val interface{}
	var err error

	switch v.dataType {
	case AttrTypeNull:
	case AttrTypeString:
		val, err = v.globalStringTable.get(v.data)
		if err != nil {
			return nil, err
		}
	case AttrTypeIntDec, AttrTypeIntHex, AttrTypeIntBool,
		AttrTypeIntColorArgb8, AttrTypeIntColorRgb8,
		AttrTypeIntColorArgb4, AttrTypeIntColorRgb4,
		AttrTypeReference:
		val = v.data
	default:
		return nil, ErrUnknownResourceDataType
	}

	v.convertedData = val
	return val, nil
}

// Returns the data converted to a readable string, to the format it was likely in the original AndroidManifest.xml.
//
// Unknown data types are returned as the string from ErrUnknownResourceDataType.Error().
func (v *ResourceValue) String() (res string, err error) {
	switch v.dataType {
	case AttrTypeNull:
		res = "null"
	case AttrTypeIntHex:
		res = fmt.Sprintf("0x%x", v.data)
	case AttrTypeIntBool:
		if v.data != 0 {
			res = "true"
		} else {
			res = "false"
		}
	case AttrTypeIntColorArgb8:
		res = fmt.Sprintf("#%08x", v.data)
	case AttrTypeIntColorRgb8:
		res = fmt.Sprintf("#%06x", v.data)
	case AttrTypeIntColorArgb4:
		res = fmt.Sprintf("#%04x", v.data)
	case AttrTypeIntColorRgb4:
		res = fmt.Sprintf("#%03x", v.data)
	case AttrTypeReference:
		res = fmt.Sprintf("@%x", v.data)
	default:
		var val interface{}
		val, err = v.Data()
		if err == nil {
			res = fmt.Sprintf("%v", val)
		}
	}
	return
}
