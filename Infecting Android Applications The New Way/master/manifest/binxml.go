package manifest

import (
	"bytes"
	"encoding/binary"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"strconv"
	"strings"
	"unsafe"
)

type binxmlParseInfo struct {
	strings     stringTable
	resourceIds []uint32

	encoder ManifestEncoder
	res     *ResourceTable
}

// Some samples have manifest in plaintext, this is an error.
// 2c882a2376034ed401be082a42a21f0ac837689e7d3ab6be0afb82f44ca0b859
var ErrPlainTextManifest = errors.New("xml is in plaintext, binary form expected")

// Deprecated: just calls ParseXML
func ParseManifest(r io.Reader, enc ManifestEncoder, resources *ResourceTable) error {
	return ParseXml(r, enc, resources)
}

// the main purpose of this reader is to
// count number of bytes readed  after parsing string table
// so we can calc offset to the end of the string table
type myReader struct {
	read int
	r    io.Reader
}

type myRead interface {
	GetRead() int
}

func (mr *myReader) Read(p []byte) (n int, err error) {
	n, err = mr.r.Read(p)
	mr.read += n
	return
}

func (mr *myReader) GetRead() int {
	return mr.read
}

// Parse the binary Xml format. The resources are optional and can be nil.
func ParseXml(r io.Reader, enc ManifestEncoder, resources *ResourceTable) error {
	x := binxmlParseInfo{
		encoder: enc,
		res:     resources,
	}

	id, headerLen, totalLen, err := parseChunkHeader(r)
	if err != nil {
		return err
	}
	//check if manifest is binary not plaintext
	if (id & 0xFF) == '<' {
		buf := bytes.NewBuffer(make([]byte, 0, 8))
		binary.Write(buf, binary.LittleEndian, &id)
		binary.Write(buf, binary.LittleEndian, &headerLen)
		binary.Write(buf, binary.LittleEndian, &totalLen)

		if s := buf.String(); strings.HasPrefix(s, "<?xml ") || strings.HasPrefix(s, "<manif") {
			return ErrPlainTextManifest
		}
	}

	// Android doesn't care.
	/*if id != chunkAxmlFile {
	    return fmt.Errorf("Invalid top chunk id: 0x%08x", id)
	}*/

	defer x.encoder.Flush()

	totalLen -= chunkHeaderSize

	var len uint32
	var lastId uint16
	for i := uint32(0); i < totalLen; i += len {
		id, _, len, err = parseChunkHeader(r)
		if err != nil {
			return fmt.Errorf("Error parsing header at 0x%08x of 0x%08x %08x: %s", i, totalLen, lastId, err.Error())
		}

		lastId = id

		lm := &io.LimitedReader{R: r, N: int64(len) - 2*4}

		switch id {
		case chunkStringTable:
			x.strings, err = parseStringTable(lm)
		case chunkResourceIds:
			err = x.parseResourceIds(lm)
		default:
			if (id & chunkMaskXml) == 0 {
				err = fmt.Errorf("Unknown chunk id 0x%x", id)
				break
			}

			// skip line number and unknown 0xFFFFFFFF
			if _, err = io.CopyN(ioutil.Discard, lm, 2*4); err != nil {
				break
			}

			switch id {
			case chunkXmlNsStart:
				err = x.parseNsStart(lm)
			case chunkXmlNsEnd:
				err = x.parseNsEnd(lm)
			case chunkXmlTagStart:
				err = x.parseTagStart(lm)
			case chunkXmlTagEnd:
				err = x.parseTagEnd(lm)
			case chunkXmlText:
				err = x.parseText(lm)
			default:
				err = fmt.Errorf("Unknown chunk id 0x%x", id)
			}
		}

		if err == ErrEndParsing {
			break
		} else if err != nil {
			return fmt.Errorf("Chunk: 0x%08x: %s", id, err.Error())
		} else if lm.N != 0 {
			return fmt.Errorf("Chunk: 0x%08x: was not fully read", id)
		}
	}

	return x.encoder.Flush()
}

func (x *binxmlParseInfo) parseResourceIds(r *io.LimitedReader) error {
	if (r.N % 4) != 0 {
		return fmt.Errorf("Invalid chunk size!")
	}

	count := uint32(r.N / 4)
	var id uint32
	for i := uint32(0); i < count; i++ {
		if err := binary.Read(r, binary.LittleEndian, &id); err != nil {
			return err
		}
		x.resourceIds = append(x.resourceIds, id)
	}
	return nil
}

func (x *binxmlParseInfo) parseNsStart(r *io.LimitedReader) error {
	var err error
	ns := &xml.Name{}

	var idx uint32
	if err = binary.Read(r, binary.LittleEndian, &idx); err != nil {
		return err
	}

	if ns.Local, err = x.strings.get(idx); err != nil {
		return err
	}

	if err = binary.Read(r, binary.LittleEndian, &idx); err != nil {
		return err
	}

	if ns.Space, err = x.strings.get(idx); err != nil {
		return err
	}

	// TODO: what to do with this?
	_ = ns
	return nil
}

func (x *binxmlParseInfo) parseNsEnd(r *io.LimitedReader) error {
	if _, err := io.CopyN(ioutil.Discard, r, 2*4); err != nil {
		return fmt.Errorf("error skipping: %s", err.Error())
	}

	// TODO: what to do with this?
	return nil
}

func (x *binxmlParseInfo) parseTagStart(r *io.LimitedReader) error {
	var namespaceIdx, nameIdx, attrCnt, classAttrIdx uint32

	if err := binary.Read(r, binary.LittleEndian, &namespaceIdx); err != nil {
		return fmt.Errorf("error reading namespace idx: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &nameIdx); err != nil {
		return fmt.Errorf("error reading name idx: %s", err.Error())
	}

	if _, err := io.CopyN(ioutil.Discard, r, 4); err != nil {
		return fmt.Errorf("error skipping flag: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &attrCnt); err != nil {
		return fmt.Errorf("error reading attrCnt: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &classAttrIdx); err != nil {
		return fmt.Errorf("error reading classAttr: %s", err.Error())
	}

	idAttributeIdx := (attrCnt >> 16) - 1
	attrCnt = (attrCnt & 0xFFFF)

	styleAttrIdx := (classAttrIdx >> 16) - 1
	classAttrIdx = (classAttrIdx & 0xFFFF)

	_ = styleAttrIdx
	_ = idAttributeIdx

	namespace, err := x.strings.get(namespaceIdx)
	if err != nil {
		return fmt.Errorf("error decoding namespace: %s", err.Error())
	}

	name, err := x.strings.get(nameIdx)
	if err != nil {
		return fmt.Errorf("error decoding name: %s", err.Error())
	}

	tok := xml.StartElement{
		Name: xml.Name{Local: name, Space: namespace},
	}

	var attrData [attrValuesCount]uint32
	for i := uint32(0); i < attrCnt; i++ {
		if err := binary.Read(r, binary.LittleEndian, &attrData); err != nil {
			return fmt.Errorf("error reading attrData: %s", err.Error())
		}

		// Android actually reads attributes purely by their IDs (see frameworks/base/core/res/res/values/attrs_manifest.xml
		// and its generated R class, that's where the indexes come from, namely the AndroidManifestActivity array)
		// but good guy android actually puts the strings into the string table on the same indexes anyway, most of the time.
		// This is for the samples that don't have it, mostly due to obfuscators/minimizers.
		// The ID can't change, because it would break current APKs.
		// Sample: 98d2e837b8f3ac41e74b86b2d532972955e5352197a893206ecd9650f678ae31
		//
		// The exception to this rule is the "package" attribute in the root manifest tag. That one MUST NOT use
		// resource ids, instead, it needs to use the string table. The meta attrs 'platformBuildVersion*'
		// are the same, except Android never parses them so it's just for manual analysis.
		// Sample: a3ee88cf1492237a1be846df824f9de30a6f779973fe3c41c7d7ed0be644ba37
		//
		// In general, android doesn't care about namespaces, but if a resource ID is used, it has to have been
		// in the android: namespace, so we fix that up.

		// frameworks/base/core/jni/android_util_AssetManager.cpp android_content_AssetManager_retrieveAttributes
		// frameworks/base/core/java/android/content/pm/PackageParser.java parsePackageSplitNames
		var attrName string
		if attrData[attrIdxName] < uint32(len(x.resourceIds)) {
			attrName = getAttributteName(x.resourceIds[attrData[attrIdxName]])
		}

		var attrNameFromStrings string
		if attrName == "" || name == "manifest" {
			attrNameFromStrings, err = x.strings.get(attrData[attrIdxName])
			if err != nil {
				if attrName == "" {
					return fmt.Errorf("error decoding attrNameIdx: %s", err.Error())
				}
			} else if attrName != "" && attrNameFromStrings != "package" && !strings.HasPrefix(attrNameFromStrings, "platformBuildVersion") {
				attrNameFromStrings = ""
			}
		}

		attrNameSpace, err := x.strings.get(attrData[attrIdxNamespace])
		if err != nil {
			return fmt.Errorf("error decoding attrNamespaceIdx: %s", err.Error())
		}

		if attrNameFromStrings != "" {
			attrName = attrNameFromStrings
		} else if attrNameSpace == "" {
			attrNameSpace = "http://schemas.android.com/apk/res/android"
		}

		attr := xml.Attr{
			Name: xml.Name{Local: attrName, Space: attrNameSpace},
		}

		switch attrData[attrIdxType] >> 24 {
		case AttrTypeString:
			attr.Value, err = x.strings.get(attrData[attrIdxString])
			if err != nil {
				return fmt.Errorf("error decoding attrStringIdx: %s", err.Error())
			}
		case AttrTypeIntBool:
			attr.Value = strconv.FormatBool(attrData[attrIdxData] != 0)
		case AttrTypeIntHex:
			attr.Value = fmt.Sprintf("0x%x", attrData[attrIdxData])
		case AttrTypeFloat:
			val := (*float32)(unsafe.Pointer(&attrData[attrIdxData]))
			attr.Value = fmt.Sprintf("%g", *val)
		case AttrTypeReference:
			isValidString := false
			if x.res != nil {
				var e *ResourceEntry
				if attr.Name.Local == "icon" || attr.Name.Local == "roundIcon" {
					e, err = x.res.GetIconPng(attrData[attrIdxData])
				} else {
					e, err = x.res.GetResourceEntry(attrData[attrIdxData])
				}

				if err == nil {
					attr.Value, err = e.value.String()
					isValidString = err == nil
				}
			}

			if !isValidString && attr.Value == "" {
				attr.Value = fmt.Sprintf("@%x", attrData[attrIdxData])
			}
		default:
			attr.Value = strconv.FormatInt(int64(int32(attrData[attrIdxData])), 10)
		}
		tok.Attr = append(tok.Attr, attr)
	}

	return x.encoder.EncodeToken(tok)
}

func (x *binxmlParseInfo) parseTagEnd(r *io.LimitedReader) error {
	var namespaceIdx, nameIdx uint32
	if err := binary.Read(r, binary.LittleEndian, &namespaceIdx); err != nil {
		return fmt.Errorf("error reading namespace idx: %s", err.Error())
	}

	if err := binary.Read(r, binary.LittleEndian, &nameIdx); err != nil {
		return fmt.Errorf("error reading name idx: %s", err.Error())
	}

	namespace, err := x.strings.get(namespaceIdx)
	if err != nil {
		return fmt.Errorf("error decoding namespace: %s", err.Error())
	}

	name, err := x.strings.get(nameIdx)
	if err != nil {
		return fmt.Errorf("error decoding name: %s", err.Error())
	}

	return x.encoder.EncodeToken(xml.EndElement{Name: xml.Name{Local: name, Space: namespace}})
}

func (x *binxmlParseInfo) parseText(r *io.LimitedReader) error {
	var idx uint32
	if err := binary.Read(r, binary.LittleEndian, &idx); err != nil {
		return fmt.Errorf("error reading idx: %s", err.Error())
	}

	text, err := x.strings.get(idx)
	if err != nil {
		return fmt.Errorf("error decoding idx: %s", err.Error())
	}

	if _, err := io.CopyN(ioutil.Discard, r, 2*4); err != nil {
		return fmt.Errorf("error skipping: %s", err.Error())
	}

	return x.encoder.EncodeToken(xml.CharData(text))
}
