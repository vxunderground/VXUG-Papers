package manifest

import (
	"archive/zip"
	"compress/flate"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
)

type zipReaderFileSubEntry struct {
	offset int64
	method uint16
}

// This struct mimics of Reader from archive/zip. It's purpose is to handle
// even broken archives that Android can read, but archive/zip cannot.
type ZipReader struct {
	File map[string]*ZipReaderFile

	// Files in the order they were found in the zip. May contain the same ZipReaderFile
	// multiple times in case of broken/crafted ZIPs
	FilesOrdered []*ZipReaderFile

	zipFileReader io.ReadSeeker
	ownedZipFile  *os.File
}

// This struct mimics of File from archive/zip. The main difference is it can represent
// multiple actual entries in the ZIP file in case it has more than one with the same name.
type ZipReaderFile struct {
	Name  string
	IsDir bool

	zipFile        io.ReadSeeker
	internalReader io.Reader
	internalCloser io.Closer

	zipEntry *zip.File

	entries  []zipReaderFileSubEntry
	curEntry int
}

// Opens the file(s) for reading. After calling open, you should iterate through all possible entries that
// go by that Filename with for f.Next() { f.Read()... }
func (zr *ZipReaderFile) Open() error {
	if zr.internalReader != nil {
		return errors.New("File is already opened.")
	}

	if zr.zipEntry != nil {
		var err error
		zr.curEntry = 0
		rc, err := zr.zipEntry.Open()
		if err != nil {
			return err
		}
		zr.internalReader = rc
		zr.internalCloser = rc
	} else {
		zr.curEntry = -1
	}

	return nil
}

// Reads data from current opened file. Returns io.EOF at the end of current file, but another file entry might exist.
// Use Next() to check for that.
func (zr *ZipReaderFile) Read(p []byte) (int, error) {
	if zr.internalReader == nil {
		if zr.curEntry == -1 && !zr.Next() {
			return 0, io.ErrUnexpectedEOF
		}

		if zr.curEntry >= len(zr.entries) {
			return 0, io.ErrUnexpectedEOF
		}

		_, err := zr.zipFile.Seek(zr.entries[zr.curEntry].offset, 0)
		if err != nil {
			return 0, err
		}

		switch zr.entries[zr.curEntry].method {
		case zip.Store:
			zr.internalReader = zr.zipFile
		default: // case zip.Deflate: // Android treats everything but 0 as deflate
			rc := flate.NewReader(zr.zipFile)
			zr.internalReader = rc
			zr.internalCloser = rc
		}
	}
	return zr.internalReader.Read(p)
}

// Moves this reader to the next file represented under it's Name. Returns false if there are no more to read.
func (zr *ZipReaderFile) Next() bool {
	if len(zr.entries) == 0 && zr.internalReader != nil {
		zr.curEntry++
		return zr.curEntry == 1
	}

	zr.Close()

	if zr.curEntry+1 >= len(zr.entries) {
		return false
	}
	zr.curEntry++
	return true
}

// Closes this reader and all opened files.
func (zr *ZipReaderFile) Close() error {
	if zr.internalReader != nil {
		if zr.internalCloser != nil {
			zr.internalCloser.Close()
			zr.internalCloser = nil
		}
		zr.internalReader = nil
	}
	return nil
}

// Get the file header from ZIP (can return nil with broken archives)
func (zr *ZipReaderFile) ZipHeader() *zip.FileHeader {
	if zr.zipEntry != nil {
		return &zr.zipEntry.FileHeader
	}
	return nil
}

// Closes this ZIP archive and all it's ZipReaderFile entries.
func (zr *ZipReader) Close() error {
	if zr.zipFileReader == nil {
		return nil
	}

	for _, zf := range zr.File {
		zf.Close()
	}

	var err error
	if zr.ownedZipFile != nil {
		err = zr.ownedZipFile.Close()
		zr.ownedZipFile = nil
	}

	zr.zipFileReader = nil
	return err
}

type readAtWrapper struct {
	io.ReadSeeker
}

func (wr *readAtWrapper) ReadAt(b []byte, off int64) (n int, err error) {
	if readerAt, ok := wr.ReadSeeker.(io.ReaderAt); ok {
		return readerAt.ReadAt(b, off)
	}

	oldpos, err := wr.Seek(off, io.SeekCurrent)
	if err != nil {
		return
	}

	if _, err = wr.Seek(off, io.SeekStart); err != nil {
		return
	}

	if n, err = wr.Read(b); err != nil {
		return
	}

	_, err = wr.Seek(oldpos, io.SeekStart)
	return
}

// Attempts to open ZIP for reading.
func OpenZip(path string) (zr *ZipReader, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}

	zr, err = OpenZipReader(f)
	if err != nil {
		f.Close()
	} else {
		zr.ownedZipFile = f
	}
	return
}

// Attempts to open ZIP for reading. Might Seek the reader to arbitrary
// positions.
func OpenZipReader(zipReader io.ReadSeeker) (zr *ZipReader, err error) {
	zr = &ZipReader{
		File:          make(map[string]*ZipReaderFile),
		zipFileReader: zipReader,
	}

	f := &readAtWrapper{zipReader}

	var zipinfo *zip.Reader
	zipinfo, err = tryReadZip(f)
	if err == nil {
		for i, zf := range zipinfo.File {
			// Android treats anything but 0 as deflate.
			if zf.Method != zip.Store && zf.Method != zip.Deflate {
				zipinfo.File[i].Method = zip.Deflate
			}

			cl := path.Clean(zf.Name)
			if zr.File[cl] == nil {
				zf := &ZipReaderFile{
					Name:     cl,
					IsDir:    zf.FileInfo().IsDir(),
					zipFile:  f,
					zipEntry: zf,
				}
				zr.File[cl] = zf
				zr.FilesOrdered = append(zr.FilesOrdered, zf)
			}
		}
		return
	}

	if _, err = f.Seek(0, io.SeekStart); err != nil {
		return
	}

	var off int64
	for {
		off, err = findNextFileHeader(f)
		if off == -1 || err != nil {
			return
		}

		var nameLen, extraLen, method uint16
		if _, err = f.Seek(off+8, 0); err != nil {
			return
		}

		if err = binary.Read(f, binary.LittleEndian, &method); err != nil {
			return
		}

		if _, err = f.Seek(off+26, 0); err != nil {
			return
		}

		if err = binary.Read(f, binary.LittleEndian, &nameLen); err != nil {
			return
		}

		if err = binary.Read(f, binary.LittleEndian, &extraLen); err != nil {
			return
		}

		buf := make([]byte, nameLen)
		if _, err = f.ReadAt(buf, off+30); err != nil {
			return
		}

		fileName := path.Clean(string(buf))
		fileOffset := off + 30 + int64(nameLen) + int64(extraLen)

		zrf := zr.File[fileName]
		if zrf == nil {
			zrf = &ZipReaderFile{
				Name:     fileName,
				zipFile:  f,
				curEntry: -1,
			}
			zr.File[fileName] = zrf
		}
		zr.FilesOrdered = append(zr.FilesOrdered, zrf)

		zrf.entries = append([]zipReaderFileSubEntry{zipReaderFileSubEntry{
			offset: fileOffset,
			method: method,
		}}, zrf.entries...)

		if _, err = f.Seek(off+4, 0); err != nil {
			return
		}
	}
}

func tryReadZip(f *readAtWrapper) (r *zip.Reader, err error) {
	defer func() {
		if pn := recover(); pn != nil {
			err = fmt.Errorf("%v", pn)
			r = nil
		}
	}()

	size, err := f.Seek(0, io.SeekEnd)
	if err != nil {
		return
	}

	r, err = zip.NewReader(f, size)
	return
}

func findNextFileHeader(f io.ReadSeeker) (offset int64, err error) {
	start, err := f.Seek(0, 1)
	if err != nil {
		return -1, err
	}
	defer func() {
		if _, serr := f.Seek(start, 0); serr != nil && err == nil {
			err = serr
		}
	}()

	buf := make([]byte, 64*1024)
	toCmp := []byte{0x50, 0x4B, 0x03, 0x04}

	ok := 0
	offset = start

	for {
		n, err := f.Read(buf)
		if err != nil && err != io.EOF {
			return -1, err
		}

		if n == 0 {
			return -1, nil
		}

		for i := 0; i < n; i++ {
			if buf[i] == toCmp[ok] {
				ok++
				if ok == len(toCmp) {
					offset += int64(i) - int64(len(toCmp)-1)
					return offset, nil
				}
			} else {
				ok = 0
			}
		}

		offset += int64(n)
	}
}
