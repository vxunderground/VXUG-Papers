// Package apkparser parses AndroidManifest.xml and resources.arsc from Android APKs.
package manifest

import (
	"common"
	"fmt"
	"io"
	"log"
	"os"
)

type ApkParser struct {
	apkPath string
	zip     *ZipReader

	encoder   ManifestEncoder
	resources *ResourceTable
}

// save manifest to disk for binary patching

func (p *ApkParser) SaveManifestToDisk() {

	file := p.zip.File["AndroidManifest.xml"]

	if file == nil {
		fmt.Errorf("Failed to find %s in APK!", "AndroidManifest.xml")
	}

	if err := file.Open(); err != nil {
		panic(err)
	}
	defer file.Close()

	// open output file
	fo, err := os.Create(common.ManifestBinaryPath)
	if err != nil {
		panic(err)
	}
	// close fo on exit and check for its returned error
	defer func() {
		if err := fo.Close(); err != nil {
			panic(err)
		}
	}()

	// make a buffer to keep chunks that are read
	buf := make([]byte, 1024)
	for {
		// read a chunk
		n, err := file.Read(buf)
		if err != nil && err != io.EOF {
			panic(err)
		}
		if n == 0 {
			break
		}

		// write a chunk
		if _, err := fo.Write(buf[:n]); err != nil {
			panic(err)
		}
	}
}

// Calls ParseApkReader
func ParseApk(path string, encoder ManifestEncoder) {
	f, zipErr := os.Open(path)
	if zipErr != nil {
		log.Panic("Failed to open apk")
	}
	defer f.Close()

	ParseApkReader(f, encoder)
}

// Parse APK's Manifest, including resolving refences to resource values.
// encoder expects an XML encoder instance, like Encoder from encoding/xml package.
//
// zipErr != nil means the APK couldn't be opened. The manifest will be parsed
// even when resourcesErr != nil, just without reference resolving.
func ParseApkReader(r io.ReadSeeker, encoder ManifestEncoder) {
	zip, zipErr := OpenZipReader(r)
	if zipErr != nil {
		log.Panic("Failed to open zip reader")
	}
	defer zip.Close()

	ParseApkWithZip(zip, encoder)
}

// Parse APK's Manifest, including resolving refences to resource values.
// encoder expects an XML encoder instance, like Encoder from encoding/xml package.
//
// Use this if you already opened the zip with OpenZip or OpenZipReader before.
// This method will not Close() the zip.
//
// The manifest will be parsed even when resourcesErr != nil, just without reference resolving.
func ParseApkWithZip(zip *ZipReader, encoder ManifestEncoder) {
	apkParser := ApkParser{
		zip:     zip,
		encoder: encoder,
	}

	fmt.Println("\t--Parsing resources...")
	apkParser.parseResources()

	fmt.Println("\t--Parsing manifest...")
	apkParser.ParseXml("AndroidManifest.xml")

	apkParser.SaveManifestToDisk()

}

// Prepare the ApkParser instance, load resources if possible.
// encoder expects an XML encoder instance, like Encoder from encoding/xml package.
//
// This method will not Close() the zip, you are still the owner.
func NewParser(zip *ZipReader, encoder ManifestEncoder) (parser *ApkParser) {
	parser = &ApkParser{
		zip:     zip,
		encoder: encoder,
	}
	parser.parseResources()
	return
}

func (p *ApkParser) parseResources() {
	if p.resources != nil {
		log.Panic("resources is not nil")
	}

	defer func() {
		if r := recover(); r != nil {
			log.Panic("recover() not nil")
		}
	}()

	resourcesFile := p.zip.File["resources.arsc"]
	if resourcesFile == nil {
		log.Panic("resource.arsc not found")
	}

	if err := resourcesFile.Open(); err != nil {
		log.Panic("Failed to open resources.arsc: %s", err.Error())
	}
	defer resourcesFile.Close()
	p.resources = ParseResourceTable(resourcesFile)
}

func (p *ApkParser) ParseXml(name string) {

	file := p.zip.File[name]

	if file == nil {
		log.Panicf("Failed to find %s in APK!", name)
	}

	if err := file.Open(); err != nil {
		log.Panic("Failed to open manifest")
	}
	defer file.Close()

	var lastErr error
	for file.Next() {
		if err := ParseXml(&myReader{r: file}, p.encoder, p.resources); err != nil {
			lastErr = err
		}
	}

	if lastErr == ErrPlainTextManifest {
		log.Panic("Manifest in plaintext")
	}
}
