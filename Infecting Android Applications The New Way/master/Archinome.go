// author: Thatskriptkid (www.orderofsixangles.com)
// You can use my kaitai struct for binary manifest.
// https://github.com/thatskriptkid/Kaitai-Struct-Android-Manifest-binary-XML

package main

import (
	"common"
	mydex "dex"
	"encoding/xml"
	"fmt"
	"log"
	"manifest"
	"os"
)

func main() {

	//setup logging
	logFile, err := os.OpenFile("apkinfector.log", os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatal(err)
	}

	defer logFile.Close()

	log.SetOutput(logFile)

	manifestPlainFile, err := os.Create(manifest.PlainPath) // create/truncate the file
	if err != nil {
		log.Panic("Failed to create AndroidManifest plaintext", err)
	}

	enc := xml.NewEncoder(manifestPlainFile)

	enc.Indent("", "\t")

	fmt.Println("Parsing APK...")
	manifest.ParseApk(os.Args[1], enc)

	//close before reading
	manifestPlainFile.Close()

	fmt.Println("Patching APK")
	fmt.Println("\t--Patching manifest...")
	manifest.Patch()

	fmt.Println("\t--Patching dex...")
	mydex.Patch()

	fmt.Println("Injecting...")
	common.Inject(os.Args[1], os.Args[2])

	fmt.Println("Done! Now you should sign your apk")
}
