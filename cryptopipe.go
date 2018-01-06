package main

import (
	"bufio"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"strings"
	//#include <unistd.h>
	"C"
)

var mode = "encrypt"

func main() {
	key := make([]byte, 32)
	var password string
	for i, v := range os.Args {
		if strings.Compare(v, "keygen") == 0 {
			prompt := C.CString("Please enter a password: ")
			prompt2 := C.CString("Again: ")
			sp := C.GoString(C.getpass(prompt))
			sp2 := C.GoString(C.getpass(prompt2))
			if strings.Compare(sp, sp2) == 0 {
				password = sp
				phash := sha256.Sum256([]byte(password))
				f, err := os.Create("key")
				if err != nil {
					fmt.Println("Unable to open key file because", err)
					os.Exit(-1)
				}
				f.Write(phash[:])
				f.Close()
				fmt.Println("Keyfile written!")
				os.Exit(-1)
			} else {
				fmt.Println("Passwords do not match.")
			}
			os.Exit(0)
		}
		if strings.Compare(v, "-p") == 0 {
			if i+1 >= len(os.Args) {
				fmt.Fprintln(os.Stderr, "Must pass a password to -p")
				os.Exit(-1)
			}
			password = os.Args[i+1]
			phash := sha256.Sum256([]byte(password))
			key = phash[:]
		}
		if strings.Compare(v, "-k") == 0 {
			if i+1 >= len(os.Args) {
				fmt.Fprintln(os.Stderr, "Parameter mismatch, must pass a filename to -k")
				os.Exit(-1)
			}
			f, err := os.Open(os.Args[i+1])
			if err != nil {
				fmt.Fprintln(os.Stderr, "Can't open keyfile!", err)
				os.Exit(-1)
			}
			f.Read(key[:32])
			f.Close()
		}
		if strings.Compare(v, "decrypt") == 0 {
			mode = "decrypt"
		}
	}
	writer := bufio.NewWriter(os.Stdout)
	reader := bufio.NewReader(os.Stdin)
	b, err := aes.NewCipher(key)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Problem:", err)
	}
	bs := b.BlockSize()
	iv := make([]byte, bs)
	bufsiz := 1048576
	buffer := make([]byte, bufsiz)
	if strings.Compare(mode, "encrypt") == 0 {
		rand.Read(iv)
		writer.Write(iv)
		e := cipher.NewCFBEncrypter(b, iv)
		for {
			read, err := reader.Read(buffer)
			if err != nil {
				if err != io.EOF {
					fmt.Fprintln(os.Stderr, err)
				}
				break
			}
			e.XORKeyStream(buffer[:read], buffer[:read])
			writer.Write(buffer[:read])
		}
		writer.Flush()
	} else if strings.Compare(mode, "decrypt") == 0 {
		read, err := reader.Read(iv)
		if err != nil || read != bs {
			fmt.Fprintln(os.Stderr, "Can't read IV!", err)
		}
		e := cipher.NewCFBDecrypter(b, iv)
		for {
			read, err := reader.Read(buffer)
			if err != nil {
				if err != io.EOF {
					fmt.Fprintln(os.Stderr, err)
				}
				break
			}
			e.XORKeyStream(buffer[:read], buffer[:read])
			writer.Write(buffer[:read])
		}
		writer.Flush()
	}
}
