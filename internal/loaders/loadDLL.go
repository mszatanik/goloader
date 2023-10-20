package loaders

import (
	"fmt"
	"syscall"
	"unsafe"

	"github.com/mszatanik/goloader/pkg/win32"
)

func loadDLL(filePath string, pid uint32) {
	// OpenProcess
	remoteProcHandle, err := win32.OpenProcessCall(
		win32.CREATE_THREAD,
		uintptr(uint32(0)),
		uintptr(pid),
	)

	if remoteProcHandle == 0 {
		panic(fmt.Sprintf("[-] OpenProcess failed: %s", err))
	}

	// GetProcAddress
	loadLibraryAPointer, err := syscall.BytePtrFromString("LoadLibraryA")
	if err != nil {
		panic(fmt.Sprintf("[-] LoadLibraryA conversion failed: %s", err))
	}

	loadLibraryAAddress, err := win32.GetProcAddressCall(win32.Kernel32.Handle(), (uintptr)(unsafe.Pointer(loadLibraryAPointer)))
	_, _, err = win32.GetProcAddress.Call(
		win32.Kernel32.Handle(),
		(uintptr)(unsafe.Pointer(loadLibraryAPointer)),
	)
	if loadLibraryAAddress == 0 {
		panic(fmt.Sprintf("[-] GetProcAddress failed: %s", err))
	}

	// CreateRemoteThread
	path, err := syscall.UTF16PtrFromString(filePath)
	remoteThread, err := win32.CreateRemoteThreadCall(
		remoteProcHandle,
		0,
		0,
		loadLibraryAAddress,
		uintptr(*path),
		0,
	)
	if remoteThread == 0 {
		panic(fmt.Sprintf("[-] CreateRemoteThread failed: %s", err))
	}

	// CloseHandle
	exitCode, err := win32.CloseHandleCall(remoteProcHandle)
	if exitCode == 0 {
		panic(fmt.Sprintf("[-] remoteProcHandle failed: %s", err))
	}
}
