package main

import (
	"fmt"
	"syscall"
	"unsafe"
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	MEM_RELEASE            = 0x8000
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_READWRITE         = 0x04

	INFINITE = 0xFFFFFFFF

	CREATE_PROCESS            = 0x0080
	CREATE_THREAD             = 0x0002
	DUP_HANDLE                = 0x0040
	QUERY_INFORMATION         = 0x0400
	QUERY_LIMITED_INFORMATION = 0x1000
	SET_INFORMATION           = 0x0200
	SET_QUOTA                 = 0x0100
	SUSPEND_RESUME            = 0x0800
	TERMINATE                 = 0x0001
	VM_OPERATION              = 0x0008
	VM_READ                   = 0x0010
	VM_WRITE                  = 0x0020
	ALL_ACCESS                = 0x001F0FFF
)

var (
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	RtlMoveMemory       = kernel32.NewProc("RtlMoveMemory")
	VirtualAlloc        = kernel32.NewProc("VirtualAlloc")
	VirtualAllocEx      = kernel32.NewProc("VirtualAllocEx")
	VirtualProtect      = kernel32.NewProc("VirtualProtect")
	VirtualProtectEx    = kernel32.NewProc("VirtualProtectEx")
	OpenProcess         = kernel32.NewProc("OpenProcess")
	WriteProcessMemory  = kernel32.NewProc("WriteProcessMemory")
	GetProcAddress      = kernel32.NewProc("GetProcAddress")
	CreateRemoteThread  = kernel32.NewProc("CreateRemoteThread")
	WaitForSingleObject = kernel32.NewProc("WaitForSingleObject")
	GetExitCodeThread   = kernel32.NewProc("GetExitCodeThread")
	CloseHandle         = kernel32.NewProc("CloseHandle")
	VirtualFreeEx       = kernel32.NewProc("VirtualFreeEx ")
)

// Reserves, commits, or changes the state of a region of pages in the virtual address space of the calling process. Memory allocated by this function is automatically initialized to zero.
// RTFM at https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualalloc
//
// lpAddress - The starting address of the region to allocate. [..] If this parameter is NULL, the system determines where to allocate the region.
//
// dwSize - The size of the region, in bytes. If the lpAddress parameter is NULL, this value is rounded up to the next page boundary.
//
// flAllocationType - The type of memory allocation. (https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants) [..] When allocating dynamic memory for an enclave, the flProtect parameter must be PAGE_READWRITE or PAGE_EXECUTE_READWRITE.
//
// flProtect - The memory protection for the region of pages to be allocated.
//
// returns the base address of the allocated region of pages, nil otherwise
func VirtualAllocCall(lpAddress uintptr, dwSize uintptr, flAllocationType uintptr, flProtect uintptr) (uintptr, error) {
	fmt.Println("[*] VirtualAlloc")
	retval, _, err := VirtualAlloc.Call(
		lpAddress,
		dwSize,
		flAllocationType,
		flProtect,
	)
	if err != nil && err.Error() != "The operation completed successfully." {
		return retval, err
	}

	return retval, nil
}

// Reserves, commits, or changes the state of a region of memory within the virtual address space of a specified process. The function initializes the memory it allocates to zero.
// RTFM at https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
//
// hProcess - The handle to a process.
//
// lpAddress - The starting address of the region to allocate. [..] If this parameter is NULL, the system determines where to allocate the region.
//
// dwSize - The size of the region, in bytes. If the lpAddress parameter is NULL, this value is rounded up to the next page boundary.
//
// flAllocationType - The type of memory allocation. (https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants) [..] When allocating dynamic memory for an enclave, the flProtect parameter must be PAGE_READWRITE or PAGE_EXECUTE_READWRITE.
//
// flProtect - The memory protection for the region of pages to be allocated.
//
// returns the base address of the allocated region of pages, nil otherwise
func VirtualAllocExCall(hProcess uintptr, lpAddress uintptr, dwSize uintptr, flAllocationType uintptr, flProtect uintptr) (uintptr, error) {
	fmt.Println("[*] VirtualAllocEx")
	retval, _, err := VirtualAllocEx.Call(
		hProcess,
		lpAddress,
		dwSize,
		flAllocationType,
		flProtect,
	)
	if err != nil && err.Error() != "The operation completed successfully." {
		return retval, err
	}

	return retval, nil
}

// Changes the protection on a region of committed pages in the virtual address space of the calling process.
// RTFM at https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect
//
// lpAddress - The address of the starting page of the region of pages whose access protection attributes are to be changed.
//
// dwSize - The size of the region whose access protection attributes are to be changed, in bytes.
//
// flNewProtect - The memory protection option. (https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants)
//
// lpflOldProtect - A pointer to a variable that receives the previous access protection value of the first page in the specified region of pages.
//
// returns nil of success, otherwise err if the retval is zero
func VirtualProtectCall(lpAddress uintptr, dwSize uintptr, flNewProtect uintptr, lpflOldProtect uintptr) error {
	fmt.Println("[*] VirtualProtect")
	retval, _, err := VirtualProtect.Call(
		lpAddress,
		dwSize,
		flNewProtect,
		lpflOldProtect,
	)
	if retval == 0 {
		return err
	}

	return nil
}

// Changes the protection on a region of committed pages in the virtual address space of a specified process.
// RTFM at https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotectex
//
// hProcess - A handle to the process whose memory protection is to be changed.
//
// lpAddress - The address of the starting page of the region of pages whose access protection attributes are to be changed.
//
// dwSize - The size of the region whose access protection attributes are to be changed, in bytes.
//
// flNewProtect - The memory protection option. (https://learn.microsoft.com/en-us/windows/win32/Memory/memory-protection-constants)
//
// lpflOldProtect - A pointer to a variable that receives the previous access protection value of the first page in the specified region of pages.
//
// returns nil of success, otherwise err if the lpflOldProtect is zero
func VirtualProtectExCall(hProcess uintptr, lpAddress uintptr, dwSize uintptr, flNewProtect uintptr) (uintptr, error) {
	fmt.Println("[*] VirtualProtectEx")
	var lpflOldProtect uintptr
	_, _, err := VirtualProtectEx.Call(
		hProcess,
		lpAddress,
		dwSize,
		flNewProtect,
		lpflOldProtect,
	)
	if lpflOldProtect == 0 {
		return lpflOldProtect, err
	}

	return lpflOldProtect, nil
}

// Writes data to an area of memory in a specified process. The entire area to be written to must be accessible or the operation fails.
// RTFM at https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
//
// hProcess - A handle to the process memory to be modified. The handle must have PROCESS_VM_WRITE and PROCESS_VM_OPERATION access to the process.
//
// lpBaseAddress - A pointer to the base address in the specified process to which data is written. Before data transfer occurs, the system verifies that all data in the base address and memory of the specified size is accessible for write access, and if it is not accessible, the function fails.
//
// lpBuffer - A pointer to the buffer that contains data to be written in the address space of the specified process.
//
// nSize - The number of bytes to be written to the specified process.
//
// returns lpNumberOfBytesWritten, otherwise err if lpNumberOfBytesWritten == 0
func WriteProcessMemoryCall(hProcess uintptr, lpBaseAddress uintptr, lpBuffer uintptr, nSize uintptr) (int, error) {
	fmt.Println("[*] WriteProcessMemory")
	lpNumberOfBytesWritten, _, err := WriteProcessMemory.Call(
		hProcess,
		lpBaseAddress,
		lpBuffer,
		nSize,
	)

	if lpNumberOfBytesWritten == 0 {
		return int(lpNumberOfBytesWritten), err
	}

	return int(lpNumberOfBytesWritten), nil
}

// Opens an existing local process object.
// RTFM at https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
//
// dwDesiredAccess - The access to the process object. This access right is checked against the security descriptor for the process. (https://learn.microsoft.com/en-us/windows/win32/procthread/process-security-and-access-rights)
//
// bInheritHandle - If this value is TRUE, processes created by this process will inherit the handle. Otherwise, the processes do not inherit this handle.
//
// dwProcessId - The identifier of the local process to be opened.
//
// returns open handle to the specified process, NULL otherwise
func OpenProcessCall(dwDesiredAccess uintptr, bInheritHandle uintptr, dwProcessId uintptr) (uintptr, error) {
	fmt.Println("[*] OpenProcess")
	procHandle, _, err := OpenProcess.Call(
		dwDesiredAccess,
		bInheritHandle,
		dwProcessId,
	)

	if procHandle == 0 {
		return 0, err
	}

	return procHandle, nil
}

// Copies the contents of a source memory block to a destination memory block, and supports overlapping source and destination memory blocks.
// RTFM at https://learn.microsoft.com/en-us/windows/win32/devnotes/rtlmovememory
//
// Destination - A pointer to the destination memory block to copy the bytes to.
//
// Source - A pointer to the source memory block to copy the bytes from.
//
// Length - The number of bytes to copy from the source to the destination.
//
// returns err
func RtlMoveMemoryCall(Destination uintptr, Source uintptr, Length uintptr) error {
	fmt.Println("[*] RtlMoveMemory")
	_, _, err := RtlMoveMemory.Call(
		Destination,
		Source,
		Length,
	)

	return err
}

// Retrieves the address of an exported function (also known as a procedure) or variable from the specified dynamic-link library (DLL).
// RTFM at https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getprocaddress
//
// hModule - A handle to the DLL module that contains the function or variable. The LoadLibrary, LoadLibraryEx, LoadPackagedLibrary, or GetModuleHandle function returns this handle.
//
// lpProcName - The function or variable name, or the function's ordinal value. If this parameter is an ordinal value, it must be in the low-order word; the high-order word must be zero.
//
// returns address of the exported function or variable, NULL otherwise
func GetProcAddressCall(hModule uintptr, lpProcName uintptr) (uintptr, error) {
	fmt.Println("[*] GetProcAddress")
	procAddress, _, err := GetProcAddress.Call(
		hModule,
		lpProcName,
	)
	if procAddress == 0 {
		return 0, err
	}

	return procAddress, nil
}

// Creates a thread that runs in the virtual address space of another process.
// RTFM at https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
//
// hProcess - A handle to the process in which the thread is to be created.
//
// lpThreadAttributes - A pointer to a SECURITY_ATTRIBUTES structure that specifies a security descriptor for the new thread and determines whether child processes can inherit the returned handle. If lpThreadAttributes is NULL, the thread gets a default security descriptor and the handle cannot be inherited.  (https://learn.microsoft.com/en-us/previous-versions/windows/desktop/legacy/aa379560(v=vs.85))
//
// dwStackSize - The initial size of the stack, in bytes.
//
// lpStartAddress - A pointer to the application-defined function of type LPTHREAD_START_ROUTINE to be executed by the thread and represents the starting address of the thread in the remote process.
//
// lpParameter - A pointer to a variable to be passed to the thread function.
//
// dwCreationFlags - The flags that control the creation of the thread. (O, CREATE_SUSPENDED, STACK_SIZE_PARAM_IS_A_RESERVATION)
//
// lpThreadId - A pointer to a variable that receives the thread identifier.
//
// returns a handle to the new thread, NULL otherwise
func CreateRemoteThreadCall(hProcess uintptr, lpThreadAttributes uintptr, dwStackSize uintptr, lpStartAddress uintptr, lpParameter uintptr, dwCreationFlags uintptr) (uintptr, error) {
	fmt.Println("[*] CreateRemoteThread")
	var lpThreadId uint32 = 0
	remoteThread, _, err := CreateRemoteThread.Call(
		hProcess,
		lpThreadAttributes,
		dwStackSize,
		lpStartAddress,
		lpParameter,
		dwCreationFlags,
		uintptr(unsafe.Pointer(&lpThreadId)),
	)

	if remoteThread == 0 {
		return remoteThread, err
	}

	return remoteThread, nil
}

// Waits until the specified object is in the signaled state or the time-out interval elapses.
// RTFM at https://learn.microsoft.com/en-us/windows/win32/api/synchapi/nf-synchapi-waitforsingleobject
//
// hHandle - A handle to the object.
//
// dwMilliseconds - The time-out interval, in milliseconds. If a nonzero value is specified, the function waits until the object is signaled or the interval elapses. If dwMilliseconds is zero, the function does not enter a wait state if the object is not signaled; it always returns immediately. If dwMilliseconds is INFINITE, the function will return only when the object is signaled.
//
// returns uintptr code
func WaitForSingleObjectCall(hHandle uintptr, dwMilliseconds uintptr) (uintptr, error) {
	fmt.Println("[*] WaitForSingleObject")
	retval, _, err := WaitForSingleObject.Call(
		hHandle,
		dwMilliseconds,
	)

	return retval, err
}

// Retrieves the termination status of the specified thread.
// RTFM at https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getexitcodethread
//
// hThread - A handle to the thread.
//
// lpExitCode - A pointer to a variable to receive the thread termination status.
//
// returns a nonzero value upon success, 0 otherwise
func GetExitCodeThreadCall(hThread uintptr) (int, error) {
	fmt.Println("[*] GetExitCodeThread")
	var lpExitCode uintptr = 0
	_, _, err := GetExitCodeThread.Call(
		hThread,
		lpExitCode,
	)
	return int(lpExitCode), err
}

// Closes an open object handle.
// RTFM at https://learn.microsoft.com/en-us/windows/win32/api/handleapi/nf-handleapi-closehandle
//
// hObject - A valid handle to an open object.
//
// returns a nonzero value upon success, 0 otherwise
func CloseHandleCall(hObject uintptr) (int, error) {
	fmt.Println("[*] CloseHandle")
	retval, _, err := CloseHandle.Call(hObject)
	return int(retval), err
}

// Releases, decommits, or releases and decommits a region of memory within the virtual address space of a specified process.
// RTFM at https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfreeex
//
// hProcess - A handle to a process. The function frees memory within the virtual address space of the process.
//
// lpAddress - A pointer to the starting address of the region of memory to be freed.
//
// dwSize - The size of the region of memory to free, in bytes.
//
// dwFreeType - The type of free operation.
//
// returns a nonzero value upon success, 0 otherwise
func VirtualFreeExCall(hProcess uintptr, lpAddress uintptr, dwSize uintptr, dwFreeType uintptr) (int, error) {
	fmt.Println("[*] VirtualFreeEx")
	retval, _, err := VirtualFreeEx.Call(
		hProcess,
		lpAddress,
		dwSize,
		dwFreeType,
	)
	return int(retval), err
}
