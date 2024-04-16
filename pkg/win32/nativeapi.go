package win32

import (
	"fmt"
	"syscall"
	"time"
	"unsafe"
)

// https://ntdoc.m417z.com/ntopenprocess
// NtOpenProcess(
//
//	_Out_ PHANDLE ProcessHandle,
//	_In_ ACCESS_MASK DesiredAccess,
//	_In_ POBJECT_ATTRIBUTES ObjectAttributes,
//	_In_opt_ PCLIENT_ID ClientId
//	);
func NtOpenProcess(desiredAccess uintptr, pid uintptr) (syscall.Handle, error) {
	var (
		processHandle    syscall.Handle
		objectAttributes OBJECT_ATTRIBUTES
		clientId         CLIENT_ID
	)
	objectAttributes.Length = uint32(unsafe.Sizeof(objectAttributes))
	objectAttributes.Attributes = 0
	objectAttributes.RootDirectory = 0
	objectAttributes.SecurityDescriptor = 0
	objectAttributes.SecurityQualityOfService = 0

	clientId.UniqueProcess = pid

	ret, _, err := procNtOpenProcess.Call(
		uintptr(unsafe.Pointer(&processHandle)),
		desiredAccess,
		uintptr(unsafe.Pointer(&objectAttributes)),
		uintptr(unsafe.Pointer(&clientId)),
	)
	if ret != 0 {
		return processHandle, err
	}
	return processHandle, nil
}

// https://ntdoc.m417z.com/ntallocatevirtualmemory
// NtAllocateVirtualMemory(
//
//	_In_ HANDLE ProcessHandle,
//	_Inout_ _At_(*BaseAddress, _Readable_bytes_(*RegionSize) _Writable_bytes_(*RegionSize) _Post_readable_byte_size_(*RegionSize)) PVOID *BaseAddress,
//	_In_ ULONG_PTR ZeroBits,
//	_Inout_ PSIZE_T RegionSize,
//	_In_ ULONG AllocationType,
//	_In_ ULONG Protect
//	);
func NtAllocateVirtualMemory(
	ProcessHandle syscall.Handle,
	BaseAddress *PVOID,
	ZeroBits ULONG_PTR,
	RegionSize *SIZE_T,
	AllocationType ULONG,
	Protect ULONG,
) NTSTATUS {
	ret, _, _ := procNtAllocateVirtualMemory.Call(
		uintptr(ProcessHandle),
		uintptr(unsafe.Pointer(BaseAddress)), // IN OUT
		uintptr(ZeroBits),
		uintptr(unsafe.Pointer(RegionSize)), // IN OUT changes value to actual size of allocated memmory (it's rounded up at the end)
		uintptr(AllocationType),
		uintptr(Protect),
	)
	return NTSTATUS(ret)
}

// https://ntdoc.m417z.com/ntprotectvirtualmemory
// NtProtectVirtualMemory(
//
//	_In_ HANDLE ProcessHandle,
//	_Inout_ PVOID *BaseAddress,
//	_Inout_ PSIZE_T RegionSize,
//	_In_ ULONG NewProtect,
//	_Out_ PULONG OldProtect
//	);
func NtProtectVirtualMemory(
	ProcessHandle syscall.Handle,
	BaseAddress *PVOID,
	NumberOfBytesToProtect *SIZE_T,
	NewAccessProtection ULONG,
	OldAccessProtection *ULONG,
) NTSTATUS {
	ret, _, _ := procNtProtectVirtualMemory.Call(
		uintptr(ProcessHandle),
		uintptr(unsafe.Pointer(BaseAddress)),
		uintptr(unsafe.Pointer(NumberOfBytesToProtect)),
		uintptr(NewAccessProtection),
		uintptr(unsafe.Pointer(OldAccessProtection)),
	)
	return NTSTATUS(ret)
}

// https://ntdoc.m417z.com/ntwritevirtualmemory
// NtWriteVirtualMemory(
//
//	_In_ HANDLE ProcessHandle,
//	_In_opt_ PVOID BaseAddress,
//	_In_reads_bytes_(BufferSize) PVOID Buffer,
//	_In_ SIZE_T BufferSize,
//	_Out_opt_ PSIZE_T NumberOfBytesWritten
//	);
func NtWriteVirtualMemory(processHandle syscall.Handle, baseAddress *PVOID, buffer []byte) (uintptr, error) {
	var bytesWritten uintptr
	ret, _, err := procNtWriteVirtualMemory.Call(
		uintptr(processHandle),
		uintptr(unsafe.Pointer(baseAddress)),
		uintptr(unsafe.Pointer(&buffer[0])),
		uintptr(len(buffer)),
		uintptr(unsafe.Pointer(&bytesWritten)),
	)
	if ret != 0 {
		return bytesWritten, err
	}
	return bytesWritten, nil
}

// https://ntdoc.m417z.com/ntcreatethread
// NtCreateThread(
//
//	_Out_ PHANDLE ThreadHandle,
//	_In_ ACCESS_MASK DesiredAccess,
//	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
//	_In_ HANDLE ProcessHandle,
//	_Out_ PCLIENT_ID ClientId,
//	_In_ PCONTEXT ThreadContext,
//	_In_ PINITIAL_TEB InitialTeb,
//	_In_ BOOLEAN CreateSuspended
//	);
func NtCreateThread(processHandle HANDLE, startAddress *PVOID, parameter uintptr, createSuspended bool) (HANDLE, NTSTATUS) {
	var threadHandle HANDLE
	var objectAttributes OBJECT_ATTRIBUTES
	var clientID CLIENT_ID

	objectAttributes.Length = uint32(unsafe.Sizeof(objectAttributes))
	objectAttributes.Attributes = 0
	objectAttributes.RootDirectory = 0
	objectAttributes.SecurityDescriptor = 0
	objectAttributes.SecurityQualityOfService = 0

	var iSuspended uintptr = 0
	if createSuspended {
		iSuspended = 1
	}

	ret, _, _ := procNtCreateThread.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		uintptr(THREAD_ALL_ACCESS),
		uintptr(unsafe.Pointer(&objectAttributes)),
		uintptr(processHandle),
		uintptr(unsafe.Pointer(&clientID)),
		uintptr(unsafe.Pointer(startAddress)),
		parameter,
		iSuspended,
	)
	return threadHandle, NTSTATUS(ret)
}

// https://ntdoc.m417z.com/ntcreatethreadex
// NtCreateThreadEx(
//
//	_Out_ PHANDLE ThreadHandle,
//	_In_ ACCESS_MASK DesiredAccess,
//	_In_opt_ POBJECT_ATTRIBUTES ObjectAttributes,
//	_In_ HANDLE ProcessHandle,
//	_In_ PUSER_THREAD_START_ROUTINE StartRoutine,
//	_In_opt_ PVOID Argument,
//	_In_ ULONG CreateFlags, // THREAD_CREATE_FLAGS_*
//	_In_ SIZE_T ZeroBits,
//	_In_ SIZE_T StackSize,
//	_In_ SIZE_T MaximumStackSize,
//	_In_opt_ PPS_ATTRIBUTE_LIST AttributeList
//	);
func NtCreateThreadEx(processHandle syscall.Handle, startAddress *PVOID, parameter uintptr, CreateFlags uintptr) (syscall.Handle, NTSTATUS) {
	var (
		threadHandle     syscall.Handle
		objectAttributes OBJECT_ATTRIBUTES
	)

	objectAttributes.Length = uint32(unsafe.Sizeof(objectAttributes))
	objectAttributes.Attributes = 0
	objectAttributes.RootDirectory = 0
	objectAttributes.SecurityDescriptor = 0
	objectAttributes.SecurityQualityOfService = 0

	//     ntCTEx(&ht, 0x1FFFFF, NULL, ph, (LPTHREAD_START_ROUTINE) lb, rb, FALSE, NULL, NULL, NULL, NULL);
	ret, _, _ := procNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		uintptr(0x1FFFFF),
		uintptr(0),
		uintptr(processHandle),
		uintptr(unsafe.Pointer(startAddress)),
		parameter,
		CreateFlags,
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&objectAttributes)),
	)
	return threadHandle, NTSTATUS(ret)
}

func NtCreateThreadEx2(processHandle syscall.Handle, startAddress uintptr, parameter uintptr, createSuspended bool) (syscall.Handle, error) {
	var threadHandle syscall.Handle
	objectAttributes := OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(OBJECT_ATTRIBUTES{})),
	}
	var flags uint32
	if createSuspended {
		flags |= THREAD_CREATE_FLAGS_CREATE_SUSPENDED
	}
	ret, _, err := procNtCreateThreadEx.Call(
		uintptr(unsafe.Pointer(&threadHandle)),
		uintptr(0x1FFFFF),
		0,
		uintptr(processHandle),
		startAddress,
		parameter,
		uintptr(flags),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(&objectAttributes)),
		uintptr(0),
		uintptr(0),
	)
	if ret != 0 {
		return 0, fmt.Errorf("NtCreateThreadEx failed: %v", err)
	}
	return threadHandle, nil
}

func NtWaitForSingleObject(objectHandle syscall.Handle, alertable bool, timeout time.Duration) NTSTATUS {
	var iAlertable int8 = 0
	if alertable {
		iAlertable = 1
	}
	ret, _, _ := procNtWaitForSingleObject.Call(
		uintptr(objectHandle),
		uintptr(iAlertable),
		uintptr(timeout.Nanoseconds()/1000000), // Convert to milliseconds
	)
	return NTSTATUS(ret)
}

func NtWaitForSingleObject2(threadHandle syscall.Handle) NTSTATUS {
	ret, _, _ := procNtWaitForSingleObject.Call(uintptr(threadHandle), uintptr(syscall.INFINITE))
	return NTSTATUS(ret)
}

// https://ntdoc.m417z.com/rtlcreateuserthread
// RtlCreateUserThread(
//
//	_In_ HANDLE ProcessHandle,
//	_In_opt_ PSECURITY_DESCRIPTOR ThreadSecurityDescriptor,
//	_In_ BOOLEAN CreateSuspended,
//	_In_opt_ ULONG ZeroBits,
//	_In_opt_ SIZE_T MaximumStackSize,
//	_In_opt_ SIZE_T CommittedStackSize,
//	_In_ PUSER_THREAD_START_ROUTINE StartAddress,
//	_In_opt_ PVOID Parameter,
//	_Out_opt_ PHANDLE ThreadHandle,
//	_Out_opt_ PCLIENT_ID ClientId
//	);
func RtlCreateUserThread(processHandle HANDLE, startAddress *PVOID, parameter uintptr, createSuspended bool) (HANDLE, NTSTATUS) {
	var threadHandle HANDLE

	var attributes uintptr
	if createSuspended {
		attributes = 0x4 // CREATE_SUSPENDED
	}
	ret, _, _ := procRtlCreateUserThread.Call(
		uintptr(processHandle),
		uintptr(0),
		uintptr(THREAD_CREATE_FLAGS_CREATE_SUSPENDED),
		uintptr(0),
		uintptr(0),
		uintptr(0),
		uintptr(unsafe.Pointer(startAddress)),
		parameter,
		attributes,
		0,
	)
	return threadHandle, NTSTATUS(ret)
}
