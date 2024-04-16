package win32

import "syscall"

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	MEM_RELEASE            = 0x8000
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_EXECUTE_READ      = 0x20
	PAGE_READWRITE         = 0x04

	INFINITE = 0xFFFFFFFF

	CREATE_PROCESS            = 0x0080
	CREATE_THREAD             = 0x0002
	DUP_HANDLE                = 0x0040
	QUERY_INFORMATION         = 0x0400
	QUERY_LIMITED_INFORMATION = 0x1000
	SET_INFORMATION           = 0x0200
	SET_QUOTA                 = 0x0100
	CREATE_SUSPENDED          = 0x00000004
	SUSPEND_RESUME            = 0x0800
	TERMINATE                 = 0x0001
	VM_OPERATION              = 0x0008
	VM_READ                   = 0x0010
	VM_WRITE                  = 0x0020
	ALL_ACCESS                = 0x001F0FFF

	THREAD_CREATE_FLAGS_CREATE_SUSPENDED   = 0x00000001
	THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH = 0x00000002
	THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x00000004

	PROCESS_ALL_ACCESS = 0x00100000

	THREAD_DIRECT_IMPERSONATION      = 0x0200
	THREAD_GET_CONTEXT               = 0x0008
	THREAD_IMPERSONATE               = 0x0100
	THREAD_QUERY_INFORMATION         = 0x0040
	THREAD_QUERY_LIMITED_INFORMATION = 0x0800
	THREAD_SET_CONTEXT               = 0x0010
	THREAD_SET_INFORMATION           = 0x0020
	THREAD_SET_LIMITED_INFORMATION   = 0x0400
	THREAD_SET_THREAD_TOKEN          = 0x0080
	THREAD_SUSPEND_RESUME            = 0x0002
	THREAD_TERMINATE                 = 0x0001
	THREAD_ALL_ACCESS                = THREAD_DIRECT_IMPERSONATION | THREAD_GET_CONTEXT | THREAD_IMPERSONATE | THREAD_QUERY_INFORMATION | THREAD_QUERY_LIMITED_INFORMATION | THREAD_SET_CONTEXT | THREAD_SET_INFORMATION | THREAD_SET_LIMITED_INFORMATION | THREAD_SET_THREAD_TOKEN | THREAD_SUSPEND_RESUME | THREAD_TERMINATE

	CONTEXT_CONTROL = 0x00000001
)

var (
	Kernel32 = syscall.NewLazyDLL("kernel32.dll")

	RtlMoveMemory       = Kernel32.NewProc("RtlMoveMemory")
	VirtualAlloc        = Kernel32.NewProc("VirtualAlloc")
	VirtualAllocEx      = Kernel32.NewProc("VirtualAllocEx")
	VirtualProtect      = Kernel32.NewProc("VirtualProtect")
	VirtualProtectEx    = Kernel32.NewProc("VirtualProtectEx")
	OpenProcess         = Kernel32.NewProc("OpenProcess")
	OpenThread          = Kernel32.NewProc("OpenThread")
	SuspendThread       = Kernel32.NewProc("SuspendThread")
	WriteProcessMemory  = Kernel32.NewProc("WriteProcessMemory")
	GetProcAddress      = Kernel32.NewProc("GetProcAddress")
	CreateRemoteThread  = Kernel32.NewProc("CreateRemoteThread")
	WaitForSingleObject = Kernel32.NewProc("WaitForSingleObject")
	GetExitCodeThread   = Kernel32.NewProc("GetExitCodeThread")
	CloseHandle         = Kernel32.NewProc("CloseHandle")
	VirtualFreeEx       = Kernel32.NewProc("VirtualFreeEx")
	EnumProcesses       = Kernel32.NewProc("EnumProcesses")
	CreateProcessA      = Kernel32.NewProc("CreateProcessA")
	GetThreadContext    = Kernel32.NewProc("GetThreadContext")
	SetThreadContext    = Kernel32.NewProc("SetThreadContext")
	ReadProcessMemory   = Kernel32.NewProc("ReadProcessMemory")
)

var (
	modntdll = syscall.NewLazyDLL("ntdll.dll")

	procNtOpenProcess           = modntdll.NewProc("NtOpenProcess")
	procNtCurrentProcess        = modntdll.NewProc("NtCurrentProcess")
	procNtAllocateVirtualMemory = modntdll.NewProc("NtAllocateVirtualMemory")
	procNtProtectVirtualMemory  = modntdll.NewProc("NtProtectVirtualMemory")
	procNtWriteVirtualMemory    = modntdll.NewProc("NtWriteVirtualMemory")
	procRtlCreateUserThread     = modntdll.NewProc("RtlCreateUserThread")
	procNtCreateThread          = modntdll.NewProc("NtCreateThread")
	procNtCreateThreadEx        = modntdll.NewProc("NtCreateThreadEx")
	procNtWaitForSingleObject   = modntdll.NewProc("NtWaitForSingleObject")
	NtUnmapViewOfSection        = modntdll.NewProc("NtUnmapViewOfSection")
)

type (
	HANDLE    uintptr
	NTSTATUS  int32
	PVOID     uintptr
	SIZE_T    uintptr
	ULONG     uint32
	ULONG_PTR uintptr
)

type CLIENT_ID struct {
	UniqueProcess uintptr
	UniqueThread  uintptr
}

type OBJECT_ATTRIBUTES struct {
	Length                   uint32
	RootDirectory            uintptr
	ObjectName               uintptr
	Attributes               uint32
	SecurityDescriptor       uintptr
	SecurityQualityOfService uintptr
}
