package main

import "syscall"

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	PAGE_READWRITE         = 0x04
)

var (
	kernel32      = syscall.NewLazyDLL("kernel32.dll")
	RtlMoveMemory = kernel32.NewProc("RtlMoveMemory")

	VirtualAlloc   = kernel32.NewProc("VirtualAlloc")
	VirtualProtect = kernel32.NewProc("VirtualProtect")
)
