#pragma once
#include <windows.h>
#include <winternl.h>

typedef BOOL(WINAPI* IsBadReadPtr_typedef)(CONST VOID* lp, UINT_PTR ucb);
typedef NTSTATUS(WINAPI* NtDeviceIoControlFile_typedef)(HANDLE FileHandle, HANDLE Event, PIO_APC_ROUTINE ApcRoutine, PVOID ApcContext, PIO_STATUS_BLOCK IoStatusBlock, ULONG IoControlCode, PVOID InputBuffer, ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength);
typedef DWORD(WINAPI* GetLogicalDrives_typedef)();
typedef UINT(WINAPI* GetDriveTypeA_typedef)(LPCSTR lpRootPathName);
typedef BOOL(WINAPI* GetVolumeInformationA_typedef)(LPCSTR lpRootPathName, LPSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize);
typedef HANDLE(WINAPI* CreateFileA_typedef)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
typedef DWORD(WINAPI* GetFileAttributesA_typedef)(LPCSTR lpFileName);
typedef DWORD(WINAPI* GetFileAttributesW_typedef)(LPCWSTR lpFileName);
typedef HANDLE(WINAPI* FindFirstFileA_typedef)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI* CreateProcessA_typedef)(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef BOOL(WINAPI* CreateProcessW_typedef)(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
typedef HMODULE(WINAPI* LoadLibraryA_typedef)(LPCSTR lpLibFileName); 
typedef void(WINAPI* KiUserExceptionDispatcher_typedef)(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context);
typedef NTSTATUS(NTAPI* NtContinue_typedef)(PCONTEXT ThreadContext, BOOLEAN RaiseAlert);
typedef SIZE_T(WINAPI* VirtualQuery_typedef)(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
typedef HWND(WINAPI* FindWindowA_typedef)(LPCSTR lpClassName, LPCSTR lpWindowName);
