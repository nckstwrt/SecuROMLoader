#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <winternl.h>
#include <profileapi.h>
#include "Config.h"
#include "NString.h"
#include "Utils.h"
#include "minhook/MinHook.h"
#include "Typedefs.h"
#include "CRCFixer.h"
#include "DeviceIoControlHook.h"
#include "Compatibility.h"
#include <vector>

// Tested Games:
// Crysis - 07.34.0014
// Command and Conquer 3 (v1.9) - 07.33.0017
// Prototype - 07.39.0006
// Pro Evolution Soccer 3 - 4.85.04
// Magic The Gathering - Battlegrounds - 4.85.07
// Counterstrike - Condition Zero - 5.00.03 (May need VersionInjector (or just rename the exe))
// Grand Theft Auto - Vice City 1.0 - 4.84.69
// Grand Theft Auto - Vice City 1.1 - 4.84.75
// Manhunt - 5.03.03
// Max Payne 2 - 4.85.07 - Needs SafeSEH turned off in the exe manually (log file will tell you how)
// Football Manager 2008 - 07.34.0013 (has SafeSEH but works anyway)


NtDeviceIoControlFile_typedef NtDeviceIoControlFile_Orig;
GetLogicalDrives_typedef GetLogicalDrives_Orig;
GetDriveTypeA_typedef GetDriveTypeA_Orig;
GetVolumeInformationA_typedef GetVolumeInformationA_Orig;
FindFirstFileA_typedef FindFirstFileA_Orig;
CreateFileA_typedef CreateFileA_Orig;
CreateFileA_typedef CreateFileA_Orig_KBase;
CreateProcessA_typedef CreateProcessA_Orig;
CreateProcessW_typedef CreateProcessW_Orig;
LoadLibraryA_typedef LoadLibraryA_Orig;
KiUserExceptionDispatcher_typedef KiUserExceptionDispatcher_Orig;
NtContinue_typedef NtContinue_Orig;

HMODULE hOurModule;
Config config;
bool logCreateFile = false;
int HWBPStage = 0;
int HWBPCheckDone = 0;
const char* CDROMDriveLetter = NULL;

DWORD WINAPI GetLogicalDrives_Hook()
{
	DWORD ret = GetLogicalDrives_Orig();
	if (CDROMDriveLetter)
	{
		char driveLetter = toupper(CDROMDriveLetter[0]);
		if (driveLetter >= 'A' && driveLetter <= 'Z')
		{
			ret |= 1 << (driveLetter - 'A');
			logc(FOREGROUND_GREEN, "GetLogicalDrives_Hook: Adding %c as a valid drive\n", driveLetter);
		}
	}
	return ret;
}

UINT WINAPI GetDriveTypeA_Hook(LPCSTR lpRootPathName)
{
	if (CDROMDriveLetter && lpRootPathName && toupper(lpRootPathName[0]) == toupper(CDROMDriveLetter[0]))
	{
		logc(FOREGROUND_GREEN, "GetDriveTypeA_Hook = %s IS A CDROM!\n", lpRootPathName ? lpRootPathName : "NULL");
		return DRIVE_CDROM;
	}
	log("GetDriveTypeA_Hook = %s\n", lpRootPathName ? lpRootPathName : "NULL");
	return GetDriveTypeA_Orig(lpRootPathName);
}

BOOL WINAPI GetVolumeInformationA_Hook(LPCSTR lpRootPathName, LPSTR lpVolumeNameBuffer, DWORD nVolumeNameSize, LPDWORD lpVolumeSerialNumber, LPDWORD lpMaximumComponentLength, LPDWORD lpFileSystemFlags, LPSTR lpFileSystemNameBuffer, DWORD nFileSystemNameSize)
{
	logc(FOREGROUND_BLUE, "GetVolumeInformationA_Hook: lpRootPathName: %s\n", lpRootPathName ? lpRootPathName : "NULL");
	BOOL ret = GetVolumeInformationA_Orig(lpRootPathName, lpVolumeNameBuffer, nVolumeNameSize, lpVolumeSerialNumber, lpMaximumComponentLength, lpFileSystemFlags, lpFileSystemNameBuffer, nFileSystemNameSize);
	const char* CDROMVolumeName = config.GetValue("CDROMVolumeName");
	if (CDROMVolumeName && CDROMDriveLetter && lpVolumeNameBuffer && strlen(CDROMVolumeName) < nVolumeNameSize && toupper(lpRootPathName[0]) == toupper(CDROMDriveLetter[0]))
	{
		strcpy(lpVolumeNameBuffer, CDROMVolumeName);
		logc(FOREGROUND_BLUE, "GetVolumeInformationA_Hook: Replacing VolumeName with: %s\n", lpVolumeNameBuffer);

		if (lpFileSystemNameBuffer && strlen("CDFS") < nFileSystemNameSize)
		{
			strcpy(lpFileSystemNameBuffer, "CDFS");
			logc(FOREGROUND_BLUE, "GetVolumeInformationA_Hook: Replacing FileSystemName with: %s\n", lpFileSystemNameBuffer);
		}
		ret = TRUE;
	}
	return ret;
}

HANDLE WINAPI CreateFileA_Hook(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	std::string strFileName;
	if (lpFileName)
	{
		strFileName = config.GetFileMapping(lpFileName);
		lpFileName = strFileName.c_str();
	}

	if (CDROMDriveLetter)
	{
		NString drivePath = NString::Format("\\\\.\\%c:", toupper(CDROMDriveLetter[0]));
		NString FileNameUpper = NString(lpFileName).ToUpper();
		if (drivePath == FileNameUpper)
		{
			logc(FOREGROUND_LIME, "Redirecting CreateFileA of CDROM drive %s to NUL device\n", (LPCSTR)drivePath);
			lpFileName = "NUL";
		}
	}
	HANDLE ret = CreateFileA_Orig(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	if (logCreateFile && lpFileName && _stricmp(lpFileName, "CONOUT$") != 0)
		log("CreateFileA_Hook Hook - lpFileName: %s ret: %08X\n", lpFileName == NULL ? "!NULL!" : lpFileName, ret);

	return ret;
}

HANDLE WINAPI CreateFileA_Hook_KBase(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
	std::string strFileName;
	if (lpFileName)
	{
		strFileName = config.GetFileMapping(lpFileName);
		lpFileName = strFileName.c_str();
	}
	HANDLE ret = CreateFileA_Orig_KBase(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);

	if (logCreateFile && lpFileName && _stricmp(lpFileName, "CONOUT$") != 0)
		log("CreateFileA_Hook_KBase Hook - lpFileName: %s ret: %08X\n", lpFileName == NULL ? "!NULL!" : lpFileName, ret);

	return ret;
}

int InjectSelf(DWORD pid)
{
	char szSecDrvEmuDLLPath[MAX_PATH];

	GetModuleFileName(hOurModule, szSecDrvEmuDLLPath, MAX_PATH);

	log("Injecting DLL %s\n", szSecDrvEmuDLLPath);

	// Open Process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) // Not INVALID_HANDLE_VALUE...Strangely
	{
		log("Process found, but cannot open handle\n");
		return -1;
	}

	// Get the address of our LoadLibraryA function. This is assuming our address for LoadLibrary will be the same as our target processes 
	LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

	// Get full path name of the target dll
	char szPath[MAX_PATH];
	GetFullPathNameA(szSecDrvEmuDLLPath, MAX_PATH, szPath, NULL);

	// Create Memory in Target Process to hold the DLL's filename
	LPVOID newMemory = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(szPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (newMemory == NULL)
	{
		log("Could not allocate memory inside the target process\n");
		return -1;
	}

	// Write the fullpath filename into the target process
	BOOL bWritten = WriteProcessMemory(hProcess, newMemory, szPath, strlen(szPath) + 1, NULL);
	if (bWritten == 0)
	{
		log("There were no bytes written to the process's address space.\n");
		return -1;
	}

	// Create Remote Thread to run LoadLibrary with our fullpath
	HANDLE hNewThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, newMemory, NULL, NULL);
	if (hNewThread == NULL)
	{
		log("Could not create remote thread in target process\n");
	}

	// Wait for it to run
	WaitForSingleObject(hNewThread, INFINITE);

	// Clean up
	CloseHandle(hNewThread);
	CloseHandle(hProcess);

	log("Injecting into pid %d\n", pid);

	return 0;
}

BOOL WINAPI CreateProcessA_Hook(LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
	log("CreateProcessA Hook (%s) (%s)\n", (lpApplicationName == NULL) ? "" : lpApplicationName, (lpCommandLine == NULL) ? "" : lpCommandLine);

	const DWORD isCreateSuspended = dwCreationFlags & CREATE_SUSPENDED;
	if (!isCreateSuspended) dwCreationFlags |= CREATE_SUSPENDED;

	if (!CreateProcessA_Orig(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation))
		return FALSE;

	InjectSelf(lpProcessInformation->dwProcessId);

	if (!isCreateSuspended)
		ResumeThread(lpProcessInformation->hThread);
	return TRUE;
}


BOOL WINAPI CreateProcessW_Hook(LPCWSTR lpApplicationName, LPWSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCWSTR lpCurrentDirectory, LPSTARTUPINFOW lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation)
{
	log("CreateProcessW Hook: %ls\n", lpApplicationName);

	const DWORD isCreateSuspended = dwCreationFlags & CREATE_SUSPENDED;
	if (!isCreateSuspended) dwCreationFlags |= CREATE_SUSPENDED;

	if (!CreateProcessW_Orig(lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes, bInheritHandles, dwCreationFlags, lpEnvironment, lpCurrentDirectory, lpStartupInfo, lpProcessInformation))
		return FALSE;

	InjectSelf(lpProcessInformation->dwProcessId);

	if (!isCreateSuspended)
		ResumeThread(lpProcessInformation->hThread);
	return TRUE;
}

HMODULE WINAPI LoadLibraryA_Hook(LPCSTR lpLibFileName)
{
	static DWORD TableClass = 0;

	if (lpLibFileName)
		log("LoadLibraryA_Hook: Loading %s\n", lpLibFileName);

	HMODULE ret = LoadLibraryA_Orig(lpLibFileName);

	ApplyDLLCompatibilityPatches(lpLibFileName);

	return ret;
}

bool NtContinueLogging = false;
void WINAPI KiUserExceptionDispatcher_RealHook(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context)
{
	if (ExceptionRecord->ExceptionCode == 0xC0000094)	// STATUS_INTEGER_DIVIDE_BY_ZERO
	{
		// Most likely a SecuROM 4 + 5 anti-debug trickery. Turn off NtContinue logging else it takes forever.
		NtContinueLogging = false;
		return;
	}
	/*
	logc(FOREGROUND_YELLOW, "ExceptionCode: %08X\n", ExceptionRecord->ExceptionCode);
	logc(FOREGROUND_YELLOW, "KiUserExceptionDispatcher_Hook: ExceptionRecord: %08X Context: %08X\n", ExceptionRecord, Context);
	logc(FOREGROUND_YELLOW, "DR0: %08X DR1: %08X DR2: %08X DR3: %08X\n", Context->Dr0, Context->Dr1, Context->Dr2, Context->Dr3);
	logc(FOREGROUND_YELLOW, "DR6: %08X DR7: %08X\n", Context->Dr6, Context->Dr7);
	logc(FOREGROUND_YELLOW, "EIP: %08X\n", Context->Eip);
	*/
	if (ExceptionRecord->ExceptionCode == 0xC000001D)	// STATUS_ILLEGAL_INSTRUCTION
	{
		HWBPStage = 1;
	}
	else
	{
		if (HWBPStage >= 1 && ExceptionRecord->ExceptionCode == 0x80000004)	// STATUS_SINGLE_STEP  (EXCEPTION_BREAKPOINT == 0x80000003)
		{
			HWBPStage++;
		}
		else
			HWBPStage = 0;
	}
	//logc(FOREGROUND_YELLOW, "HWBPStage: %d\n", HWBPStage);
}

void __declspec(naked) WINAPI KiUserExceptionDispatcher_Hook(PEXCEPTION_RECORD ExceptionRecord, PCONTEXT Context)
{
	// C000001D STATUS_ILLEGAL_INSTRUCTION
	// 80000004 STATUS_SINGLE_STEP
	__asm
	{
		MOV EAX, [ESP + 4]
		MOV ECX, [ESP]
		PUSH EAX
		PUSH ECX
		CALL KiUserExceptionDispatcher_RealHook
		jmp KiUserExceptionDispatcher_Orig
	}
}

NTSTATUS WINAPI NtContinue_Hook(PCONTEXT Context, BOOLEAN RaiseAlert)
{
	if (NtContinueLogging)
	{
		logc(FOREGROUND_PURPLE, "NtContinue_Hook: ThreadContext: %08X RaiseAlert: %d\n", Context, RaiseAlert);
		logc(FOREGROUND_PURPLE, "DR0: %08X DR1: %08X DR2: %08X DR3: %08X\n", Context->Dr0, Context->Dr1, Context->Dr2, Context->Dr3);
		logc(FOREGROUND_PURPLE, "DR6: %08X DR7: %08X\n", Context->Dr6, Context->Dr7);
		logc(FOREGROUND_PURPLE, "EIP: %08X\n", Context->Eip);
	}

	if (HWBPStage == 5)
	{
		logc(FOREGROUND_RED, "End of HWBP detection!\n");
		//Context->Dr0 = Context->Dr1 = Context->Dr2 = Context->Dr3 = Context->Dr6 = Context->Dr7 = 0;
		if (HWBPCheckDone++ == 1)
		{
			CRCFixer();
			GetKey(true);
		}
		HWBPStage = 0;
	}

	return NtContinue_Orig(Context, RaiseAlert);
}

void SecuROMLoader(HMODULE hModule)
{
	hOurModule = hModule;
	config.LoadConfig("version.json");

	if (config.GetBool("logging"))
	{
		CreateConsole();
		HideConsoleCursor();
		NString logFile = config.GetValue("logFile");
		SetLogging(true, logFile.IsEmpty() ? NULL : (LPCSTR)logFile.Replace("ProcessID", NString::Format("%d", GetCurrentProcessId())));
		logCreateFile = config.GetBool("logCreateFile");
	}
	else
		SetLogging(false);

	char szExeFile[MAX_PATH];
	GetModuleFileNameA(NULL, szExeFile, MAX_PATH);
	NString csExeFile = szExeFile;
	NString csCommandLine = GetCommandLine();

	MH_STATUS status = MH_Initialize();

	DisableThreadLibraryCalls(hModule);

	log("Version.DLL Loaded!\n");
	log("Loaded by .exe: %s\n", (LPCSTR)csExeFile);
	log("CommandLine: %s\n", (LPCSTR)csCommandLine);

	if (HasSafeSEH())
	{
		logc(FOREGROUND_RED, "The executable has SafeSEH enabled. This could cause crashes with some games (like Max Payne 2).\n");
		logc(FOREGROUND_RED, "You may need to disable SafeSEH in the executable using a PE Editor.\n");
		GetKey(true);	
	}
	
	CDROMDriveLetter = config.GetValue("CDROMDriveLetter");
	if (CDROMDriveLetter == NULL)
	{
		logc(FOREGROUND_YELLOW, "CDROMDriveLetter not set from config\n");
		CDROMDriveLetter = "L";
	}
	logc(FOREGROUND_GREEN, "Using CDROMDriveLetter: %s\n", CDROMDriveLetter);

	if (status != MH_OK)
	{
		log("Minhook init failed!\n");
		return;
	}

	if (MH_CreateHookApi(L"ntdll", "NtDeviceIoControlFile", &NtDeviceIoControlFile_Hook, reinterpret_cast<LPVOID*>(&NtDeviceIoControlFile_Orig)) != MH_OK)
	{
		log("Unable to hook NtDeviceIoControlFile\n");
		GetKey(true);
		return;
	}

	if (MH_CreateHookApi(L"kernel32", "GetLogicalDrives", &GetLogicalDrives_Hook, reinterpret_cast<LPVOID*>(&GetLogicalDrives_Orig)) != MH_OK)
	{
		log("Unable to hook GetLogicalDrives\n");
		return;
	}

	if (MH_CreateHookApi(L"kernel32", "GetDriveTypeA", &GetDriveTypeA_Hook, reinterpret_cast<LPVOID*>(&GetDriveTypeA_Orig)) != MH_OK)
	{
		log("Unable to hook GetDriveTypeA\n");
		return;
	}

	if (MH_CreateHookApi(L"kernel32", "GetVolumeInformationA", &GetVolumeInformationA_Hook, reinterpret_cast<LPVOID*>(&GetVolumeInformationA_Orig)) != MH_OK)
	{
		log("Unable to hook GetVolumeInformationA\n");
		return; 
	}

	FARPROC pCreateFileA_K32 = NULL, pCreateFileA_KBase = NULL;
	HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
	HMODULE hKernelBase = GetModuleHandleA("kernelbase.dll");

	pCreateFileA_K32 = GetProcAddress(hKernel32, "CreateFileA");
	if (hKernelBase)
		pCreateFileA_KBase = GetProcAddress(hKernelBase, "CreateFileA");

	if (pCreateFileA_K32 != pCreateFileA_KBase)
	{
		if (MH_CreateHook(pCreateFileA_K32, CreateFileA_Hook, (LPVOID*)&CreateFileA_Orig) != MH_OK)
		{
			log("Unable to hook CreateFileA from kernel32.dll\n");
			return;
		}
		if (MH_CreateHook(pCreateFileA_KBase, CreateFileA_Hook_KBase, (LPVOID*)&CreateFileA_Orig_KBase) != MH_OK)
		{
			log("Unable to hook CreateFileA from kernelbase.dll\n");
			return;
		}
	}
	else
	{
		if (MH_CreateHook(pCreateFileA_K32, CreateFileA_Hook, (LPVOID*)&CreateFileA_Orig) != MH_OK)
		{
			log("Unable to hook CreateFileA from kernel32.dll\n");
			return;
		}
	}

	if ((status = MH_CreateHookApi(L"kernel32", "CreateProcessA", &CreateProcessA_Hook, reinterpret_cast<LPVOID*>(&CreateProcessA_Orig))) != MH_OK)
	{
		log("Unable to hook CreateProcessA: %d\n", status);
		GetKey(true);
		return;
	}

	if (MH_CreateHookApi(L"kernel32", "CreateProcessW", &CreateProcessW_Hook, reinterpret_cast<LPVOID*>(&CreateProcessW_Orig)) != MH_OK)
	{
		log("Unable to hook CreateProcessW\n");
		GetKey(true);
		return;
	}

	if (MH_CreateHookApi(L"kernel32", "LoadLibraryA", LoadLibraryA_Hook, reinterpret_cast<LPVOID*>(&LoadLibraryA_Orig)) != MH_OK)
	{
		log("Unable to hook LoadLibraryA\n");
		return;
	}

	if (MH_CreateHookApi(L"ntdll", "KiUserExceptionDispatcher", &KiUserExceptionDispatcher_Hook, reinterpret_cast<LPVOID*>(&KiUserExceptionDispatcher_Orig)) != MH_OK)
	{
		log("Unable to hook KiUserExceptionDispatcher\n");
		return;
	}

	if (MH_CreateHookApi(L"ntdll", "NtContinue", &NtContinue_Hook, reinterpret_cast<LPVOID*>(&NtContinue_Orig)) != MH_OK)
	{
		log("Unable to hook NtContinue\n");
		return;
	}

	if (MH_EnableHook(MH_ALL_HOOKS) != MH_OK)
	{
		log("Enable Hooks Failed!\n");
		return;
	}

	log("Hooks Complete!\n");
}

