#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <conio.h>
#include "Utils.h"

FILE* log_file = NULL;
bool loggingEnabled = false;
CRITICAL_SECTION log_critical_section;

void SetLogging(bool enable, const char* logFileName)
{
	InitializeCriticalSection(&log_critical_section);
	if (enable && logFileName)
	{
		log_file = fopen(logFileName, /*"a+t"*/"wt");
		log("Logging to file: %s\n", logFileName);
	}
	loggingEnabled = enable;
}

void logc(WORD col, const char* fmt, ...)
{
	if (!loggingEnabled || fmt == NULL)
		return;
	EnterCriticalSection(&log_critical_section);
	va_list va;
	if (log_file)
	{
		va_start(va, fmt);
		vfprintf(log_file, fmt, va);
		va_end(va);
		fflush(log_file);
	}

	if (stdout)
	{
		HANDLE hConsole = CreateFileA("CONOUT$", GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
		DWORD mode = 0;
		GetConsoleMode(hConsole, &mode);
		SetConsoleMode(hConsole, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
		int r, g, b;

		switch (col)
		{
		case FOREGROUND_WHITE:
			r = 240; g = 240; b = 240;  // Softer white
			break;
		case FOREGROUND_GREY:
			r = 128; g = 128; b = 128;  // Neutral gray
			break;
		case FOREGROUND_BLUE:
			r = 0; g = 120; b = 215;    // Windows 10 accent blue
			break;
		case FOREGROUND_CYAN:
			r = 0; g = 200; b = 200;    // Teal cyan
			break;
		case FOREGROUND_GREEN:
			r = 0; g = 180; b = 0;      // Rich green
			break;
		case FOREGROUND_LIME:
			r = 50; g = 205; b = 50;    // Lime green
			break;
		case FOREGROUND_YELLOW:
			r = 255; g = 215; b = 0;    // Golden yellow
			break;
		case FOREGROUND_ORANGE:
			r = 255; g = 140; b = 0;    // Dark orange
			break;
		case FOREGROUND_PINK:
			r = 255; g = 105; b = 180;  // Hot pink
			break;
		case FOREGROUND_MAGENTA:
			r = 186; g = 85; b = 211;   // Medium orchid
			break;
		case FOREGROUND_PURPLE:
			r = 138; g = 43; b = 226;   // Blue violet
			break;
		case FOREGROUND_RED:
			r = 220; g = 20; b = 60;    // Crimson
			break;
		case FOREGROUND_BROWN:
			r = 139; g = 69; b = 19;    // Saddle brown
			break;
		case FOREGROUND_TURQUOISE:
			r = 64; g = 224; b = 208;   // Turquoise
			break;
		default:
			r = 192; g = 192; b = 192;  // Default to light gray
			break;
		}

		printf("\x1b[38;2;%d;%d;%dm", r, g, b);
		
		va_start(va, fmt);
		vfprintf(stdout, fmt, va);
		va_end(va);

		printf("\x1b[38;2;%d;%d;%dm", 192, 192, 192);  // Set to "white" by default
		SetConsoleMode(hConsole, mode);
		CloseHandle(hConsole);
	}
	/*
	if (stdout)
	{
		//HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

		HANDLE hConsole = CreateFileA("CONOUT$", GENERIC_WRITE | GENERIC_READ, FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		// Save current text attributes
		CONSOLE_SCREEN_BUFFER_INFO consoleInfo;
		WORD saved_attributes;
		GetConsoleScreenBufferInfo(hConsole, &consoleInfo);
		saved_attributes = consoleInfo.wAttributes;

		// Set color to bright green
		SetConsoleTextAttribute(hConsole, col | FOREGROUND_INTENSITY);  // FOREGROUND_GREEN | FOREGROUND_INTENSITY

		va_start(va, fmt);
		vfprintf(stdout, fmt, va);
		va_end(va);

		SetConsoleTextAttribute(hConsole, saved_attributes);

		CloseHandle(hConsole);
	}
	*/
	LeaveCriticalSection(&log_critical_section);
}

void log(const char* fmt, ...)
{
	if (!loggingEnabled || fmt == NULL)
		return;
	EnterCriticalSection(&log_critical_section);
	va_list va;
	if (log_file)
	{
		va_start(va, fmt);
		vfprintf(log_file, fmt, va);
		va_end(va);
		fflush(log_file);
	}
	if (stdout)
	{
		va_start(va, fmt);
		vfprintf(stdout, fmt, va);
		va_end(va);
	}
	LeaveCriticalSection(&log_critical_section);
}

void LogKey(const char* keyName, DWORD addr, int keyLength)
{
	if (addr != 0)
	{
		log("%s (%08X): ", keyName, addr);
		if (keyLength > 16)
			log("\n");
		for (int i = 0; i < keyLength; i++)
		{
			if (i != 0 && (i % 16) == 0)
				log("\n");
			log("%02X ", (DWORD) * (((BYTE*)addr) + i));
		}
		log("\n");
	}
}

BYTE hexdigit(char hex)
{
	return (hex <= '9') ? hex - '0' : toupper(hex) - 'A' + 10;
}

BYTE hexbyte(const char* hex)
{
	if (*hex == '?')		// ?? is a wildcard and will be 00 - which means 00 matches with anything
		return 0;
	else
		return (hexdigit(*hex) << 4) | hexdigit(*(hex + 1));
}

BYTE *hexstring(const char * szHexString)
{
	BYTE searchSize = (BYTE)(strlen(szHexString) / 2);
	BYTE* searchHex = new BYTE[searchSize];

	for (BYTE i = 0; i < searchSize; i++)
	{
		searchHex[i] = hexbyte(&szHexString[i * 2]);
	}

	return searchHex;
}

DWORD FindHex(DWORD StartAddr, DWORD EndAddr, BYTE* searchHex, DWORD searchSize)
{
#ifdef _DEBUG
	log("FindHex called from %08X to %08X (searchSize: %08X)\n", StartAddr, EndAddr, searchSize);
#endif

	//DWORD dwOldProtect = 0;
	//VirtualProtect((LPVOID)StartAddr, EndAddr - StartAddr, PAGE_EXECUTE_READWRITE, &dwOldProtect);		// Sometimes parts of the section can not even have read access! (Scarface!)

	DWORD ret = -1L;
	DWORD i;
	BYTE* ptr = (BYTE*)StartAddr;
	DWORD Length = (EndAddr - StartAddr) - searchSize;
	BYTE* cmpptr = searchHex;
	DWORD matched = 0;
	DWORD mostmatched = 0;
	for (i = 0; i < Length; i++)
	{
		if ((*ptr == *cmpptr) || (*cmpptr == 0))
		{
			cmpptr++;
			matched++;
			if (matched == searchSize)
			{
				ret = ((DWORD)ptr) - (searchSize - 1);
				break;
			}
			if (mostmatched < matched)
				mostmatched = matched;
		}
		else
		{
			ptr -= matched;
			i -= matched;
			matched = 0;
			cmpptr = searchHex;
		}
		ptr++;
	}

	//DWORD dwNewProtect;
	//VirtualProtect((LPVOID)StartAddr, EndAddr - StartAddr, dwOldProtect, &dwNewProtect);

	return ret;
}

DWORD FindHexString(DWORD StartAddr, DWORD EndAddr, const char* szHexString, const char* szPurpose)
{
	DWORD i;
	DWORD ret = -1L;

#ifdef _DEBUG
	log("FindHexString called: \"%s\" from %08X to %08X\n", szHexString, StartAddr, EndAddr);
#endif

	BYTE searchSize = (BYTE)(strlen(szHexString) / 2);
	if (StartAddr < (EndAddr - searchSize))
	{
		BYTE* searchHex = new BYTE[searchSize];

		for (i = 0; i < searchSize; i++)
		{
			searchHex[i] = hexbyte(&szHexString[i * 2]);
		}

		ret = FindHex(StartAddr, EndAddr, searchHex, searchSize);

		delete[] searchHex;

		if (szPurpose != NULL)
			log("FindHexString(%08X, %08X, \"%s\", \"%s\") == %08X%s\n", StartAddr, EndAddr, szHexString, szPurpose, ret, ret == -1L ? "" : " FOUND!");
	}
	else
		logc(FOREGROUND_RED, "FindHexString StartAddr < (EndAddr - searchSize) failed: %08X < %08X\n", StartAddr, EndAddr);

	return ret;
}

std::vector<DWORD> FindAllHexString(DWORD StartAddr, DWORD EndAddr, const char* szHexString, const char* szPurpose)
{
	std::vector<DWORD> ret;

	while (true)
	{
		StartAddr = FindHexString(StartAddr, EndAddr, szHexString, szPurpose);
		if (StartAddr == -1L)
			break;
		ret.push_back(StartAddr++);
	}

	return ret;
}

BOOL GetSafeDiscVersionFromBuffer(BYTE* buffer, DWORD dwBufferSize, DWORD* pdwVersion, DWORD* pdwSubVersion, DWORD* pdwRevision)
{
	BOOL bRet = FALSE;
	if (buffer && dwBufferSize > 0)
	{
		// BoG_ *90.0&!! Yy> (alternative: 000001_!!!)
		DWORD offset = 0x20;
		DWORD AddrToVersion = FindHexString((DWORD)buffer, ((DWORD)buffer) + dwBufferSize, "426F475F202A39302E30262121202059793E0000000000000000000000000000", "Version String");
		if (AddrToVersion == -1)
		{
			AddrToVersion = FindHexString((DWORD)buffer, ((DWORD)buffer) + dwBufferSize, "3030303030315F21212100", "Version String v2");
			offset = 11;
		}

		if (AddrToVersion != -1)
		{
			*pdwVersion = *(DWORD*)(AddrToVersion + offset);
			*pdwSubVersion = *(DWORD*)(AddrToVersion + offset + 4);
			*pdwRevision = *(DWORD*)(AddrToVersion + offset + 8);

			log("SafeDisc Version: %d.%02d.%02d\n", *pdwVersion, *pdwSubVersion, *pdwRevision);
			bRet = TRUE;
		}
	}
	return bRet;
}

BOOL GetSafeDiscVersion(const char* szExeFile, DWORD* pdwVersion, DWORD* pdwSubVersion, DWORD* pdwRevision)
{
	BOOL bRet = FALSE;
	HANDLE hFile = CreateFile(szExeFile, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_ALWAYS, 0, 0);
	if (hFile != INVALID_HANDLE_VALUE)
	{
		DWORD dwFileSize = GetFileSize(hFile, NULL);
		DWORD dwBytesRead;
		BYTE* buffer = new BYTE[dwFileSize];
		ReadFile(hFile, buffer, dwFileSize, &dwBytesRead, NULL);
		bRet = GetSafeDiscVersionFromBuffer(buffer, dwBytesRead, pdwVersion, pdwSubVersion, pdwRevision);
		delete[] buffer;
	}
	CloseHandle(hFile);
	return bRet;
}

PIMAGE_SECTION_HEADER GetSectionByName(DWORD addr, const char* szName)
{
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)addr;
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((BYTE*)pidh + pidh->e_lfanew);

	PIMAGE_FILE_HEADER pifh = (PIMAGE_FILE_HEADER)&pinh->FileHeader;
	PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinh);

	for (WORD i = 0; i < pifh->NumberOfSections; i++)
	{
		if (_stricmp((char*)pish->Name, szName) == 0)
			return pish;
		pish++;
	}

	return NULL;
}

std::vector<PIMAGE_SECTION_HEADER> GetSections(DWORD addr)
{
	std::vector<PIMAGE_SECTION_HEADER> sections;
	PIMAGE_DOS_HEADER pidh = (PIMAGE_DOS_HEADER)addr;
	PIMAGE_NT_HEADERS pinh = (PIMAGE_NT_HEADERS)((BYTE*)pidh + pidh->e_lfanew);
	PIMAGE_FILE_HEADER pifh = (PIMAGE_FILE_HEADER)&pinh->FileHeader;
	PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinh);
	for (WORD i = 0; i < pifh->NumberOfSections; i++)
	{
		sections.push_back(pish);
		pish++;
	}
	return sections;
}

DWORD GetExeSizeInMemory()
{
	HMODULE hExe = GetModuleHandle(NULL);
	if (!hExe)
		return -1L;

	IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)hExe;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return -1L;

	IMAGE_NT_HEADERS* nt =
		(IMAGE_NT_HEADERS*)((BYTE*)hExe + dos->e_lfanew);

	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return -1L;

	return nt->OptionalHeader.SizeOfImage;
}

BOOL WriteProtectedDWORD(DWORD Addr, DWORD Value, bool logWrite)
{
	BOOL bRet = FALSE;
	DWORD old;
	if (VirtualProtectEx(GetCurrentProcess(), (void*)Addr, 4, PAGE_READWRITE, &old))
	{
		*((DWORD*)Addr) = Value;
		if (VirtualProtectEx(GetCurrentProcess(), (void*)Addr, 4, old, &old))
			bRet = TRUE;
	}

	if (logWrite)
	{
		if (bRet)
			log("WriteProtectedDWORD(%08X, %08X)\n", Addr, Value);
		else
			log("Failed to WriteProtectedDWORD(%08X, %08X) !!!!\n", Addr, Value);
	}
	return bRet;
}

BOOL WriteProtectedBYTE(DWORD Addr, BYTE Value, bool logWrite)
{
	BOOL bRet = FALSE;
	DWORD old;
	if (VirtualProtectEx(GetCurrentProcess(), (void*)Addr, 1, PAGE_READWRITE, &old))
	{
		*((BYTE*)Addr) = Value;
		if (VirtualProtectEx(GetCurrentProcess(), (void*)Addr, 1, old, &old))
			bRet = TRUE;
	}

	if (logWrite)
	{
		if (bRet)
			log("WriteProtectedBYTE(%08X, %02X)\n", Addr, (DWORD)Value);
		else
			log("Failed to WriteProtectedBYTE(%08X, %02X) !!!!\n", Addr, (DWORD)Value);
	}
	return bRet;
}

HRESULT PatchIat(HMODULE Module, PSTR ImportedModuleName, PSTR ImportedProcName, PVOID AlternateProc, PVOID* OldProc)
{
#define PtrFromRva( base, rva ) ( ( ((DWORD)( PBYTE ) base) ) + ((DWORD)rva) )
	PIMAGE_DOS_HEADER DosHeader = (PIMAGE_DOS_HEADER)Module;
	PIMAGE_NT_HEADERS NtHeader;
	PIMAGE_IMPORT_DESCRIPTOR ImportDescriptor;
	UINT Index;

	NtHeader = (PIMAGE_NT_HEADERS)PtrFromRva(DosHeader, DosHeader->e_lfanew);

	if (IMAGE_NT_SIGNATURE != NtHeader->Signature)
		return HRESULT_FROM_WIN32(ERROR_BAD_EXE_FORMAT);

	ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)PtrFromRva(DosHeader, NtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	for (Index = 0; ImportDescriptor[Index].Characteristics != 0; Index++)
	{
		PSTR dllName = (PSTR)PtrFromRva(DosHeader, ImportDescriptor[Index].Name);

		if (_strcmpi(dllName, ImportedModuleName) == 0)
		{
			PIMAGE_THUNK_DATA Thunk;
			PIMAGE_THUNK_DATA OrigThunk;

			if (!ImportDescriptor[Index].FirstThunk || !ImportDescriptor[Index].OriginalFirstThunk)
				return E_INVALIDARG;

			Thunk = (PIMAGE_THUNK_DATA)PtrFromRva(DosHeader, ImportDescriptor[Index].FirstThunk);
			OrigThunk = (PIMAGE_THUNK_DATA)PtrFromRva(DosHeader, ImportDescriptor[Index].OriginalFirstThunk);

			for (; OrigThunk->u1.Function != NULL; OrigThunk++, Thunk++)
			{
				if (OrigThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
					continue;

				PIMAGE_IMPORT_BY_NAME import = (PIMAGE_IMPORT_BY_NAME)PtrFromRva(DosHeader, OrigThunk->u1.AddressOfData);

				if (strcmp(ImportedProcName, (char*)import->Name) == 0)
				{
					DWORD junk;
					MEMORY_BASIC_INFORMATION thunkMemInfo;

					VirtualQuery(Thunk, &thunkMemInfo, sizeof(MEMORY_BASIC_INFORMATION));

					if (!VirtualProtect(thunkMemInfo.BaseAddress, thunkMemInfo.RegionSize, PAGE_EXECUTE_READWRITE, &thunkMemInfo.Protect))
						return HRESULT_FROM_WIN32(GetLastError());

					if (OldProc)
						*OldProc = (PVOID)(DWORD)Thunk->u1.Function;

					Thunk->u1.Function = (DWORD)AlternateProc;

					if (!VirtualProtect(thunkMemInfo.BaseAddress, thunkMemInfo.RegionSize, thunkMemInfo.Protect, &junk))
						return HRESULT_FROM_WIN32(GetLastError());

					return S_OK;
				}
			}

			return HRESULT_FROM_WIN32(ERROR_PROC_NOT_FOUND);
		}
	}

	return HRESULT_FROM_WIN32(ERROR_MOD_NOT_FOUND);
}

// Only useful as SafeDisc sometimes loops through to find the DLLs real address (rather than the hooked Shim address or IAT jmp)
DWORD FindRealAddress(const char* szDLLName, const char* szProcName, void* pChangeAddressTo, void** OriginalFunction)
{
	DWORD ret = -1L;
	DWORD dwChangeAddressTo = (DWORD)pChangeAddressTo;
	HMODULE lib = LoadLibraryEx(szDLLName, NULL, DONT_RESOLVE_DLL_REFERENCES);
	PIMAGE_NT_HEADERS header = (PIMAGE_NT_HEADERS)((BYTE*)lib + ((PIMAGE_DOS_HEADER)lib)->e_lfanew);
	PIMAGE_EXPORT_DIRECTORY exports = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)lib + header->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD* names = (DWORD*)((int)lib + exports->AddressOfNames);
	WORD* ords = (WORD*)((int)lib + exports->AddressOfNameOrdinals);
	DWORD* funcs = (DWORD*)((int)lib + exports->AddressOfFunctions);
	for (DWORD i = 0; i < exports->NumberOfNames; i++)
	{
		char* szFoundName = (char*)lib + (DWORD)names[i];
		if (szFoundName && _stricmp(szProcName, szFoundName) == 0)
		{
			// TODO: Worry about Ordinalbase ???
			ret = ((DWORD)lib) + (DWORD)funcs[ords[i]];

			log("Found Export: %s at %08X (FuncPtr: %08X)\n", szFoundName, ret, (DWORD)&funcs[ords[i]]);

			if (dwChangeAddressTo != 0)
			{
				WriteProtectedDWORD((DWORD)&funcs[ords[i]], dwChangeAddressTo - ((DWORD)lib));
			}

			break;
		}
	}
	if (OriginalFunction && ret != -1L)
		*OriginalFunction = (void*)ret;
	return ret;
}

void EnableDebugPriv()
{
	HANDLE hToken;
	LUID luid;
	TOKEN_PRIVILEGES tkp;

	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken);

	LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid);

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL);

	CloseHandle(hToken);
}

void InjectDCEAPIHook(DWORD pid)
{
	if (GetFileAttributes("DCEAPIHook.dll") != -1L)
	{
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		LPVOID loadLibraryAddr = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
		char szPath[MAX_PATH];
		GetFullPathNameA("DCEAPIHook.dll", MAX_PATH, szPath, NULL);
		LPVOID newMemory = (LPVOID)VirtualAllocEx(hProcess, NULL, strlen(szPath) + 1, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
		WriteProcessMemory(hProcess, newMemory, szPath, strlen(szPath) + 1, NULL);
		HANDLE hNewThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, newMemory, NULL, NULL);
		WaitForSingleObject(hNewThread, INFINITE);
		CloseHandle(hNewThread);
		CloseHandle(hProcess);
	}
}

bool EndsInTmp(const char* szFilename)
{
	bool ret = false;
	if (szFilename != NULL)
	{
		const char* dot = strrchr(szFilename, '.');
		if (_stricmp(dot, ".tmp") == 0)
			ret = true;
	}
	return ret;
}

DWORD ReverseBytes(DWORD value) { return ((value >> 24) & 0x000000FF) | ((value >> 8) & 0x0000FF00) | ((value << 8) & 0x00FF0000) | ((value << 24) & 0xFF000000); }

bool UnProtectAddress(BYTE* Addr, int size)
{
	bool ret = true;
	DWORD oldProtect;
	if (!VirtualProtect((LPVOID)Addr, size, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		printf("Failed to unprotect addr:  0x%X\n", (uintptr_t)Addr);
		ret = false;
	}
	return ret;
}

void UnProtect_memcpy(void* _Dst, void const* _Src, size_t _Size)
{
	DWORD oldProtect, oldProtect2;
	if (VirtualProtect((LPVOID)_Dst, _Size, PAGE_EXECUTE_READWRITE, &oldProtect))
	{
		memcpy(_Dst, _Src, _Size);
		VirtualProtect((LPVOID)_Dst, _Size, oldProtect, &oldProtect2);
		logc(FOREGROUND_RED | FOREGROUND_BLUE, "UnProtect_memcpy From: %X8 To %08X (Size: %X)\n", (uintptr_t)_Src, (uintptr_t)_Dst, _Size);
	}
	else
		logc(FOREGROUND_RED, "Failed to unprotect addr:  0x%X\n", (uintptr_t)_Dst);
}

BOOL bFirstGetch = TRUE;
char GetKey(bool bForce)
{
	char ret = 0;
	if (loggingEnabled && (bFirstGetch || bForce))
	{
		while (_kbhit()) 
			_getch(); // discard
		
		logc(FOREGROUND_RED, "Press any key...\n");
		ret = _getch();
		bFirstGetch = FALSE;
	}
	return ret;
}

#ifdef _M_X64
#define PPEB __readgsqword(0x60)
#else
#define PPEB __readfsdword(0x30)
#endif

uintptr_t GetBaseAddress()
{
	return (uintptr_t)(*(PVOID*)(PPEB + 0x10));
}

void CreateConsole()
{
	if (!AttachConsole(ATTACH_PARENT_PROCESS))
		AllocConsole();

	FILE* fDummy;
	freopen_s(&fDummy, "CONIN$", "r", stdin);
	freopen_s(&fDummy, "CONOUT$", "w", stderr);
	freopen_s(&fDummy, "CONOUT$", "w", stdout);
}

void ClearConsole()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
	CONSOLE_SCREEN_BUFFER_INFO csbi;
	DWORD consoleSize;
	DWORD charsWritten;
	COORD coordScreen = { 0, 0 };

	// Get the number of character cells in the current buffer
	if (!GetConsoleScreenBufferInfo(hConsole, &csbi))
		return;

	consoleSize = csbi.dwSize.X * csbi.dwSize.Y;

	// Fill the entire screen with blanks
	FillConsoleOutputCharacter(hConsole, ' ', consoleSize, coordScreen, &charsWritten);
	FillConsoleOutputAttribute(hConsole, csbi.wAttributes, consoleSize, coordScreen, &charsWritten);

	// Put the cursor at the top-left corner
	SetConsoleCursorPosition(hConsole, coordScreen);
}

void HideConsoleCursor()
{
	HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

	CONSOLE_CURSOR_INFO cursorInfo;
	GetConsoleCursorInfo(hConsole, &cursorInfo);

	cursorInfo.bVisible = FALSE;  // Set visibility to false
	SetConsoleCursorInfo(hConsole, &cursorInfo);
}

void WriteToFile(const char* szFilename, BYTE* data, int dataSize)
{
	FILE* fout = fopen(szFilename, "wb");
	if (fout)
	{
		fwrite(data, 1, dataSize, fout);
		fclose(fout);
	}
	else
		logc(FOREGROUND_RED, "Could not DumpToFile: %s\n", szFilename);
}

bool GetExecutableDirectory(char* outPath, DWORD size)
{
	char fullPath[MAX_PATH];

	// Get full path to the executable
	DWORD length = GetModuleFileNameA(NULL, fullPath, MAX_PATH);
	if (length == 0 || length == MAX_PATH)
		return false; // Failed or path was truncated

	// Copy to output buffer
	strncpy(outPath, fullPath, size);
	outPath[size - 1] = '\0';

	char* lastBackslash = strrchr(outPath, '\\');
	if (lastBackslash != NULL)
	{
		*lastBackslash = '\0';
		return true;
	}

	return false;
}

BOOL GetLoadedDllBaseAndSize(LPCSTR dllName, HMODULE* outBase, DWORD* outSize)
{
	HMODULE hMod = GetModuleHandleA(dllName);
	if (!hMod)
		return FALSE;

	BYTE* base = (BYTE*)hMod;
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)base;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(base + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	DWORD size = nt->OptionalHeader.SizeOfImage;
	if (outBase) *outBase = hMod;
	if (outSize) *outSize = size;
	return TRUE;
}

BOOL HasSafeSEH()
{
	HMODULE hMod = GetModuleHandle(NULL);
	if (!hMod) return FALSE;

	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMod;
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return FALSE;

	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMod + dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE) return FALSE;

	IMAGE_DATA_DIRECTORY dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];
	if (dir.VirtualAddress == 0 || dir.Size == 0) return FALSE;

	PIMAGE_LOAD_CONFIG_DIRECTORY32 cfg = (PIMAGE_LOAD_CONFIG_DIRECTORY32)((BYTE*)hMod + dir.VirtualAddress);

	if (cfg->SEHandlerTable != 0 && cfg->SEHandlerCount > 0)
	{
		DWORD HandlerCountOffset = ((DWORD)(&cfg->SEHandlerCount)) - ((DWORD)dos);
		log("SafeSEH is present. HandlerTable: %08X Count: %d\n", cfg->SEHandlerTable, cfg->SEHandlerCount);
		log("SafeSEH HandlerCountOffset: %08X\n", HandlerCountOffset);
		log("^ This is the offset to patch in the file. Make the 4 bytes at the location in the file = 0 to turn off SafeSEH.\n");
		return true;
	}
	else
		return false;
}

BOOL IsReadablePointer(void* ptr)
{
	MEMORY_BASIC_INFORMATION mbi;
	if (VirtualQuery(ptr, &mbi, sizeof(mbi)) == 0)
		return FALSE;

	if (mbi.State != MEM_COMMIT)
		return FALSE;

	if ((mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD)) != 0)
		return FALSE;

	// PAGE_READONLY, PAGE_READWRITE, etc. are readable
	return TRUE;
}

DWORD GetEntryPointFromBase(DWORD base)
{
	BYTE* baseAddr = reinterpret_cast<BYTE*>(base);
	PIMAGE_DOS_HEADER dos = reinterpret_cast<PIMAGE_DOS_HEADER>(baseAddr);
	if (dos->e_magic != IMAGE_DOS_SIGNATURE) return NULL;

	PIMAGE_NT_HEADERS64 nt64 = reinterpret_cast<PIMAGE_NT_HEADERS64>(baseAddr + dos->e_lfanew);
	if (nt64->Signature != IMAGE_NT_SIGNATURE) return NULL;

	// Check 32 vs 64
	if (nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
		// 64-bit
		DWORD64 entryRVA = reinterpret_cast<PIMAGE_NT_HEADERS64>(baseAddr + dos->e_lfanew)
			->OptionalHeader.AddressOfEntryPoint;
		return (DWORD)(baseAddr + entryRVA);
	}
	else if (nt64->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
		// 32-bit
		PIMAGE_NT_HEADERS32 nt32 = reinterpret_cast<PIMAGE_NT_HEADERS32>(baseAddr + dos->e_lfanew);
		DWORD entryRVA = nt32->OptionalHeader.AddressOfEntryPoint;
		return  (DWORD)(baseAddr + entryRVA);
	}

	return 0;
}

void RestrictProcessors(int CPUs)
{
	if (CPUs > 0)
	{
		HANDLE hProcess = GetCurrentProcess();

		// Example: Restrict process to run only on 8 CPUs max (stops Prototype from crashing)
		DWORD_PTR affinityMask = (1ULL << CPUs) - 1;
		/*
		switch (CPUs)
		{
		case 1:
			affinityMask = 1;
			break;
		case 2:
			affinityMask = 1 | 2;
			break;
		case 4:
			affinityMask = 1 | 2 | 4 | 8;
			break;
		case 8:
		default:
			affinityMask = 1 | 2 | 4 | 8 | 16 | 32 | 64 | 128;
			break;
		}*/

		if (!SetProcessAffinityMask(hProcess, affinityMask))
			log("Failed to set affinity: %lu\n", GetLastError());
		else
			log("Process affinity set successfully. CPU Count = %d\n", CPUs);
	}
}

BOOL GetDirectoryOfDLL(const char* dllName, char* outDir, DWORD outDirSize)
{
	if (!dllName || !outDir || outDirSize == 0)
		return FALSE;

	HMODULE hMod = GetModuleHandle(dllName);
	if (!hMod)
		return FALSE; // DLL not loaded

	TCHAR fullPath[MAX_PATH];
	DWORD len = GetModuleFileName(hMod, fullPath, MAX_PATH);
	if (len == 0 || len == MAX_PATH)
		return FALSE;

	// Find the last backslash in the path
	LPTSTR lastSlash = strrchr(fullPath, '\\');
	if (!lastSlash)
		return FALSE; // malformed path?

	*lastSlash = TEXT('\0'); // terminate string at last '\'

	if (strlen(fullPath) >= outDirSize)
		return FALSE; // buffer too small

	strcpy(outDir, fullPath);
	return TRUE;
}