#ifndef _UTILS_H_
#define _UTILS_H_

#include <windows.h>
#include <stdio.h>
#include <vector>

extern FILE* log_file;

void SetLogging(bool enable, const char* logFileName = NULL);
void logc(WORD col, const char* fmt, ...);
void log(const char* fmt, ...);
void LogKey(const char *keyName, DWORD addr, int keyLength = 16);
BYTE hexdigit(char hex);
BYTE hexbyte(const char* hex);
BYTE* hexstring(const char* szHexString);
DWORD FindHex(DWORD StartAddr, DWORD EndAddr, BYTE *searchHex, DWORD searchSize);
DWORD FindHexString(DWORD StartAddr, DWORD EndAddr, const char *szHexString, const char *szPurpose = NULL);
std::vector<DWORD> FindAllHexString(DWORD StartAddr, DWORD EndAddr, const char* szHexString, const char* szPurpose = NULL);
BOOL GetSafeDiscVersionFromBuffer(BYTE *buffer, DWORD dwBufferSize, DWORD *pdwVersion, DWORD *pdwSubVersion, DWORD *pdwRevision);
BOOL GetSafeDiscVersion(const char *szExeFile, DWORD *pdwVersion, DWORD *pdwSubVersion, DWORD *pdwRevision);
PIMAGE_SECTION_HEADER GetSectionByName(DWORD addr, const char *szName);
std::vector<PIMAGE_SECTION_HEADER> GetSections(DWORD addr);
DWORD GetExeSizeInMemory();
BOOL WriteProtectedDWORD(DWORD Addr, DWORD Value, bool logWrite = true);
BOOL WriteProtectedBYTE(DWORD Addr, BYTE Value, bool logWrite = true);
HRESULT PatchIat(HMODULE Module, PSTR ImportedModuleName, PSTR ImportedProcName, PVOID AlternateProc, PVOID *OldProc);
DWORD FindRealAddress(const char *szDLLName, const char *szProcName, void* pChangeAddressTo = 0, void **OriginalFunction = NULL);
void EnableDebugPriv();
void InjectDCEAPIHook(DWORD pid);
bool EndsInTmp(const char* szFilename);
DWORD ReverseBytes(DWORD value);
bool UnProtectAddress(BYTE* Addr, int size);
void UnProtect_memcpy(void* _Dst, void const* _Src, size_t _Size);
char GetKey(bool bForce = false);
uintptr_t GetBaseAddress();
void CreateConsole();
void ClearConsole();
void HideConsoleCursor();
void WriteToFile(const char* szFilename, BYTE* data, int dataSize);
BOOL GetLoadedDllBaseAndSize(LPCSTR dllName, HMODULE* outBase, DWORD* outSize);
BOOL HasSafeSEH();
BOOL IsReadablePointer(void* ptr);
DWORD GetEntryPointFromBase(DWORD base);
void RestrictProcessors(int CPUs);
BOOL GetDirectoryOfDLL(const char* dllName, char* outDir, DWORD outDirSize);

#ifdef FOREGROUND_BLUE
#undef FOREGROUND_BLUE
#undef FOREGROUND_GREEN
#undef FOREGROUND_RED
#endif

enum ForegroundColor
{
	FOREGROUND_WHITE,
	FOREGROUND_BLUE,
	FOREGROUND_GREEN,
	FOREGROUND_RED,
	FOREGROUND_GREY,
	FOREGROUND_CYAN,
	FOREGROUND_LIME,
	FOREGROUND_YELLOW,
	FOREGROUND_ORANGE,
	FOREGROUND_PINK,
	FOREGROUND_MAGENTA,
	FOREGROUND_PURPLE,
	FOREGROUND_BROWN,
	FOREGROUND_TURQUOISE
};

#endif