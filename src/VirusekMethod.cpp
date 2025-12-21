#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "minhook/MinHook.h"
#include "VirusekMethod.h"
#include "Utils.h"

VirtualQuery_typedef VirtualQuery_Orig;
FindWindowA_typedef FindWindowA_Orig;

__declspec(naked) void Ret0()
{
	__asm xor eax, eax
	__asm ret
}

DWORD CheckRegion(DWORD start, DWORD size, DWORD exeStart, DWORD exeEnd)
{
	logc(FOREGROUND_GREEN, "CheckRegion: Start: %08X Size: %08X\n", start, size);
	BYTE* ptr = (BYTE*)start;
	size -= 0x48;
	for (DWORD i = 0; i < size; i++)
	{
		if (ptr[i + 0] == 0x08 && ptr[i + 1] == 0x00 && ptr[i + 2] == 0x00 && ptr[i + 3] == 0x00 && ptr[i + 4] == 0x00 && ptr[i + 5] == 0x00 && ptr[i + 6] == 0x00 && ptr[i + 7] == 0x00)
		{
			// Check Pointers
			DWORD ptr1Addr = i + 0x38;
			DWORD ptr1 = *(DWORD*)&ptr[ptr1Addr];	// Map to Ptr3
			DWORD ptr2Addr = i + 0x44;
			DWORD ptr2 = *(DWORD*)&ptr[ptr2Addr];	// Map to a xor eax,eax ret
			DWORD ptr3Addr = i + 0x2C;
			DWORD ptr3 = *(DWORD*)&ptr[ptr3Addr];	// Function to Map to

			if (ptr1 < exeStart || ptr1 > exeEnd ||
				ptr2 < exeStart || ptr2 > exeEnd ||
				ptr3 < exeStart || ptr3 > exeEnd)
			{
				//logc(FOREGROUND_YELLOW, "CheckRegion: Failed pointer checks at %08X (Ptr1: %08X Ptr2: %08X Ptr3: %08X)\n", start + i, ptr1, ptr2, ptr3);
				continue;
			}

			// just make sure all the bytes before where the pointers where are 0 and have their correct suffix bytes
			if (ptr[ptr1Addr - 1] != 0 || ptr[ptr1Addr + 4] != 0x5 ||
				ptr[ptr2Addr - 1] != 0 || ptr[ptr2Addr + 4] != 0xE ||
				ptr[ptr3Addr - 1] != 0 || ptr[ptr3Addr + 4] != 0x4)
				continue;

			logc(FOREGROUND_GREEN, "CheckRegion: Found SecuROM region to patch at %08X  (Ptr1: %08X Ptr2: %08X Ptr3: %08X)\n", start + i, ptr1, ptr2, ptr3);

			*(DWORD*)&ptr[ptr1Addr] = ptr3;
			*(DWORD*)&ptr[ptr2Addr] = (DWORD)&Ret0;

			GetKey(true);
			return i;
		}
	}
	return -1L;
}

HWND WINAPI FindWindowA_Hook(LPCSTR lpClassName, LPCSTR lpWindowName)
{
	MH_STATUS status = MH_DisableHook(&FindWindowA);
	logc(FOREGROUND_BROWN, "FindWindowA_Hook: lpClassName: %s lpWindowName: %s %08X\n", lpClassName ? lpClassName : "NULL", lpWindowName ? lpWindowName : "NULL", status);

	DWORD exeStart = (DWORD)GetModuleHandle(NULL);
	DWORD exeEnd = exeStart + GetExeSizeInMemory();

	MEMORY_BASIC_INFORMATION mbi;
	DWORD AddrFound = -1L;
	DWORD ret = VirtualQuery((void*)0, &mbi, sizeof(mbi));
	if (ret != 0)
	{
		while (true)
		{
			if (mbi.State == 0x1000 && ((mbi.Protect & 0xEE) != 0) && ((mbi.Protect & 0x100) == 0))
			{
				DWORD Addr = CheckRegion((DWORD)mbi.BaseAddress, mbi.RegionSize, exeStart, exeEnd);
				if (Addr != 0xFFFFFFFF)
				{
					AddrFound = Addr;
					break;	// Found it?
				}
			}

			if (mbi.RegionSize <= 0)
				break;

			ret = VirtualQuery((void*)(((DWORD)mbi.BaseAddress) + mbi.RegionSize), &mbi, sizeof(mbi));
			if (ret == 0)
				break;
		}
		if (AddrFound != -1L)
		{
			logc(FOREGROUND_BROWN, "FindWindowA_Hook: Found SecuROM region at %08X\n", AddrFound);
		}
	}
	/*
	// Skylanders specific testing!
	CRCFixer(-1L, -1L, true, false);
	WritePatchBYTE(0x013EEE76, 0xB0);
	WritePatchBYTE(0x013EEE77, 0x00);
	WritePatchBYTE(0x013EEE78, 0x90);
	WritePatchBYTE(0x012667F1, 0x39);
	WritePatchBYTE(0x012667F2, 0xC0);
	WritePatchDWORD(0x0159A910, 0x90C3C031); // xor eax,eax ret // Patching this stops paul.dll loading
	WritePatchDWORD(0x01416B80, 0x080A5BE9);
	WritePatchBYTE(0x01416B84, 0x00);
	WritePatchBYTE(0x01416B85, 0x90);
	WritePatchBYTE(0x01416B86, 0x90);

	WritePatchBYTE(0x00EA1F9A, 0x39);		// 6005 patch cmp eax, eax
	WritePatchBYTE(0x00EA1F9B, 0xC0);
	ApplyPatches();
	GetKey(true);
	*/

	return FindWindowA_Orig(lpClassName, lpWindowName);
}

BOOL VirtualQuery_Hook_Logging = false;
SIZE_T WINAPI VirtualQuery_Hook(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength)
{
	if (lpAddress == NULL)
		VirtualQuery_Hook_Logging = true;
	if (VirtualQuery_Hook_Logging)
		logc(FOREGROUND_CYAN, "VirtualQuery_Hook: lpAddress: %08X %08X\n", (DWORD)lpAddress, dwLength);
	SIZE_T ret = VirtualQuery_Orig(lpAddress, lpBuffer, dwLength);
	if (dwLength == sizeof(MEMORY_BASIC_INFORMATION))
	{
		if (VirtualQuery_Hook_Logging)
		{
			logc(FOREGROUND_CYAN, "Ret: %08X BaseAddress: %08X AllocationBase: %08X AllocationProtect: %08X RegionSize: %08X State: %08X Protect: %08X Type: %08X\n", ret,
				 (DWORD)lpBuffer->BaseAddress, (DWORD)lpBuffer->AllocationBase, lpBuffer->AllocationProtect, lpBuffer->RegionSize, lpBuffer->State, lpBuffer->Protect, lpBuffer->Type);
		}
	}
	else
		logc(FOREGROUND_RED, "VirtualQuery_Hook: Unexpected dwLength: %d\n", dwLength);
	return ret;
}

