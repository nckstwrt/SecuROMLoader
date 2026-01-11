// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"

void RunVirusekMethod();

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
		RunVirusekMethod();
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

__declspec(naked) void Ret0()
{
	__asm xor eax, eax
	__asm ret
}

// This little function is an unnecessary hop but makes for a useful unchecked breakpoint when debugging
DWORD RemapToPtr3;
__declspec(naked) void JmpToPtr3()
{
	__asm
	{
		push dword ptr[RemapToPtr3]
		ret
	}
}

DWORD CheckRegion(DWORD start, DWORD size, DWORD exeStart, DWORD exeEnd)
{
	//logc(FOREGROUND_GREEN, "CheckRegion: Start: %08X Size: %08X\n", start, size);
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
			RemapToPtr3 = *(DWORD*)&ptr[ptr3Addr];	// Function to Map to

			if (ptr1 < exeStart || ptr1 > exeEnd ||
				ptr2 < exeStart || ptr2 > exeEnd ||
				RemapToPtr3 < exeStart || RemapToPtr3 > exeEnd)
			{
				//logc(FOREGROUND_YELLOW, "CheckRegion: Failed pointer checks at %08X (Ptr1: %08X Ptr2: %08X Ptr3: %08X)\n", start + i, ptr1, ptr2, ptr3);
				continue;
			}

			// just make sure all the bytes before where the pointers where are 0 and have their correct suffix bytes
			if (ptr[ptr1Addr - 1] != 0 || ptr[ptr1Addr + 4] != 0x5 ||
				ptr[ptr2Addr - 1] != 0 || ptr[ptr2Addr + 4] != 0xE ||
				ptr[ptr3Addr - 1] != 0 || ptr[ptr3Addr + 4] != 0x4)
				continue;

			//logc(FOREGROUND_GREEN, "CheckRegion: Found SecuROM region to patch at %08X  (Ptr1: %08X Ptr2: %08X Ptr3: %08X)\n", start + i, ptr1, ptr2, RemapToPtr3);

			*(DWORD*)&ptr[ptr1Addr] = (DWORD)&JmpToPtr3;
			*(DWORD*)&ptr[ptr2Addr] = (DWORD)&Ret0;

			//GetKey(true);
			return i;
		}
	}
	return -1L;
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

void RunVirusekMethod()
{
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
			//logc(FOREGROUND_BROWN, "FindWindowA_Hook: Found SecuROM region at %08X\n", AddrFound);
		}
	}
}
