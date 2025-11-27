#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include "NString.h"
#include "Utils.h"
#include "CRCFixer.h"
#include "Config.h"
#include "Compatibility.h"
#include "PiratesPatching.h"
#include <algorithm>

extern Config config;

bool SecuROM3PatchingDone = false;
bool SuccessfulPatching = true;

BOOL WINAPI FakeQueryPerformanceCounter(LARGE_INTEGER* lpPerformanceCount)
{
	static uint64_t counter = 0;
	uint64_t QPC_Frequency;
	QueryPerformanceFrequency((LARGE_INTEGER*)&QPC_Frequency);

	counter += (QPC_Frequency / 5); // (1/5 of a second)

	lpPerformanceCount->QuadPart = counter;

	return TRUE;
}

void PatchQPCCalls(DWORD start, DWORD end)
{
	HMODULE hModule = GetModuleHandle(NULL);
	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
	PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);

	DWORD maxStart = (DWORD)hModule;
	DWORD maxEnd = maxStart + ntHeader->OptionalHeader.SizeOfImage - 4;

	DWORD QPCCall = (DWORD)GetProcAddress(GetModuleHandle("kernel32.dll"), "QueryPerformanceCounter");

	BYTE* ptr = (BYTE*)0;
	logc(FOREGROUND_GREEN, "Patching QPC calls from %08X to %08X\n", start, end);
	for (DWORD i = start; i < end - 6; i++)
	{
		if (ptr[i] == 0xFF && ptr[i + 1] == 0x15)
		{
			DWORD callAddr = *(DWORD*)(&ptr[i + 2]);
			if (callAddr >= maxStart && callAddr <= maxEnd)
			{
				DWORD pCall = *(DWORD*)callAddr;
				if (pCall == QPCCall)
				{
					logc(FOREGROUND_GREEN, "Found QPC call at %08X\n", i);
					WritePatchBYTE(i, 0xE8); 
					WritePatchDWORD(i + 1, (((DWORD)FakeQueryPerformanceCounter) - i) - 5);
					WritePatchBYTE(i + 5, 0x90);
				}
			}
		}
	}
}

static bool GetSecuROMVersion(int* VersionMajor, int* VersionMinor, int* VersionRevision)
{
	bool ret = false;
	DWORD versionString = -1L;
	DWORD ExeAddr = (DWORD)GetModuleHandle(NULL);
	auto sections = GetSections(ExeAddr);
	for (auto& section : sections)
	{
		//DWORD dwOldProtect = 0;
		//VirtualProtect((LPVOID)(ExeAddr + section->VirtualAddress), section->Misc.VirtualSize, PAGE_EXECUTE_READWRITE, &dwOldProtect);		// Sometimes parts of the section can not even have read access! (Scarface!)

		versionString = FindHexString(ExeAddr + section->VirtualAddress, ExeAddr + section->VirtualAddress + section->Misc.VirtualSize, "4164644403000000??2E????2E????00");

		//VirtualProtect((LPVOID)(ExeAddr + section->VirtualAddress), section->Misc.VirtualSize, dwOldProtect, &dwOldProtect);
		if (versionString != -1L)
			break;
	}
	if (versionString != -1L)
	{
		if (sscanf((char*)(versionString + 8), "%01d.%02d.%02d", VersionMajor, VersionMinor, VersionRevision) == 3)
		{
			logc(FOREGROUND_GREEN, "SecuROM Version: %d.%02d.%02d\n", *VersionMajor, *VersionMinor, *VersionRevision);
			ret = true;
		}
	}
	return ret;
}

void GeometryHookForSecuROM3()
{
	logc(FOREGROUND_GREEN, "SecuROM 3/4/5 Geometry Hook Called. Reversing Patches...\n");
	ReversePatches();
}

bool PatchCDCheck1(DWORD start, DWORD end)
{
	// Trying to be more generic about how we find CD Check 1. It almost always has a JMP before it of EB CC
	// Then it has a mov register, memory address. Problem is EAX is 1 byte different in size from ECX or EDX. So need to account for both
	// Then it has a cmp register, memory address. Again, the register can be different - but at least that's almost always starting 3B
	// then it does a JNE - but somes that can be long and sometimes that can be short. So we need to account for both. Examples:
	/*	
	Max Payne 2: 4.85.04
	00575CA5 | EB CC                                 | jmp maxpayne2.575C73                             |
	00575CA7 | A1 78FB5900 | mov eax, dword ptr ds : [59FB78] | Good
	00575CAC | 3B05 ACBA6400 | cmp eax, dword ptr ds : [64BAAC] | 0064BAAC : "/NYF"
	00575CB2 | 0F85 89000000 | jne maxpayne2.575D41 | not taken
	00575CB8 | 68 E0E66400 | push maxpayne2.64E6E0 
	Diablo 2: 3.17.00 
	004154D3 | EB CC                            | jmp game.4154A1                                               |
	004154D5 | 8B0D 90E94100                    | mov ecx,dword ptr ds:[41E990]                                 |
	004154DB | 3B0D DC844300                    | cmp ecx,dword ptr ds:[4384DC]                                 |
	004154E1 | 75 11                            | jne game.4154F4                                               |
	004154E3 | 8B15 D45E4300                    | mov edx,dword ptr ds:[435ED4]                                 |
	004154E9 | 80CE 20                          | or dh,20                                                      |
	Driv3r: 5.03.13
	009736B0 | EB CC		 | jmp driv3r.97367E                                |
	009736B2 | 8B0D A86B9D00 | mov ecx,dword ptr ds:[9D6BA8]                    | 009D6BA8:"v37#"
	009736B8 | 3B0D 8CCBAD00 | cmp ecx,dword ptr ds:[ADCB8C]                    | 00ADCB8C:"/NYF"
	009736BE | 0F85 A3000000 | jne driv3r.973767                                |
	009736C4 | 68 A0F5AD00   | push driv3r.ADF5A0                               |
	*/
	int patchCount = 0;
	logc(FOREGROUND_ORANGE, "Trying to generically find CD Check 1 patch location\n");
	std::vector<NString> JMPPatterns = { "EBCC", "EBCA", "EBCB" };

	for (auto& pattern : JMPPatterns)
	{
		auto eax = FindAllHexString(start, end, pattern + NString("A1 ???????? 3B ?? ????????").Replace(" ", ""), "EAX Search");
		auto others = FindAllHexString(start, end, pattern + NString("8B ?? ???????? 3B ?? ????????").Replace(" ", ""), "All other register search");
		if (eax.size() > 0)
		{
			logc(FOREGROUND_ORANGE, "Found %d possible CD Check 1 locations using EAX - patching them all\n", eax.size());
			for (DWORD loc : eax)
			{
				logc(FOREGROUND_ORANGE, "CD Check 1 patch location at %08X (EAX)\n", loc);
				// Might be a small jump or a long jump - NOP accordingly
				if (*(BYTE*)(loc + 0xD) == 0x75)
				{
					WritePatchBYTE(loc + 0xD, 0x90);
					WritePatchBYTE(loc + 0xE, 0x90);
					patchCount++;
				}
				else
				{
					if (*(BYTE*)(loc + 0xD) == 0x0F && *(BYTE*)(loc + 0xE) == 0x85)
					{
						WritePatchBYTE(loc + 0xD, 0x90);
						WritePatchBYTE(loc + 0xE, 0x90);
						WritePatchDWORD(loc + 0xF, 0x90909090);
						patchCount++;
					}
					else
						logc(FOREGROUND_RED, "Unexpected byte pattern at %08X - not patching\n", loc + 0xD);
				}
			}
		}
		if (others.size() > 0)
		{
			logc(FOREGROUND_ORANGE, "Found %d possible CD Check 1 locations using another register - patching them all\n", others.size());
			for (DWORD loc : others)
			{
				logc(FOREGROUND_ORANGE, "CD Check 1 patch location at %08X (other)\n", loc);
				// Might be a small jump or a long jump - NOP accordingly
				if (*(BYTE*)(loc + 0xE) == 0x75)
				{
					WritePatchBYTE(loc + 0xE, 0x90);
					WritePatchBYTE(loc + 0xF, 0x90);
					patchCount++;
				}
				else
				{
					if (*(BYTE*)(loc + 0xE) == 0x0F && *(BYTE*)(loc + 0xF) == 0x85)
					{
						WritePatchBYTE(loc + 0xE, 0x90);
						WritePatchBYTE(loc + 0xF, 0x90);
						WritePatchDWORD(loc + 0x10, 0x90909090);
						patchCount++;
					}
					else
						logc(FOREGROUND_RED, "Unexpected byte pattern at %08X - not patching\n", loc + 0xE);
				}
			}
		}
	}

	// After the EBCC JMP there is often a JE soon after with a push 800. Depending on what it's looking for on the CD it might pass anyway - but we should try to patch it
	auto part2 = FindAllHexString(start, end, "74??680008000068????????68????????E8", "Finding Part 2 of CD Check 1 Patch (NOP the next JE (small))");
	for (DWORD loc : part2)
	{
		logc(FOREGROUND_ORANGE, "Found Part 2 of CD Check 1 patch location at %08X\n", loc);
		WritePatchBYTE(loc, 0x90);
		WritePatchBYTE(loc + 1, 0x90);
	}

	return (patchCount > 0);
}


bool SecuROM345Patching()
{
	if (SecuROM3PatchingDone)
	{
		logc(FOREGROUND_GREEN, "SecuROM 3/4/5 Patching Already Attempted.\n");
		return SuccessfulPatching;
	}

	int VersionMajor = 0, VersionMinor = 0, VersionRevision = 0;
	if (!GetSecuROMVersion(&VersionMajor, &VersionMinor, &VersionRevision))
	{
		logc(FOREGROUND_RED, "Failed to determine SecuROM version. Cannot proceed with patching.\n");
		SecuROM3PatchingDone = true;
		return false;
	}

	if (VersionMajor < 3 || VersionMajor > 5)
	{
		logc(FOREGROUND_RED, "Not SecuROM version 3, 4 or 5. Cannot proceed with SecuROM patching.\n");
		SecuROM3PatchingDone = true;
		return false;
	}

	DWORD ExeAddr = (DWORD)GetModuleHandle(NULL);
	auto section = GetSectionByName(ExeAddr, ".cms_t");
	if (section == NULL)
	{
		logc(FOREGROUND_RED, "Failed to find .cms_t section for patching. Assume Entry Point is cms_t section.\n");
		DWORD entryPoint = GetEntryPointFromBase(ExeAddr);
		logc(FOREGROUND_YELLOW, "Entry Point: %08X\n", entryPoint);
		auto sections = GetSections(ExeAddr);
		auto it = std::find_if(sections.begin(), sections.end(), [entryPoint, ExeAddr](PIMAGE_SECTION_HEADER s) { return (entryPoint >= (ExeAddr + s->VirtualAddress)) && (entryPoint < (ExeAddr + s->VirtualAddress + s->Misc.VirtualSize)); });
		if (it != sections.end())
		{
			section = *it;
			logc(FOREGROUND_GREEN, "Found Entry Point section: %s\n", (char*)section->Name);
		}
	}

	if (section)
	{
		DWORD CDCheckSectionStart = ExeAddr + section->VirtualAddress;
		DWORD CDCheckSectionEnd = ExeAddr + section->VirtualAddress + section->Misc.VirtualSize;

		if (!PatchCDCheck1(CDCheckSectionStart, CDCheckSectionEnd))
		{
			logc(FOREGROUND_RED, "Failed to find any CD Check 1 patch locations\n");
			SuccessfulPatching = PiratesPatching(CDCheckSectionStart, CDCheckSectionEnd);
			SecuROM3PatchingDone = true;
			return SuccessfulPatching;
		}

		// CD Check 3 is normally - seems to always be edx and if multiple found you can remove all of them:
		/*
		0041FBC3                             | 81EA 96000000                    | sub edx,96                           |          <----- classic sub edx, 96
		0041FBC9                             | 3915 58F74400                    | cmp dword ptr ds:[44F758],edx        |
		0041FBCF                             | 75 11                             | jne game.41FBE2                                  | not taken when good  (is taken when bad) -
		*/
		auto CDCheck3Patches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "81??9600000039??????????75", "CD CHECK 3");
		for (DWORD addr : CDCheck3Patches)
		{
			logc(FOREGROUND_GREEN, "Found CD Check 3 patch location at %08X. NOPing out the JNE\n", addr);
			WritePatchBYTE(addr + 0xC, 0x90);
			WritePatchBYTE(addr + 0xD, 0x90);
		}

		CDCheck3Patches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "2D9600000039??????????75", "CD CHECK 3 EAX");
		for (DWORD addr : CDCheck3Patches)
		{
			logc(FOREGROUND_GREEN, "Found CD Check 3 patch location at %08X. NOPing out the JNE\n", addr);
			WritePatchBYTE(addr + 0xB, 0x90);
			WritePatchBYTE(addr + 0xC, 0x90);
		}

		CDCheck3Patches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "81??9600000039??????????74", "CD CHECK 3 Part 2 (Force JE)");
		for (DWORD addr : CDCheck3Patches)
		{
			logc(FOREGROUND_GREEN, "Found CD Check 3 Part 2 Force JE patch location at %08X. Forcing to JMP.\n", addr);
			WritePatchBYTE(addr + 0xC, 0xEB);
		}

		CDCheck3Patches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "2D9600000039??????????74", "CD CHECK 3 EAX Part 2 (Force JE)");
		for (DWORD addr : CDCheck3Patches)
		{
			logc(FOREGROUND_GREEN, "Found CD Check 3  Part 2 Force JE patch location at %08X. Forcing to JMP\n", addr);
			WritePatchBYTE(addr + 0xB, 0xEB);
		}

		// CD Check 4 and 5. There are some checks that look like cmp eax,dword ptr ds:[edx*4+41E990], JNE 02 (75 02)  - so it's the *4+ and a JNE 02 we look for regardless of register
		auto CDCheck4Patches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "3B????????????7502", "CD CHECK 4/5");
		for (DWORD addr : CDCheck4Patches)
		{
			logc(FOREGROUND_GREEN, "Found CD Check 4 patch location at %08X. NOPing out the JNE\n", addr);
			WritePatchBYTE(addr + 0x7, 0x90);
			WritePatchBYTE(addr + 0x8, 0x90);
		}

		auto JEForce = FindHexString(CDCheckSectionStart, CDCheckSectionEnd, NString("74 ?? 813D ???????? 00005F00").Replace(" ", ""), "The one JE to force (optional)");
		if (JEForce != -1L)
		{
			logc(FOREGROUND_GREEN, "Found the one JE patch we forcing to JMP\n");
			WritePatchBYTE(JEForce, 0xEB);
		}
		else
		{
			JEForce = FindHexString(CDCheckSectionStart, CDCheckSectionEnd, NString("0F84 ???????? 813D ???????? 00005F00").Replace(" ", ""), "The one BIG JE to force (optional)");
			if (JEForce != -1L)
			{
				logc(FOREGROUND_GREEN, "Found the one BIG JE patch we forcing to JMP\n");
				WritePatchBYTE(JEForce, 0x90);
				WritePatchBYTE(JEForce + 1, 0xE9);
			}
		}
		
		
		auto GeometryCDPatches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "DD1D????????E9", "Geometry CD Check (fstp qword search)");
		if (GeometryCDPatches.size() > 0)
		{
			for (auto GeometryCDPatch : GeometryCDPatches)
			{
				logc(FOREGROUND_GREEN, "Found fstp qword search Geometry CD Check patch location at %08X\n", GeometryCDPatch);
				WritePatchBYTE(GeometryCDPatch + 0, 0x90);
				WritePatchBYTE(GeometryCDPatch + 1, 0xE8);
				WritePatchDWORD(GeometryCDPatch + 2, (((DWORD)(GeometryHookForSecuROM3)) - (GeometryCDPatch + 1)) - 5);
			}
		}
		else
		{
			auto fild = FindHexString(CDCheckSectionStart, CDCheckSectionEnd, NString("DB45 ?? DD 5D ?? DB 05 ???????? DD5D ?? DD45 ?? DC0D ???????? DC5D ?? DFE0 F6C401 0F85").Replace(" ", ""), "First FILD Big JNE");
			if (fild != -1L)
			{
				logc(FOREGROUND_GREEN, "Found FILD Big JNE patch location at %08X. Forcing the JNE\n", fild + 0x20);
				WritePatchBYTE(fild + 0x20, 0x90);
				WritePatchBYTE(fild + 0x21, 0xE9);
			}
			else
				logc(FOREGROUND_RED, "Could not find the FILD JNE patch location!\n");
		}

		auto GeometryCDPatches2 = FindHexString(CDCheckSectionStart, CDCheckSectionEnd, "DD1D????????E8", "Geometry CD Check (fstp qword search call version)");	// Only doing one of these
		if (GeometryCDPatches2 != -1L)
		{
			logc(FOREGROUND_GREEN, "Found fstp qword search call version Geometry CD Check patch location at %08X\n", GeometryCDPatches2);
			WritePatchBYTE(GeometryCDPatches2 + 0, 0x90);
			WritePatchBYTE(GeometryCDPatches2 + 1, 0xE8);
			WritePatchDWORD(GeometryCDPatches2 + 2, (((DWORD)(GeometryHookForSecuROM3)) - (GeometryCDPatches2 + 1)) - 5);
		}
			
		PatchQPCCalls(CDCheckSectionStart, CDCheckSectionEnd);
		
		ApplyCompatibilityPatches();
		ApplyPatches();
		GetKey(true);
		SecuROM3PatchingDone = true;
		
	}
	else
		logc(FOREGROUND_RED, "Failed to find .cms_t section or anything similar for patching!!!\n");

	return SecuROM3PatchingDone;
}