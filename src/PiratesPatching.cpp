#include <windows.h>
#include "CRCFixer.h"
#include "Utils.h"
#include "Compatibility.h"
#include "NString.h"

// Sid Meier's Pirates! v1.0 - 5.03.06
// This version has a different protection scheme to the versions before and after it. 
// None of the generic patching for 3, 4 or 5 of SecuROM works with this version.
// So this is handled separately - interested to know if any other games use this particular 
// obfuscation and checks in SecuROM

void GeometryHookForPirates()
{
	logc(FOREGROUND_GREEN, "Pirates Geometry Hook Called. Reversing Patches...\n");
	ReversePatches();
}

// Try to generically find the 1st CD Check - not easy!
bool PatchPiratesCDCheck1(DWORD start, DWORD end)
{
	/* Examples of CD Check 1 in Pirates! Style
	005B735A | 8B15 787B6200            | mov edx,dword ptr ds:[627B78]                                      | 8B?? ???????? 83EC 04 89??24 8B?? 2B?? ????????
	005B7360 | 83EC 04                  | sub esp,4                                                          |
	005B7363 | 893C24                   | mov dword ptr ss:[esp],edi                         89??248B??2B                |
	005B7366 | 8BFA                     | mov edi,edx                                                        |
	005B7368 | 2B3D 706A7000            | sub edi,dword ptr ds:[706A70]                                      | 00706A70:"&FYF"
	005B736E | 5F                       | pop edi                                                            |
	005B736F | 9C                       | pushfd                                            |
	005B7370 | 83EC 20                  | sub esp,20                                        |
	...
	005B73CF | 83C4 1C                  | add esp,1C                                                         |
	005B73D2 | 9D                       | popfd                                                              |
	005B73D3 | 75 10                    | jne ar.5B73E5                                                      |

	Pirates:
	00AAA9E7 | A1 A8BBB200              | mov eax,dword ptr ds:[B2BBA8]                                      |  A1 ???????? 83EC 04 890424 8BC0 2B05 ???????? 58 uses EAX
	00AAA9EC | 83EC 04                  | sub esp,4                                                          |
	00AAA9EF | 890424                   | mov dword ptr ss:[esp],eax                                         |
	00AAA9F2 | 8BC0                     | mov eax,eax                                                        | 83EC 04 890424 8BC0 
	00AAA9F4 | 2B05 50DCC100            | sub eax,dword ptr ds:[C1DC50]                                      | 2B05 ???????? 58
	00AAA9FA | 58                       | pop eax                                                            |

	Spellforce The Breath Of Winter - Possible CD Check 1 style:
	0045A13C | 8B0D A85B6400            | mov ecx,dword ptr ds:[645BA8]                     |
	0045A142 | 83EC 04                  | sub esp,4                                         |
	0045A145 | 893424                   | mov dword ptr ss:[esp],esi                        | [esp]:TpCallbackIndependent+478
	0045A148 | 8BF1                     | mov esi,ecx                                       |
	0045A14A | 2B35 50CF7300            | sub esi,dword ptr ds:[73CF50]                     | 0073CF50:"&FYF"
	0045A150 | 5E                       | pop esi                                           |
	0045A151 | 68 DC260000              | push 26DC                                         |
	0045A156 | 75 11                    | jne ar3.45A169                                    |
	0045A14A - 0045A13C = E
	*/

	int eaxPatchCount = 0;
	std::vector<DWORD> CDCheck1PatchesEAX = FindAllHexString(start, end, NString("A1 ???????? 83EC 04 89??24 8B?? 2B").Replace(" ", ""), "Pirates CD Check 1 - EAX Search");
	for (DWORD addr : CDCheck1PatchesEAX)
	{
		logc(FOREGROUND_GREY, "Accessing Possible Pirates CD Check 1 patch location at %08X (EAX)... ", addr);
		// We need to check if it's actually working on direct addresses and not the stack or similar
		if (*(BYTE*)(addr + 0xE) == 0x35	// esi 
			|| *(BYTE*)(addr + 0xE) == 0x05 // eax
			|| *(BYTE*)(addr + 0xE) == 0x3D // edi
			)
		{
			logc(FOREGROUND_GREEN, "OK - patching it\n");
			WritePatchBYTE(addr + 0xD, 0x38);			// cmp al, al
			WritePatchBYTE(addr + 0xE, 0xC0);
			WritePatchDWORD(addr + 0xF, 0x90909090);
			eaxPatchCount++;
		}
		else
			logc(FOREGROUND_YELLOW, "Ignoring. (1)\n");
	}

	int patchCount = 0;
	std::vector<DWORD> CDCheck1Patches = FindAllHexString(start, end, NString("8B?? ???????? 83EC 04 89??24 8B?? 2B").Replace(" ", ""), "Pirates CD Check 1 - Non-EAX Search");
	for (DWORD addr : CDCheck1Patches)
	{
		logc(FOREGROUND_GREY, "Accessing Possible Pirates CD Check 1 patch location at %08X... ", addr);
		// We need to check if it's actually working on direct addresses and not the stack or similar
		if (*(BYTE*)(addr + 1) == 0x15 // edx
			|| *(BYTE*)(addr + 1) == 0x0D //ecx
			) // mov reg, [address] for edx or ecx
		{
			if (*(BYTE*)(addr + 0xF) == 0x35 // esi
				|| *(BYTE*)(addr + 0xF) == 0x05 // eax 
				|| *(BYTE*)(addr + 0xF) == 0x3D // edi
				)
			{
				// Check that after this we either PUSH then JNE or PUSHFD Maybe? Ok for now
				logc(FOREGROUND_GREEN, "OK - patching it\n");
				WritePatchBYTE(addr + 0xE, 0x38);			// cmp al, al
				WritePatchBYTE(addr + 0xF, 0xC0);
				WritePatchDWORD(addr + 0x10, 0x90909090);
				patchCount++;
			}
			else
				logc(FOREGROUND_YELLOW, "Ignoring. (1)\n");
		}
		else
			logc(FOREGROUND_YELLOW, "Ignoring. (2)\n");
	}

	return (patchCount + eaxPatchCount) > 0;
}

bool PiratesPatching(DWORD CDCheckSectionStart, DWORD CDCheckSectionEnd)
{
	logc(FOREGROUND_LIME, "Checking to see Sid Meier's Pirates style protection is present\n");

	DWORD ExeAddr = (DWORD)GetModuleHandle(NULL);
	auto sections = GetSections(ExeAddr);

	std::vector<DWORD> GeometryPiratesCDPatches;
	for (auto& section : sections)
	{
		CDCheckSectionStart = ExeAddr + section->VirtualAddress;
		CDCheckSectionEnd = ExeAddr + section->VirtualAddress + section->Misc.VirtualSize;
		GeometryPiratesCDPatches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "032424DD1D????????", "Pirates! Geometry Check");
		if (GeometryPiratesCDPatches.size() == 2)
			break;
	}

	if (GeometryPiratesCDPatches.size() == 2)
	{
		logc(FOREGROUND_GREEN, "Found Pirates! Style Geometry Check. Removing CRCs\n");

		CRCFixer(CDCheckSectionStart, CDCheckSectionEnd, true, false);
		
		PatchPiratesCDCheck1(CDCheckSectionStart, CDCheckSectionEnd);
		
		// Find CD Check 3 (2 is taken care of by the PVD we send back) - Force JE
		auto ThirdCDPatchesEAX = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "89??24A1????????2B????68????????74", "CD CHECK 3 (EAX)");
		for (DWORD addr : ThirdCDPatchesEAX)
		{
			logc(FOREGROUND_GREEN, "Found CD Check 3 patch location at %08X (EAX)\n", addr);
			WritePatchBYTE(addr + 0x10, 0xEB);
		}
		auto ThirdCDPatches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "89??248B??????????2B????68????????74", "CD CHECK 3 (Non-EAX)");
		for (DWORD addr : ThirdCDPatches)
		{
			logc(FOREGROUND_GREEN, "Found CD Check 3 patch location at %08X (Non-EAX)\n", addr);
			WritePatchBYTE(addr + 0x11, 0xEB);
		}

		// Find CD Check 4 - make JNE not call (NOP the sub)
		auto FourthCDPatches = FindAllHexString(CDCheckSectionStart, CDCheckSectionEnd, "83EC0489??248B??2B??85", "CD CHECK 4");
		for (DWORD addr : FourthCDPatches)
		{
			logc(FOREGROUND_GREEN, "Found CD Check 4 patch location at %08X\n", addr);
			WritePatchBYTE(addr + 0x8, 0x38);			// cmp al, al
			WritePatchBYTE(addr + 0x9, 0xC0);
			WritePatchBYTE(addr + 0xA, 0x90);
			WritePatchDWORD(addr + 0xB, 0x90909090);
		}
		
		logc(FOREGROUND_GREEN, "Geometry patch hook...\n");
		for (DWORD addr : GeometryPiratesCDPatches)
		{
			logc(FOREGROUND_GREEN, "Patching Pirates Geometry CD Check patch location at %08X\n", addr);
			WritePatchBYTE(addr + 3, 0x90);
			WritePatchBYTE(addr + 4, 0xE8);
			WritePatchDWORD(addr + 5, (((DWORD)(GeometryHookForPirates)) - (addr + 4)) - 5);
		}

		ApplyCompatibilityPatches();
		ApplyPatches();

		logc(FOREGROUND_GREEN, "Pirates! Style Protection Patching Complete\n");
		GetKey(true);
		return true;
	}
	else
	{
		logc(FOREGROUND_RED, "Failed to even the find Pirates Geometry CD Check patch location!\n");
		GetKey(true);
	}
	return false;
}