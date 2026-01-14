#include <windows.h>
#include "Utils.h"
#include "NString.h"
#include "CRCFixer.h"
#include "Config.h"
#include <vector>

extern Config config;

struct Patch
{
	DWORD addr;
	bool isByte;
	DWORD dw;
	BYTE b;
};

std::vector<Patch> patches;
std::vector<Patch> reverse_patches;

void WritePatchDWORD(DWORD Addr, DWORD Value, bool reverse)
{
	Patch p;
	p.addr = Addr;
	p.isByte = false;
	p.dw = Value;
	if (reverse)
		reverse_patches.push_back(p);
	else
		patches.push_back(p);
}

void WritePatchBYTE(DWORD Addr, BYTE Value, bool reverse)
{
	Patch p;
	p.addr = Addr;
	p.isByte = true;
	p.b = Value;
	if (reverse)
		reverse_patches.push_back(p);
	else
		patches.push_back(p);
}

void ApplyPatches()
{
	logc(FOREGROUND_GREEN, "Applying %d patches...\n", patches.size());
	// Store original values first
	for (auto& patch : patches)
	{
		//logc(FOREGROUND_BROWN, "Storing original value at %08X\n", patch.addr);
		if (patch.isByte)
			WritePatchBYTE(patch.addr, *((BYTE*)patch.addr), true);
		else
			WritePatchDWORD(patch.addr, *((DWORD*)patch.addr), true);
	}

	for (auto& patch : patches)
	{
		//logc(FOREGROUND_BROWN, "Applying patch at %08X\n", patch.addr);
		if (patch.isByte)
			WriteProtectedBYTE(patch.addr, patch.b, false);
		else
			WriteProtectedDWORD(patch.addr, patch.dw, false);
	}

	logc(FOREGROUND_GREEN, "All patches applied.\n");
}

void ReversePatches()
{
	for (auto& patch : reverse_patches)
	{
		if (patch.isByte)
			WriteProtectedBYTE(patch.addr, patch.b, false);
		else
			WriteProtectedDWORD(patch.addr, patch.dw, false);
	}
}



int GeometryCheckCount = 0;
bool GeometryCheckOneToZero = false;

#if 1
// new GeometryHook
#ifdef __GNUC__
void __attribute__((cdecl)) 	// calling convention to access registers on the stack
#else
void _cdecl
#endif
GeometryHook_inner(int32_t edl, int32_t esi, int32_t ebp, int32_t esp,
                   int32_t ebx, int32_t edx, int32_t ecx, int32_t eax)
{
	typedef union { int32_t ex; union { int16_t x; struct { int8_t l, h; }; }; } x86reg;
	x86reg* eax_p = (x86reg*)&eax;
	logc(FOREGROUND_GREEN, "Geometry Hook Called: %d\n", GeometryCheckCount);
	if (GeometryCheckCount == 0 || (GeometryCheckOneToZero && GeometryCheckCount == 1))
	{
		GeometryCheckCount++;
		eax_p->h = 0;
	}
	else
	{
		GeometryCheckCount++;
		eax_p->h = 1;
	}
	if (GeometryCheckCount == 4)		// Securom 8 seems to do 4 geometry checks and checks for changes?
	{
		logc(FOREGROUND_ORANGE, "Reversing CRC Fixer patches now...\n");
		ReversePatches();
		GetKey(true);
		int32_t* ret_addr_p = (int32_t*)esp; // esp == pointer to return addr
		*ret_addr_p += 3;	// jump back to the test ah,5
	}
}


__declspec(naked) void GeometryHook()
{
#ifdef __GNUC__
	__asm volatile("pushad                       \n\t"
	               "call %0                      \n\t"
	               "popad                        \n\t"
	               "ret                          \n\t"
	               ::"i"(GeometryHook_inner)
	);
	__builtin_unreachable();
#else
	__asm pushad;
	__asm call GeometryHook_inner;
	__asm popad;
	__asm ret;
#endif
} // end new GeometryHook

#else

// old GeometryHook
__declspec(naked) void GeometryHook()
{
#ifdef __GNUC__
	__asm volatile("pushad             \n\t");
#else
	__asm pushad;
#endif
	logc(FOREGROUND_GREEN, "Geometry Hook Called: %d\n", GeometryCheckCount);
#ifdef __GNUC__
	__asm volatile("popad              \n\t");
#else
	__asm popad;
#endif
	if (GeometryCheckCount == 0 || (GeometryCheckOneToZero && GeometryCheckCount == 1))
	{
#ifdef __GNUC__
		__asm volatile("incd [%0]                         \n\t"
		               "mov ah, 0                         \n\t"
		               //"ret                               \n\t"
		               :"=m"(GeometryCheckCount)
		               :"m"(GeometryCheckCount)
		);
#else
		__asm 
		{
			inc [GeometryCheckCount]
			mov ah, 0
			//ret
		}
#endif
	}
	else
	{
#ifdef __GNUC__
		static_assert(sizeof(GeometryCheckCount)==4, "check size of inc asm cmd");
		__asm volatile("incd [%0]                          \n\t"
		               "mov ah, 1                          \n\t"
		               //"ret                                \n\t"
			   :"=m"(GeometryCheckCount):
			   "m"(GeometryCheckCount));
#else
		__asm
		{
			inc [GeometryCheckCount]
			mov ah, 1
			//ret
		}
#endif
	}
	if (GeometryCheckCount == 4)		// Securom 8 seems to do 4 geometry checks and checks for changes?
	{
#ifdef __GNUC__
		__asm volatile("pushad              \n\t");
#else
		__asm pushad;
#endif
		logc(FOREGROUND_ORANGE, "Reversing CRC Fixer patches now...\n");
		ReversePatches();
		GetKey(true);
#ifdef __GNUC__
		__asm volatile("popad               \n\t"
	                   "addd [esp], 3       \n\t");
#else
		__asm popad;
		__asm add dword ptr [esp], 3  // jump back to the test ah,5
#endif
	}
#ifdef __GNUC__
	__asm volatile("ret                    \n\t");
#else
	__asm ret;
#endif
}
#endif // end old GeometryHook


int CRCFix(DWORD start, DWORD end, bool removeJNE)
{
	int CRCCount = 0;
	DWORD crcAddr = start;
	while (true)
	{
		crcAddr = FindHexString(crcAddr, end, "83EC??C74424");

		if (crcAddr == -1L)
			break;

		DWORD dec = FindHexString(crcAddr + 0x13, end, "66FF4C24");
		if (dec - (crcAddr + 0x13) > 0x60)
		{
			crcAddr += 0x13;
			continue;
		}

		DWORD jmp = FindHexString(dec, end, "75");	// Find JNE

		DWORD amount = *(DWORD*)(crcAddr + 15);
		DWORD crcLocation = *(DWORD*)(crcAddr + 24);

		if (amount > 0xFFFF)
			amount &= 0xFFFF;

		// Check to see if it's doing a mov then ror and add loop
		DWORD ror = FindHexString(crcAddr, jmp, "C14C24");
		DWORD xorCalc = 0;
		DWORD addCalc = 0;
		if (ror != -1L)
		{
			BYTE ror_value = *((BYTE*)(ror + 4));
			DWORD initial_value = *((DWORD*)(crcAddr + 3 + 4));
			addCalc = (initial_value >> ror_value) | (initial_value << (32 - ror_value));
			if (crcAddr == 0x00FA6E8E)
			{
				logc(FOREGROUND_RED, "ror_value = %X initial_value = %08X\n", ror_value, initial_value);
				logc(FOREGROUND_RED, "After ROR: %08X\n", addCalc);
			}
			for (DWORD addr = crcLocation; addr < crcLocation + (amount * 4); addr += 4)
			{
				addCalc += *(DWORD*)addr;
			}

			// To patch it we replace the ROR with a mov and then remove the add - gotta find the ADD first
			BYTE esp_offset = *((BYTE*)(ror + 3));
			DWORD add = FindHexString(ror, jmp, NString::Format("01??24%02X", esp_offset));
			if (add == -1L)
			{
				logc(FOREGROUND_RED, "Can't Find ADD!!! (%08X)\n", crcAddr);
				GetKey(true);
			}
			WritePatchDWORD(add, 0x90909090); // NOP the Add
			WritePatchBYTE(ror, 0x90);
			WritePatchDWORD(ror + 1, 0x90909090); // NOP the ROR
			WritePatchDWORD(crcAddr + 3 + 4, addCalc); // Make the initial value the addCalc
		}
		else
		{
			DWORD eax_xor_loc = 0, ebx_xor_loc = 0, ecx_xor_loc = 0, edx_xor_loc = 0, ebp_xor_loc = 0, esi_xor_loc = 0, edi_xor_loc = 0;
			bool eax_xor, ebx_xor, ecx_xor, edx_xor, ebp_xor, esi_xor, edi_xor;
			int found_xors = 0;
			DWORD startSearch = crcAddr + 24 + 4;
			while (found_xors != 1)
			{
				eax_xor_loc = FindHexString(startSearch, jmp, "33C0");  // xor eax, eax
				eax_xor = eax_xor_loc != -1L;
				ebx_xor_loc = FindHexString(startSearch, jmp, "33DB");  // xor ebx, ebx
				ebx_xor = ebx_xor_loc != -1L;
				ecx_xor_loc = FindHexString(startSearch, jmp, "33C9");  // xor ecx, ecx
				ecx_xor = ecx_xor_loc != -1L;
				edx_xor_loc = FindHexString(startSearch, jmp, "33D2");  // xor edx, edx
				edx_xor = edx_xor_loc != -1L;
				ebp_xor_loc = FindHexString(startSearch, jmp, "33ED");  // xor ebp, ebp
				ebp_xor = ebp_xor_loc != -1L;
				esi_xor_loc = FindHexString(startSearch, jmp, "33F6");  // xor esi, esi
				esi_xor = esi_xor_loc != -1L;
				edi_xor_loc = FindHexString(startSearch, jmp, "33FF");  // xor edi, edi
				edi_xor = edi_xor_loc != -1L;
				found_xors = eax_xor + ebx_xor + ecx_xor + edx_xor + ebp_xor + esi_xor + edi_xor;
				if (found_xors > 1)
					startSearch += 1;
				if (found_xors == 0)
				{
					logc(FOREGROUND_RED, "Can't Find XOR!!! (%08X)\n", crcAddr);
					GetKey(true);
					break;
				}
			}

			for (DWORD addr = crcLocation; addr < crcLocation + (amount * 4); addr += 4)
				xorCalc ^= *(DWORD*)addr;

			// 38 C0 cmp al, al - replace the JNE with this and replace the dec word ptr ss with the mov 
			if (eax_xor)
				WritePatchBYTE(dec, 0xB8);
			if (ebx_xor)
				WritePatchBYTE(dec, 0xBB);
			if (ecx_xor)
				WritePatchBYTE(dec, 0xB9);
			if (edx_xor)
				WritePatchBYTE(dec, 0xBA);
			if (ebp_xor)
				WritePatchBYTE(dec, 0xBD);
			if (esi_xor)
				WritePatchBYTE(dec, 0xBE);
			if (edi_xor)
				WritePatchBYTE(dec, 0xBF);
			WritePatchDWORD(dec + 1, xorCalc);
			WritePatchBYTE(jmp, 0x38); // cmp al,al the JNE
			WritePatchBYTE(jmp + 1, 0xC0); // cmp al,al the JNE
		}

		//logc(FOREGROUND_TURQUOISE, "CRC Check at: %08X location: %08X amount: %04X xor: %08X add: %08X\n", crcAddr, crcLocation, amount, xorCalc, addCalc);

		if (removeJNE)
		{
			WritePatchBYTE(jmp, 0x90); // NOP the JNE
			WritePatchBYTE(jmp + 1, 0x90);
		}

		crcAddr += 0x13;
		CRCCount++;
	}

	return CRCCount;
}

extern DWORD CDCheckStartAddr;
extern DWORD CDCheckEndAddr;

void CRCFixer(DWORD start, DWORD end, bool removeJNE, bool autoApplyPatches)
{
	logc(FOREGROUND_CYAN, "Starting CRCFixer...\n");

	DWORD ExeAddr = (DWORD)GetModuleHandle(NULL);
	auto sections = GetSections(ExeAddr);
	std::vector<DWORD> CDCheckMatches;
	int CDCheckOffset = 0;

	if (start == -1L && end == -1L)
	{
		PIMAGE_SECTION_HEADER CDCheckSection = NULL;
		for (auto& section : sections)
		{
			logc(FOREGROUND_CYAN, "Section: %s Addr: %08X Size: %X\n", section->Name, section->VirtualAddress + ExeAddr, section->Misc.VirtualSize);
			if (_stricmp((char*)section->Name, ".rdata") == 0 || /*_stricmp((char*)section->Name, ".text") == 0 ||*/ _stricmp((char*)section->Name, ".data") == 0)
				continue;

			DWORD CDSectionStart = section->VirtualAddress + ExeAddr;
			CDCheckMatches = FindAllHexString(CDSectionStart, CDSectionStart + section->Misc.VirtualSize, "83E01F3C1F"); // and eax, 1F; cmp al, 1F;
			if (CDCheckMatches.size() >= 1)
			{
				CDCheckStartAddr = CDSectionStart;
				CDCheckEndAddr = CDSectionStart + section->Misc.VirtualSize;
				CDCheckSection = section;
				break;
			}

			//FindAllHexString(CDSectionStart, CDSectionStart + section->Misc.VirtualSize, "83C408DD1D", "Test1");
			//FindAllHexString(CDSectionStart, CDSectionStart + section->Misc.VirtualSize, "032424DD1D", "Test2");
			//FindAllHexString(CDSectionStart, CDSectionStart + section->Misc.VirtualSize, "2B3C85????????5F", "Test3");
		}
	
		if (CDCheckSection == NULL)
		{
			logc(FOREGROUND_RED, "Failed to find CD Check section!!! Searching for GTA SA style CD Check now\n");
			
			for (auto& section : sections)
			{
				DWORD CDSectionStart = section->VirtualAddress + ExeAddr;
				CDCheckMatches = FindAllHexString(CDSectionStart, CDSectionStart + section->Misc.VirtualSize, "E8????????83E01F"); // CALL proc, and eax, 1F;
				if (CDCheckMatches.size() >= 1)
				{
					CDCheckOffset = 5;
					CDCheckSection = section;
					break;
				}
			}

			if (CDCheckSection == NULL)
			{
				logc(FOREGROUND_RED, "Failed to find GTA IV style CD Check section!!! Aborting CRC Fixer\n");
				return;
			}
		}
	
		logc(FOREGROUND_CYAN, "CD Check Section: %s Addr: %08X Size: %X\n", CDCheckSection->Name, CDCheckSection->VirtualAddress + ExeAddr, CDCheckSection->Misc.VirtualSize);
		start = CDCheckSection->VirtualAddress + ExeAddr;
		end = start + CDCheckSection->Misc.VirtualSize;
	}

	int CRCCount = CRCFix(start, end, removeJNE);

	if (CDCheckMatches.size() > 0)	// If we have CD Matches then we're removing SecuROM 7/8 Checks. Else let the 345Patcher fix them.
	{
		logc(FOREGROUND_TURQUOISE, "Applying %d CD Patches...\n", CDCheckMatches.size());
		for (auto &match : CDCheckMatches)
		{
			WritePatchBYTE(match + CDCheckOffset, 0xB0);		// mov al, 1f
			WritePatchBYTE(match + CDCheckOffset + 1, 0x1F);
			WritePatchBYTE(match + CDCheckOffset + 2, 0x90);
		}
		logc(FOREGROUND_TURQUOISE, "Done\n");

		// Invert Geometry Checks
		std::vector<DWORD> geoChecks = FindAllHexString(start, end, "DC25????????DC0D????????DC1D????????DFE0F6C405");
		logc(FOREGROUND_TURQUOISE, "Applying %d Geometry Patches..\n", geoChecks.size());
		logc(FOREGROUND_TURQUOISE, "GeometryHook Function: %08X\n", (DWORD)GeometryHook);
		for (auto& match : geoChecks)
		{
			WritePatchBYTE(match + 6 + 6, 0xE8);
			WritePatchDWORD(match + 6 + 6 + 1, (((DWORD)GeometryHook) - (match + 6 + 6)) - 5);
			WritePatchBYTE(match + 6 + 6 + 1 + 4, 0x90);
			WritePatchBYTE(match + 6 + 6 + 1 + 5, 0x90);
			WritePatchBYTE(match + 6 + 6 + 1 + 6, 0x90);
		}

		// Let's see if we can kill +7C0 check - as it does vary from disk to disk (FM2008 vs GTA SA)
		std::vector<DWORD> CD7C0Checks = FindAllHexString(start, end, "8498C0070000");			// 01158FE8 | 8498 C0070000 | test byte ptr ds:[eax+7C0],bl
		logc(FOREGROUND_TURQUOISE, "Looking for +7C0 changes: %d found\n", CD7C0Checks.size());

		GeometryCheckOneToZero = config.GetBool("GeometryCheckOneToZero");		

		if (config.GetValue("Override7C0") == NULL)
		{
			if (CD7C0Checks.size() == 0)
			{
				logc(FOREGROUND_ORANGE, "No +7C0 checks found - finding early SecuROM 7 +7C0 Check Method...\n");
				std::vector<DWORD> Old7C0Potential = FindAllHexString(start, end, "B9????????8B8C01????????83E101");
				for (auto& match : Old7C0Potential)
				{
					DWORD checkValue = *(DWORD*)(match + 1) + (*(DWORD*)(match + 8));
					logc(FOREGROUND_ORANGE, "Old +7C0 Potential Check at: %08X (Check Value: %08X)\n", match, checkValue);
					if (checkValue == 0x7C0)
					{
						logc(FOREGROUND_ORANGE, "Old +7C0 Check Verified at: %08X\n", match);
						WritePatchBYTE(match + 14, 0x0); // and ecx, 0   - change to and with 0
						WritePatchBYTE(match + 13, 0xf9); // cmp ecx, 0   - change to compare with 0 // Test!
					}
				}
			}
			else
			{
				for (auto& match : CD7C0Checks)
				{
					// Maybe change for 00C06F18 | 84DB  | test bl,bl
					//WriteProtectedBYTE(match, 0x84);			// test bl,bl
					//WriteProtectedBYTE(match + 1, 0xDB);
					//WriteProtectedDWORD(match + 2, 0x90909090);
					WritePatchBYTE(match, 0x38);			// cmp al, al
					WritePatchBYTE(match + 1, 0xC0);
					WritePatchDWORD(match + 2, 0x90909090);
				}
			}
		}
		else
			logc(FOREGROUND_ORANGE, "Overriding +7C0 so not removing +7C0 checks\n");
	}

	if (autoApplyPatches)
		ApplyPatches();

	RestrictProcessors(config.GetInt("CPUCount", -1));

	logc(FOREGROUND_TURQUOISE, "Done\n");
}
