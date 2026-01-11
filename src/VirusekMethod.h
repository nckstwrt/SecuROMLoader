#pragma once
#include "Typedefs.h"

extern VirtualQuery_typedef VirtualQuery_Orig;
extern FindWindowA_typedef FindWindowA_Orig;

void RunVirusekMethod();
HWND WINAPI FindWindowA_Hook(LPCSTR lpClassName, LPCSTR lpWindowName);
SIZE_T WINAPI VirtualQuery_Hook(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength);
