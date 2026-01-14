#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <conio.h>
#include <iostream>
#include "../src/Config.h"
#include "../src/Utils.h"

Config config;
bool logging = false;

void exitlog(const char *text)
{
	log(text);
	MessageBox(0, text, "VersionInjector Error", MB_ICONERROR | MB_OK);
	exit(-1);
}

void InjectVersionDLL(DWORD pid)
{
	HANDLE hProcess;
	char szSecDrvEmuDLLPath[MAX_PATH];
	strcpy(szSecDrvEmuDLLPath, "version.dll");

	// Open Process
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (hProcess == NULL) // Not INVALID_HANDLE_VALUE...Strangely
	{
		exitlog("Process found, but cannot open handle\n");
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
		exitlog("Could not allocate memory inside the target process\n");
	}

	// Write the fullpath filename into the target process
	BOOL bWritten = WriteProcessMemory(hProcess, newMemory, szPath, strlen(szPath) + 1, NULL);
	if (bWritten == 0)
	{
		exitlog("There were no bytes written to the process's address space.\n");
	}

	// Create Remote Thread to run LoadLibrary with our fullpath
	HANDLE hNewThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)loadLibraryAddr, newMemory, NULL, NULL);
	if (hNewThread == NULL)
	{
		exitlog("Could not create remote thread in target process\n");
	}

	// Wait for it to run
	WaitForSingleObject(hNewThread, INFINITE);

	// Clean up
	CloseHandle(hNewThread);
	CloseHandle(hProcess);
}

int main(int argc, char *argv[])
{
	if (GetFileAttributesA("Version.dll") == -1L)
	{
		exitlog("Cannot find version.dll in same directory as VersionInjector.exe");
		return -1;
	}

	STARTUPINFO StartupInfo = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	StartupInfo.cb = sizeof(STARTUPINFO);

	char szPathBuffer[MAX_PATH];
	const char* szPath = config.GetValue("exeFile");

	ZeroMemory(szPathBuffer, MAX_PATH);
	if (argc < 2)
	{
		if (szPath == NULL)
		{
			OPENFILENAME ofn = { 0 };
			ofn.lStructSize = sizeof(ofn);
			ofn.hwndOwner = NULL;
			ofn.lpstrFile = szPathBuffer;
			ofn.nMaxFile = MAX_PATH;
			ofn.lpstrFilter = "Executables (*.exe)\0*.exe\0All\0*.*\0\0";
			ofn.nFilterIndex = 1;
			ofn.lpstrFileTitle = NULL;
			ofn.nMaxFileTitle = 0;
			ofn.lpstrInitialDir = NULL;
			ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

			if (GetOpenFileName(&ofn) == TRUE)
			{
				szPath = szPathBuffer;
			}
			else
			{
				log("User did not select an executable file.\n");
				return -1;
			}
		}
	}
	else
	{
		for (int i = 1; i < argc; i++)
		{
			if (strstr(argv[i], " "))
			{
				strcat(szPathBuffer, "\"");
				strcat(szPathBuffer, argv[i]);
				strcat(szPathBuffer, "\"");
			}
			else
				strcat(szPathBuffer, argv[i]);
			if (i != argc - 1)
				strcat(szPathBuffer, " ");
		}
		szPath = szPathBuffer;
	}

	log("lpApplicationName: %s\n", szPath);
	BOOL bSuccess = CreateProcessA(NULL, (char*)szPath, 0, 0, 0, CREATE_SUSPENDED, 0, 0, &StartupInfo, &pi);

	InjectVersionDLL(pi.dwProcessId);

	ResumeThread(pi.hThread);
}

int WINAPI WinMain(HINSTANCE hInst, HINSTANCE /*hPrevInst*/, LPSTR cmd_line, int showmode)
{
	config.LoadConfig("version.json");

	logging = config.GetBool("logging", false);

	SetLogging(logging, config.GetValue("injectorLogFile"));

	if (logging)
	{
		AllocConsole();
		freopen("CONOUT$", "w", stdout);
	}

	log("VersionInjector Starting...\n");

	int ret = main(__argc, __argv);

	if (logging)
		FreeConsole();
	if (log_file)
	{
		fclose(log_file);
		log_file = NULL;
	}

	return 0;
}
