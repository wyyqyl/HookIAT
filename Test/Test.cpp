#include <windows.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
	DWORD dwProcID = 0;
	HANDLE hProc = NULL;
	HMODULE hDll = NULL;
	LPTHREAD_START_ROUTINE loadLibraryAddress = NULL;
	LPVOID lpBaseAddress = NULL;
	BOOL isValid = FALSE;
	HANDLE hThread = NULL;
	WCHAR argumentBuffer[MAX_PATH];
	DWORD dwRet = 0;

	if (argc < 2)
	{
		printf("argument not enough\n");
		return -1;
	}

	dwProcID = atoi(argv[1]);
	hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcID);
	if (hProc == NULL)
	{
		printf("Could not get handle to process (%d)\n", GetLastError());
		return -1;
	}

	hDll = GetModuleHandle(TEXT("Kernel32"));
	if (hDll == NULL)
	{
		printf("Failed to get handle to kernel32 (%d)\n", GetLastError());
		return -1;
	}

	loadLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(hDll, "LoadLibraryW");
	if (loadLibraryAddress == NULL)
	{
		printf("Failed to get the address of LoadLibraryW (%d)\n", GetLastError());
		return -1;
	}

	lpBaseAddress = VirtualAllocEx(hProc, NULL, 256, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if (lpBaseAddress == NULL)
	{
		printf("Failed to allocate memory in the target (%d)\n", GetLastError());
		return -1;
	}

	dwRet = GetCurrentDirectoryW(MAX_PATH, argumentBuffer);
	if (dwRet == 0)
	{
		printf("GetCurrentDirectory failed (%d)\n", GetLastError());
		return -1;
	}
	wcscat_s(argumentBuffer, L"\\HookIAT.dll");

	isValid = WriteProcessMemory(hProc, lpBaseAddress, argumentBuffer, sizeof(argumentBuffer), NULL);
	if (!isValid)
	{
		printf("WriteProcessMemory failed (%d)\n", GetLastError());
		return -1;
	}

	hThread = CreateRemoteThread(hProc, NULL, 0, loadLibraryAddress, lpBaseAddress, 0, NULL);
	if (!hThread)
	{
		printf("CreateRemoteThread failed (%d)\n", GetLastError());
		return -1;
	}

	return 0;
}

//int main(int argc, char *argv[])
//{
//	HINSTANCE hinstLib = LoadLibrary(TEXT("HookIAT.dll"));
//	if (hinstLib == NULL)
//	{
//		printf("LoadLibrary failed (%n)\n", GetLastError());
//		return -1;
//	}
//	DWORD dwPID = GetCurrentProcessId();
//	printf("Current process ID: %d\n", dwPID);
//	FreeLibrary(hinstLib);
//	return 0;
//}