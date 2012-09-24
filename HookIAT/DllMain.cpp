#include <windows.h>
#include <stdio.h>

#define DllExport extern "C" __declspec(dllexport)
FARPROC GetCurrentProcessIdAddr;

DWORD WINAPI HookFunc()
{
	MessageBox(NULL, TEXT("Function is hooked"), TEXT("Warning"), MB_OK);
	return GetCurrentProcessIdAddr();
}

BOOL walkImportLists(LPVOID lpBaseAddress, CHAR *apiName, FILE *fptr)
{
	PIMAGE_DOS_HEADER pDosHeader;
	PIMAGE_NT_HEADERS pNtHeader;
	IMAGE_OPTIONAL_HEADER optionalHeader;
	IMAGE_DATA_DIRECTORY importDirectory;
	DWORD dwImpotStartRVA;
	PIMAGE_IMPORT_DESCRIPTOR pImportDescriptor;

	pDosHeader = (PIMAGE_DOS_HEADER)lpBaseAddress;
	if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
		return FALSE;
	fprintf(fptr, "DOS signature: 0x%04X\tVerified\n", pDosHeader->e_magic);

	pNtHeader = (PIMAGE_NT_HEADERS)((DWORD_PTR)lpBaseAddress + pDosHeader->e_lfanew);
	if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;
	fprintf(fptr, "PE signature: 0x%08X\tVerified\n", pNtHeader->Signature);

	optionalHeader = pNtHeader->OptionalHeader;
	if (optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC && optionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return FALSE;
	fprintf(fptr, "OptionalHeader magic: 0x%04X\tVerified\n", optionalHeader.Magic);

	importDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	dwImpotStartRVA = importDirectory.VirtualAddress;
	pImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)((DWORD_PTR)lpBaseAddress + importDirectory.VirtualAddress);
	if (pImportDescriptor == NULL)
	{
		fprintf(fptr, "First import descriptor is NULL\n");
		return FALSE;
	}

	DWORD dwIndex = -1;
	while (pImportDescriptor[++dwIndex].Characteristics != 0)
	{
		PIMAGE_THUNK_DATA pINT;
		PIMAGE_THUNK_DATA pIAT;
		PIMAGE_IMPORT_BY_NAME pNameData;
		DWORD nFunctions = 0;
		DWORD nOrdinalFunctions = 0;

		char *dllName = (char *)((DWORD_PTR)lpBaseAddress + pImportDescriptor[dwIndex].Name);

		if (dllName == NULL)
			fprintf(fptr, "\nImported DLL[%d]\tNULL name\n", dwIndex);
		else
			fprintf(fptr, "\nImported DLL[%d]\t%s\n", dwIndex, dllName);

		fprintf(fptr, "-------------------------------------------\n");

		pINT = (PIMAGE_THUNK_DATA)(pImportDescriptor[dwIndex].OriginalFirstThunk);
		pIAT = (PIMAGE_THUNK_DATA)(pImportDescriptor[dwIndex].FirstThunk);
		if (pINT == NULL)
		{
			fprintf(fptr, "Empty INT pointer\n");
			return FALSE;
		}
		if (pIAT == NULL)
		{
			fprintf(fptr, "Empty IAT pointer\n");
			return FALSE;
		}

		pINT = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + pImportDescriptor[dwIndex].OriginalFirstThunk);
		pIAT = (PIMAGE_THUNK_DATA)((DWORD_PTR)lpBaseAddress + pImportDescriptor[dwIndex].FirstThunk);
		if (pINT == NULL)
		{
			fprintf(fptr, "Empty INT\n");
			return FALSE;
		}
		if (pIAT == NULL)
		{
			fprintf(fptr, "Empty IAT\n");
			return FALSE;
		}

		while (pINT->u1.AddressOfData != 0)
		{
			if (!(pINT->u1.Ordinal & IMAGE_ORDINAL_FLAG))
			{
				pNameData = (PIMAGE_IMPORT_BY_NAME)(pINT->u1.AddressOfData);
				pNameData = (PIMAGE_IMPORT_BY_NAME)((DWORD_PTR)lpBaseAddress + (DWORD)pNameData);
				fprintf(fptr, "%s", pNameData->Name);
				fprintf(fptr, "\tAddress: 0x%p\n", pIAT->u1.Function);
				if (strcmp(apiName, pNameData->Name) == 0)
				{
					DWORD dwOldProtect, temp;

					GetCurrentProcessIdAddr = (FARPROC)pIAT->u1.Function;

					if (!VirtualProtect(&pIAT->u1.Function, sizeof(LPVOID), PAGE_READWRITE, &dwOldProtect))
					{
						fprintf(fptr, "VirtualProtect PAGE_READWRITE failed (%d)\n", GetLastError());
						return FALSE;
					}
					pIAT->u1.Function = (DWORD_PTR)HookFunc;
					if (!VirtualProtect(&pIAT->u1.Function, sizeof(LPVOID), dwOldProtect, &temp))
					{
						fprintf(fptr, "VirtualProtect recover failed (%d)\n", GetLastError());
						return FALSE;
					}
					fprintf(fptr, "Function %s is hooked, new address: 0x%p\n", apiName, pIAT->u1.Function);
				}
			}
			else
			{
				nOrdinalFunctions++;
			}
			pIAT++;
			pINT++;
			nFunctions++;
		}
		fprintf(fptr, "%d functions imported (%d ordinal)\n", nFunctions, nOrdinalFunctions);
	}
	return TRUE;
}

DllExport BOOL APIENTRY DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	LPVOID lpBaseAddress = (LPVOID)GetModuleHandle(NULL);
	CHAR apiName[] = "GetCurrentProcessId";
	FILE *fptr = NULL;

	errno_t error = fopen_s(&fptr, "skelog.txt", "a+");
	if (error)
		return FALSE;

	switch (fdwReason)
	{
	case DLL_PROCESS_ATTACH:
		if (!walkImportLists(lpBaseAddress, apiName, fptr))
			fprintf(fptr, "Failed to walk through import lists\n");
		break;
	default:
		break;
	}
	fclose(fptr);
	return TRUE;
}