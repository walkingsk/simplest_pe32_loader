#include <Windows.h>
#include <stdio.h>

void mcpy(void* dst, void* src, size_t size)
{
	char* d = dst;
	char* s = src;
	for (size_t i = 0; i < size; ++i)
		*d++ = *s++;
}
/*
VOID LoadPE32FromFileA(CHAR* sFileName)
{

}
*/
int (*fEntry_WinMain)(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nShowCmd);

BOOL IsValidPE32(BYTE* pPE) // to be updated later
{
	IMAGE_DOS_HEADER* pDosHd;
	IMAGE_NT_HEADERS32* pNtHds;
	IMAGE_SECTION_HEADER* pScnHd;

	pDosHd = (IMAGE_DOS_HEADER*)pPE;
	pNtHds = (IMAGE_NT_HEADERS32*)(pPE + pDosHd->e_lfanew);
	pScnHd = (IMAGE_SECTION_HEADER*)((BYTE*)(pNtHds + 1) + pNtHds->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER32));

	if (pNtHds->FileHeader.Machine != IMAGE_FILE_MACHINE_I386)
		return FALSE;
	if (pNtHds->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		return FALSE;


	return TRUE;
}
INT LoadPE32FromMemory(BYTE* pPE)
{
	if (IsValidPE32(pPE))
	{
		IMAGE_DOS_HEADER* pDosHd;
		IMAGE_NT_HEADERS32* pNtHds;
		IMAGE_SECTION_HEADER* pScnHd;
		BYTE* pImageBase;
		IMAGE_DATA_DIRECTORY* dd;

		pDosHd = (IMAGE_DOS_HEADER*)pPE;
		pNtHds = (IMAGE_NT_HEADERS32*)(pPE + pDosHd->e_lfanew);
		pScnHd = (IMAGE_SECTION_HEADER*)((BYTE*)(pNtHds + 1) + pNtHds->FileHeader.SizeOfOptionalHeader - sizeof(IMAGE_OPTIONAL_HEADER32));

		pImageBase = VirtualAlloc((PVOID)pNtHds->OptionalHeader.ImageBase, pNtHds->OptionalHeader.SizeOfImage, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (pImageBase != NULL)
		{
			DWORD oldProtect;
			DWORD newPermission;

			// load the PE32 header
			mcpy(pImageBase, pPE, pNtHds->OptionalHeader.SizeOfHeaders);

			// VirtualProtect(pImageBase, pNtHds->OptionalHeader.SizeOfHeaders, PAGE_READONLY, &oldProtect);

			// load the sections according to their VAs
			for (WORD i = 0; i < pNtHds->FileHeader.NumberOfSections; ++i)
			{
				if (pScnHd[i].SizeOfRawData > 0)
					//mcpy(pNtHds->OptionalHeader.ImageBase + pScnHd[i].VirtualAddress, pPE + pScnHd[i].PointerToRawData, pScnHd[i].SizeOfRawData);
					mcpy(pImageBase + pScnHd[i].VirtualAddress, pPE + pScnHd[i].PointerToRawData, pScnHd[i].SizeOfRawData);
				else
					//mcpy(pNtHds->OptionalHeader.ImageBase + pScnHd[i].VirtualAddress, 0, pScnHd[i].Misc.VirtualSize);
					mcpy(pImageBase + pScnHd[i].VirtualAddress, 0, pScnHd[i].Misc.VirtualSize);
				/*
				newPermission = 0;
				if (pScnHd[i].Characteristics & IMAGE_SCN_MEM_EXECUTE)
					newPermission = (pScnHd[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_EXECUTE_READWRITE : PAGE_EXECUTE_READ;
				else
					newPermission = (pScnHd[i].Characteristics & IMAGE_SCN_MEM_WRITE) ? PAGE_READWRITE : PAGE_READONLY;

				VirtualProtect(pImageBase + pScnHd[i].VirtualAddress, pScnHd[i].Misc.VirtualSize, newPermission, &oldProtect);
				*/
			}

			dd = pNtHds->OptionalHeader.DataDirectory;
			if (pNtHds->OptionalHeader.NumberOfRvaAndSizes >= 2) // Import Table exists
			{
				IMAGE_IMPORT_DESCRIPTOR* pImportEntry = (IMAGE_IMPORT_DESCRIPTOR*)(pImageBase + dd[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
				//MEMORY_BASIC_INFORMATION mbi;

				//VirtualQuery(pImportEntry, &mbi, dd[IMAGE_DIRECTORY_ENTRY_IMPORT].Size);
				//VirtualProtect(pImportEntry, pScnHd[i].Misc.VirtualSize, newPermission, &oldProtect);

				for (WORD i = 0; pImportEntry[i].FirstThunk != 0; ++i)
				{
					HMODULE hModule = LoadLibraryA(pImageBase + pImportEntry[i].Name);
					IMAGE_THUNK_DATA* pThunkAddessEntry = (IMAGE_THUNK_DATA*)(pImageBase + pImportEntry[i].FirstThunk);
					IMAGE_IMPORT_BY_NAME* pHintNameEntry;

					if (hModule == NULL)
					{
						VirtualFree((PVOID)pNtHds->OptionalHeader.ImageBase, 0, MEM_RELEASE);
						return -1;
					}

					for (; pThunkAddessEntry->u1.AddressOfData != 0; ++pThunkAddessEntry)
					{
						pHintNameEntry = (IMAGE_IMPORT_BY_NAME*)(pImageBase + pThunkAddessEntry->u1.AddressOfData);
						
						if (((DWORD)pHintNameEntry & IMAGE_ORDINAL_FLAG) == 0) // by function name
						{
							pThunkAddessEntry->u1.Function = (DWORD)GetProcAddress(hModule, pHintNameEntry->Name);
							// *pThunkAddessEntry = (DWORD) GetProcAddress(hModule, pHintNameEntry->Name);
							if (pThunkAddessEntry->u1.Function == 0)
							{
								VirtualFree((PVOID)pNtHds->OptionalHeader.ImageBase, 0, MEM_RELEASE);
								return -1;
							}
						}
						else // by ordinal
						{
							pThunkAddessEntry->u1.Function = (DWORD)GetProcAddress(hModule, (PSTR)pHintNameEntry);
							if (pThunkAddessEntry->u1.Function == 0)
							{
								VirtualFree((PVOID)pNtHds->OptionalHeader.ImageBase, 0, MEM_RELEASE);
								return -1;
							}
						}
					}
					
				}
			}
			fEntry_WinMain = pImageBase + pNtHds->OptionalHeader.AddressOfEntryPoint;
			(fEntry_WinMain)(GetModuleHandleA(NULL), NULL, "", SW_SHOWNORMAL);
			// https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-winmain
			// https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-showwindow

			// VirtualFree(pNtHds->OptionalHeader.ImageBase, pNtHds->OptionalHeader.SizeOfImage, )
			VirtualFree((PVOID)pNtHds->OptionalHeader.ImageBase, 0, MEM_RELEASE);
			return 0;
		}
		else
			return -1;
	}
	else
		return -1;
}

int main(int argc, char* argv[])
{
	if (argc >= 2)
	{
		HANDLE hFile = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (hFile != INVALID_HANDLE_VALUE)
		{
			DWORD nFileSize = GetFileSize(hFile, NULL);
			if (nFileSize != 0 && nFileSize != 0xFFFFFFFF)
			{
				HANDLE hFileMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);

				if (hFileMapping)
				{
					BYTE* pFile = (BYTE*)MapViewOfFile(hFileMapping, FILE_MAP_READ, 0, 0, 0);
					if (pFile)
					{
						LoadPE32FromMemory(pFile);

						UnmapViewOfFile(pFile);
					}
					else
					{
						printf("Failed to MapViewOfFile!");
					}
					CloseHandle(hFileMapping);
				}
			}
			else
			{
				printf("Abnormal filesize! (0x%08X)", nFileSize);
			}

			CloseHandle(hFile);
		}
		else
		{
			printf("Failed to open %s!", argv[1]);
		}

	}

	return 0;
}