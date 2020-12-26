#include "MyGetProcAddress.h"

#define _wcsnicmp _my_wcsnicmp
#define _wcsicmp _my_wcsicmp
#define wcslen _my_wcslen
#define strchr _my_strchr
#define strncpy _my_strncpy
#define strcmp _my_strcmp
#define wcsncpy_s _my_wcsncpy_s

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
	return TRUE;
}

int strcmp(LPCSTR a, LPCSTR b)
{
	int x = 0;
	do {
		x = *a - *b;
	} while (!x && *a++ && *b++);
	return x;
}

LPSTR strchr(LPSTR a, CHAR b)
{
	while (*a && *a != b) a++;
	return *a == b ? a : NULL;
}

LPSTR strncpy(LPSTR dst, LPCSTR src, SIZE_T n)
{
	LPSTR r = dst;
	while (n-- > 0)
		if ((*dst++ = *src++) == 0)
			break;
	return r;
}

SIZE_T wcslen(LPCWSTR s)
{
	SIZE_T r = 0;
	while (s[r]) r++;
	return r;
}

errno_t wcsncpy_s(LPWSTR dst, rsize_t s, LPCWSTR src, rsize_t ss)
{
	if (ss < s) s = ss;
	while (ss-- > 0)
		if ((*dst++ = *src++) == 0)
			break;
	return 0;
}

#define _IS_ALPHABET(X) ( \
	('a' <= (X) && (X) <= 'z') || ('A' <= (X) && (X) <= 'Z') \
)
int _wcsicmp(LPCWSTR a, LPCWSTR b)
{
	int x = 0;
	do {
		if (_IS_ALPHABET(*a) && _IS_ALPHABET(*b)) {
			x = (0x20 | *a) - (0x20 | *b);
		}
		else {
			x = *a - *b;
		}
	} while (!x && *a++ && *b++);
	return x;
}

int _wcsnicmp(LPCWSTR a, LPCWSTR b, SIZE_T n)
{
	int x = 0;
	do {
		if (n-- <= 0) break;
		if (_IS_ALPHABET(*a) && _IS_ALPHABET(*b)) {
			x = (0x20 | *a) - (0x20 | *b);
		} else {
			x = *a - *b;
		}
	} while (!x && *a++ && *b++);
	return x;
}

// NtCurrentTeb()->ProcessEnvironmentBlock
#define NtCurrentPeb() (((PPEB*)NtCurrentTeb())[12])

HMODULE MyGetModuleHandleW(LPCWSTR name)
{
	SIZE_T name_len = wcslen(name);
	WCHAR dotDLL[] = L".DLL";
	WCHAR dotEXE[] = L".EXE";
	if (_wcsicmp(name + name_len - 4, dotDLL) == 0 || _wcsicmp(name + name_len - 4, dotEXE) == 0) name_len -= 4;

	LIST_ENTRY* root = &NtCurrentPeb()->Ldr->InMemoryOrderModuleList;
	LDR_DATA_TABLE_ENTRY* entry = CONTAINING_RECORD(root, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
	while (entry = CONTAINING_RECORD(entry->InMemoryOrderLinks.Flink, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &entry->InMemoryOrderLinks != root) {
		UNICODE_STRING* base_name = 1 + &entry->FullDllName;
		LPCWSTR dll_base_name = base_name->Buffer;
		if (_wcsnicmp(dll_base_name, name, name_len) == 0)
			return (HMODULE)entry->DllBase;
	}
	return NULL;
}

PIMAGE_DATA_DIRECTORY GetDataDirectory(DWORD_PTR ImageBase, DWORD Index)
{
	PIMAGE_DOS_HEADER DosHead;
	PIMAGE_NT_HEADERS PeHead;
	DosHead = (PIMAGE_DOS_HEADER)ImageBase;
	PeHead = (PIMAGE_NT_HEADERS)((DWORD_PTR)DosHead + DosHead->e_lfanew);
	return (PIMAGE_DATA_DIRECTORY)(&PeHead->OptionalHeader.DataDirectory[Index]);
}

PDWORD GetApiSetMapHead()
{
	PPEB peb = NtCurrentPeb();
#if _WIN64 || __amd64__
	return *(PDWORD*)((intptr_t)peb + 0x68);
#else
	return *(PDWORD*)((intptr_t)peb + 0x38);
#endif
}

FARPROC GetExportByName(HMODULE hModule, char *ProcName)
{
	char *ApiName;
	FARPROC ApiAddress = 0;
	WORD Ordinal, *NameOrd;
	DWORD ExportSize, *Ent, *Eat, Index;
	PIMAGE_EXPORT_DIRECTORY ExportTable;
	PIMAGE_DATA_DIRECTORY DataDirec;
	DataDirec = GetDataDirectory((DWORD_PTR)hModule, IMAGE_DIRECTORY_ENTRY_EXPORT);
	ExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + DataDirec->VirtualAddress);
	ExportSize = DataDirec->Size;
	if (ExportTable)
	{
		Eat = (DWORD *)((DWORD_PTR)hModule + ExportTable->AddressOfFunctions);
		Ent = (DWORD *)((DWORD_PTR)hModule + ExportTable->AddressOfNames);
		NameOrd = (WORD *)((DWORD_PTR)hModule + ExportTable->AddressOfNameOrdinals);
		for (Index = 0; Index < ExportTable->NumberOfNames; Index++)
		{
			ApiName = (char *)((DWORD_PTR)hModule + Ent[Index]);
			if (strcmp(ProcName, ApiName) == 0) {
				Ordinal = NameOrd[Index];
				ApiAddress = (FARPROC)((DWORD_PTR)hModule + Eat[Ordinal]);
				if ((DWORD_PTR)ApiAddress >= (DWORD_PTR)ExportTable && ((DWORD_PTR)ApiAddress < ((DWORD_PTR)ExportTable + ExportSize))) {
					ApiAddress = FileNameRedirection(hModule, (char*)ApiAddress);
				}
				return ApiAddress;
			}
		}
	}
	return NULL;
}

FARPROC GetExportByOrdinal(HMODULE hModule, WORD Ordinal)
{
	FARPROC ApiAddress = 0;
	WORD *NameOrd;
	DWORD ExportSize, *Eat;
	PIMAGE_DATA_DIRECTORY DataDirec;
	PIMAGE_EXPORT_DIRECTORY ExportTable;
	DataDirec = GetDataDirectory((DWORD_PTR)hModule, IMAGE_DIRECTORY_ENTRY_EXPORT);
	ExportTable = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)hModule + DataDirec->VirtualAddress);
	ExportSize = DataDirec->Size;
	if (ExportTable)
	{
		Eat = (DWORD *)((DWORD_PTR)hModule + ExportTable->AddressOfFunctions);
		NameOrd = (WORD *)((DWORD_PTR)hModule + ExportTable->AddressOfNameOrdinals);
		ApiAddress = (FARPROC)((Eat[Ordinal - ExportTable->Base] != 0) ? ((DWORD_PTR)hModule + Eat[Ordinal - ExportTable->Base]) : 0);
		if (((DWORD_PTR)ApiAddress >= (DWORD_PTR)ExportTable) && ((DWORD_PTR)ApiAddress < ((DWORD_PTR)ExportTable + ExportSize)))
			ApiAddress = FileNameRedirection(hModule, (char *)ApiAddress);
	}
	return ApiAddress;
}

 void ResolveApiSet(WCHAR *ApiSetName, WCHAR *HostName)
{
	 WCHAR *NameBuffer;
	 WCHAR LibName[64];
	 DWORD LibNameSize, HostNameSize, *Version;
	 PAPI_SET_NAMESPACE_ARRAY_V2 SetMapHead_v2;
	 PAPI_SET_VALUE_ARRAY_V2 SetMapHost_v2;
	 PAPI_SET_NAMESPACE_ARRAY_V4 SetMapHead_v4;
	 PAPI_SET_VALUE_ARRAY_V4 SetMapHost_v4;
	 Version = GetApiSetMapHead();
	 if (Version)
	 {
		 switch (*Version)
		 {
		 case 2:
		 {
				   SetMapHead_v2 = (PAPI_SET_NAMESPACE_ARRAY_V2)Version;
				   for (DWORD i = 0; i < SetMapHead_v2->Count; ++i)
				   {
					   NameBuffer = (WCHAR *)((DWORD_PTR)SetMapHead_v2 + SetMapHead_v2->Entry[i].NameOffset);
					   LibNameSize = SetMapHead_v2->Entry[i].NameLength;
					   wcsncpy_s(LibName, 64, NameBuffer, LibNameSize / sizeof(WCHAR));
					   if (!_wcsicmp((WCHAR *)(ApiSetName + 4), LibName))
					   {
						   SetMapHost_v2 = (PAPI_SET_VALUE_ARRAY_V2)((DWORD_PTR)SetMapHead_v2 + SetMapHead_v2->Entry[i].DataOffset);
						   NameBuffer = (WCHAR *)((DWORD_PTR)SetMapHead_v2 + SetMapHost_v2->Entry[SetMapHost_v2->Count - 1].ValueOffset);
						   HostNameSize = SetMapHost_v2->Entry[SetMapHost_v2->Count - 1].ValueLength;
						   wcsncpy_s(HostName, 64, NameBuffer, HostNameSize / sizeof(WCHAR));
						   return;
					   }
				   }
				   break;
		 }
		 case 4:
		 {
				   SetMapHead_v4 = (PAPI_SET_NAMESPACE_ARRAY_V4)Version;
				   for (DWORD i = 0; i < SetMapHead_v4->Count; ++i)
				   {
					   NameBuffer = (WCHAR *)((DWORD_PTR)SetMapHead_v4 + SetMapHead_v4->Entry[i].NameOffset);
					   LibNameSize = SetMapHead_v4->Entry[i].NameLength;
					   wcsncpy_s(LibName, 64, NameBuffer, LibNameSize / sizeof(WCHAR));
					   if (!_wcsicmp((WCHAR *)(ApiSetName + 4), LibName))
					   {
						   SetMapHost_v4 = (PAPI_SET_VALUE_ARRAY_V4)((DWORD_PTR)SetMapHead_v4 + SetMapHead_v4->Entry[i].DataOffset);
						   HostNameSize = SetMapHost_v4->Entry[SetMapHost_v4->Count - 1].ValueLength;
						   NameBuffer = (WCHAR *)((DWORD_PTR)SetMapHead_v4 + SetMapHost_v4->Entry[SetMapHost_v4->Count - 1].ValueOffset);
						   wcsncpy_s(HostName, 64, NameBuffer, HostNameSize / sizeof(WCHAR));
						   return;
					   }
				   }
				   break;
		 }
		 default:
			 break;
		 }
	 }
}

FARPROC FileNameRedirection(HMODULE hModule, char *RedirectionName)
{
	char *ptr, *ProcName;
	char Buffer[64];
	WCHAR DllName[64];
	FARPROC ApiAddress = 0;
	strncpy(Buffer, RedirectionName, 64);
	ptr = strchr(Buffer, '.');
	if (ptr)
	{
		*ptr = 0;
		for (int i = 0; i < ARRAYSIZE(DllName); i++)
		{
			if ((DllName[i] = Buffer[i]) == 0)
				break;
		}
		// MultiByteToWideChar(CP_ACP, 0, Buffer, sizeof(Buffer), DllName, 64);
		WCHAR wsAPI[] = L"api-";
		if (!_wcsnicmp(DllName, wsAPI, 4))
			ResolveApiSet(DllName, DllName);
		hModule = MyGetModuleHandleW(DllName);
		if (hModule)
		{
			ProcName = (char *)(ptr + 1);
			ApiAddress = GetExportByName(hModule, ProcName);
		}
	}
	return ApiAddress;
}

FARPROC MyGetProcAddress(HMODULE hModule, char *ProcName)
{
	FARPROC ProcAddress = 0;
	DWORD_PTR Ordinal = (DWORD_PTR)ProcName;
	if (hModule == NULL)
	{
		// hModule = NtCurrentTeb()->ProcessEnvironmentBlock->ImageBaseAddress;
		hModule = ((HMODULE *)&NtCurrentPeb()->Ldr)[-1];
	}

	if (HIWORD((DWORD_PTR)ProcName))
	{
		ProcAddress = GetExportByName(hModule, ProcName);
	}
	else
	{
		Ordinal &= 0x0000FFFF;
		ProcAddress = GetExportByOrdinal(hModule, (WORD)Ordinal);
	}
	return ProcAddress;
}