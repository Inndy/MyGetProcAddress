﻿#pragma once

#include <windows.h>
#include <winternl.h>

//ApiSetSchema v2
typedef struct _API_SET_NAMESPACE_ENTRY_V2
{
	DWORD NameOffset;
	DWORD NameLength;
	DWORD DataOffset;                     //指明API_SET_VALUE_ARRAY_V2相对于API_SET_NAMESPACE_ARRAY_V2的偏移
} API_SET_NAMESPACE_ENTRY_V2, *PAPI_SET_NAMESPACE_ENTRY_V2;

typedef struct _API_SET_NAMESPACE_ARRAY_V2
{
	DWORD Version;
	DWORD Count;       //指明有多少个API_SET_MAP_ENTRY
	API_SET_NAMESPACE_ENTRY_V2 Entry[1];
} API_SET_NAMESPACE_ARRAY_V2, *PAPI_SET_NAMESPACE_ARRAY_V2;

typedef struct _API_SET_VALUE_ENTRY_V2
{
	DWORD NameOffset;
	DWORD NameLength;
	DWORD ValueOffset;
	DWORD ValueLength;
} API_SET_VALUE_ENTRY_V2, *PAPI_SET_VALUE_ENTRY_V2;

typedef struct _API_SET_VALUE_ARRAY_V2
{
	DWORD Count;                                  //API_SET_VALUE_ENTRY_V2的数量
	API_SET_VALUE_ENTRY_V2 Entry[1];
} API_SET_VALUE_ARRAY_V2, *PAPI_SET_VALUE_ARRAY_V2;
/////////////////////////////////////////////////////////////////////////////////////////

//ApiSetSchema v4
typedef struct _API_SET_NAMESPACE_ENTRY_V4
{
	DWORD Flags;
	DWORD NameOffset;
	DWORD NameLength;
	DWORD AliasOffset;
	DWORD AliasLength;
	DWORD DataOffset;                                 //API_SET_VALUE_ARRAY_V4相对于API_SET_NAMESPACE_ARRAY_V4的偏移
} API_SET_NAMESPACE_ENTRY_V4, *PAPI_SET_NAMESPACE_ENTRY_V4;

typedef struct _API_SET_NAMESPACE_ARRAY_V4
{
	DWORD Version;
	DWORD Size;
	DWORD Flags;
	DWORD Count;                                         //指明有多少个API_SET_NAMESPACE_ENTRY_V4
	API_SET_NAMESPACE_ENTRY_V4 Entry[1];
} API_SET_NAMESPACE_ARRAY_V4, *PAPI_SET_NAMESPACE_ARRAY_V4;

typedef struct _API_SET_VALUE_ENTRY_V4
{
	DWORD Flags;
	DWORD NameOffset;
	DWORD NameLength;
	DWORD ValueOffset;
	DWORD ValueLength;
} API_SET_VALUE_ENTRY_V4, *PAPI_SET_VALUE_ENTRY_V4;

typedef struct _API_SET_VALUE_ARRAY_V4
{
	DWORD Flags;
	DWORD Count;
	API_SET_VALUE_ENTRY_V4 Entry[1];
} API_SET_VALUE_ARRAY_V4, *PAPI_SET_VALUE_ARRAY_V4;
//////////////////////////////////////////////////////////////////////////////////////////

PIMAGE_DATA_DIRECTORY GetDataDirectory(DWORD ImageBase, DWORD Index);
PDWORD  GetApiSetMapHead();
FARPROC GetExportByName(HMODULE hModule, char *ProcName);
FARPROC GetExportByOrdinal(HMODULE hModule, WORD Ordinal);
void ResolveApiSet(WCHAR *ApiSetName, WCHAR *HostName);
FARPROC FileNameRedirection(HMODULE hModule, char *RedirectionName);
FARPROC MyGetProcAddress(HMODULE hModule, char *ProcName);

