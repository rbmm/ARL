#include "stdafx.h"

ULONG SaveToFile(_In_ PCWSTR lpFileName, _In_ const void* lpBuffer, _In_ ULONG nNumberOfBytesToWrite)
{
	HANDLE hFile = CreateFileW(lpFileName, FILE_APPEND_DATA, 0, 0, CREATE_ALWAYS, 0, 0);

	if (INVALID_HANDLE_VALUE != hFile)
	{
		ULONG dwError = WriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, 
			&nNumberOfBytesToWrite, 0) ? NOERROR : GetLastError();

		CloseHandle(hFile);

		return dwError;
	}

	return GetLastError();
}

#ifdef _X86_
#define __imp_sprintf_s _imp__sprintf_s
#pragma comment(linker, "/INCLUDE:__imp__sprintf_s")
#else
#pragma comment(linker, "/INCLUDE:__imp_sprintf_s")
#endif // _X86_

EXTERN_C_START
PVOID __imp_sprintf_s = 0;
EXTERN_C_END

HRESULT PrepareCode(PCWSTR FileName, PULONG64 pb, SIZE_T n)
{
	HRESULT hr = E_OUTOFMEMORY;

	SIZE_T cch = n * (7 + 16) + 1;

	if (PSTR buf = (PSTR)LocalAlloc(GMEM_FIXED, cch))
	{
		hr = ERROR_INTERNAL_ERROR;

		int len;

		PSTR psz = buf;

		do
		{
			if (0 >= (len = sprintf_s(psz, cch, "DQ 0%016I64xh\r\n", *pb++)))
			{
				break;
			}

		} while (psz += len, cch -= len, --n);

		if (!n)
		{
			hr = SaveToFile(FileName, buf, RtlPointerToOffset(buf, psz));
		}

		LocalFree(buf);
	}

	return hr;
}

void AsmEntry();

SIZE_T SizeOfShellCode();

void WINAPI ep(void*)
{
	__imp_sprintf_s = GetProcAddress(GetModuleHandleW(L"ntdll"), "sprintf_s");
	ExitProcess(PrepareCode(L"sc-load.asm", (PULONG64)AsmEntry, SizeOfShellCode()));
}