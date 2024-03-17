#include "stdafx.h"

NTSTATUS ReadFromFile(_In_ HANDLE hFile, _In_ ULONG cb, _Out_ PBYTE* ppb, _Out_ ULONG* pcb)
{
	NTSTATUS status;
	FILE_STANDARD_INFORMATION fsi;
	IO_STATUS_BLOCK iosb;

	if (0 <= (status = NtQueryInformationFile(hFile, &iosb, &fsi, sizeof(fsi), FileStandardInformation)))
	{
		if (fsi.EndOfFile.QuadPart > 0x10000000)
		{
			status = STATUS_FILE_TOO_LARGE;
		}
		else
		{
			if (PBYTE pb = (PBYTE)LocalAlloc(LMEM_FIXED, cb + ((fsi.EndOfFile.LowPart + 15) & ~15)))
			{
				if (0 > (status = NtReadFile(hFile, 0, 0, 0, &iosb, pb, fsi.EndOfFile.LowPart, 0, 0)))
				{
					LocalFree(pb);
				}
				else
				{
					*ppb = pb;
					*pcb = (ULONG)iosb.Information;
				}
			}
			else
			{
				status = STATUS_NO_MEMORY;
			}
		}
	}

	return status;
}

NTSTATUS ReadFromFile(_In_ POBJECT_ATTRIBUTES poa, _In_ ULONG cb, _Out_ PBYTE* ppb, _Out_ ULONG* pcb)
{
	HANDLE hFile;
	IO_STATUS_BLOCK iosb;

	NTSTATUS status = NtOpenFile(&hFile, FILE_GENERIC_READ, poa, &iosb,
		FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);

	if (0 <= status)
	{
		status = ReadFromFile(hFile, cb, ppb, pcb);
		NtClose(hFile);
	}

	return status;
}

NTSTATUS ReadFromFile(_In_ PCUNICODE_STRING ObjectName, _In_ ULONG cb, _Out_ PBYTE* ppb, _Out_ ULONG* pcb)
{
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, const_cast<PUNICODE_STRING>(ObjectName), OBJ_CASE_INSENSITIVE };

	return ReadFromFile(&oa, cb, ppb, pcb);
}

NTSTATUS ReadFromFile(_In_ PCWSTR lpFileName, _In_ ULONG cb, _Out_ PBYTE* ppb, _Out_ ULONG* pcb)
{
	UNICODE_STRING ObjectName;

	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(lpFileName, &ObjectName, 0, 0);

	if (0 <= status)
	{
		status = ReadFromFile(&ObjectName, cb, ppb, pcb);

		RtlFreeUnicodeString(&ObjectName);
	}

	return status ;
}

NTSTATUS ReadFromFileNt(_In_ PCWSTR lpFileName, _In_ ULONG cb, _Out_ PBYTE* ppb, _Out_ ULONG* pcb)
{
	UNICODE_STRING ObjectName;
	RtlInitUnicodeString(&ObjectName, lpFileName);
	return ReadFromFile(&ObjectName, cb, ppb, pcb);
}

NTSTATUS GetProcessIdByName(PCUNICODE_STRING ImageName, ULONG SessionId, HANDLE* UniqueProcessId)
{
	ULONG cb = 0x80000;

	union {
		PVOID pv;
		PBYTE pb;
		PSYSTEM_PROCESS_INFORMATION pspi;
	};

	NTSTATUS status;

	do
	{
		status = STATUS_NO_MEMORY;
		if (PVOID buf = LocalAlloc(0, cb))
		{
			if (0 <= (status = ZwQuerySystemInformation(SystemProcessInformation, buf, (cb += 0x1000), &cb)))
			{
				status = STATUS_NOT_FOUND;

				pv = buf;

				ULONG NextEntryOffset = 0;

				do
				{
					pb += NextEntryOffset;

					if (SessionId == pspi->SessionId &&
						RtlEqualUnicodeString(&pspi->ImageName, ImageName, TRUE))
					{
						*UniqueProcessId = pspi->UniqueProcessId;
						status = STATUS_SUCCESS;
						break;
					}

				} while (NextEntryOffset = pspi->NextEntryOffset);
			}

			LocalFree(buf);
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	return status;
}