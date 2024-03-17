#include "stdafx.h"

extern CHAR sc_begin[], sc_end[];
extern CHAR dll_begin[], dll_end[];

void Notify(NTSTATUS status, PVOID RemoteBase)
{
	wchar_t msg[0x40], txt[0x100];
	swprintf_s(msg, _countof(msg), L"status = %x, base = %p", status, RemoteBase);

	ULONG dwFlags;
	PVOID pv;

	if (status)
	{
		pv = GetModuleHandleW(L"ntdll.dll");
		dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS| FORMAT_MESSAGE_FROM_HMODULE;
	}
	else
	{
		pv = 0;
		dwFlags = FORMAT_MESSAGE_IGNORE_INSERTS | FORMAT_MESSAGE_FROM_SYSTEM;
	}

	FormatMessageW(dwFlags, pv, status, 0, txt, _countof(txt), 0);

	MessageBoxW(0, txt, msg, MB_ICONINFORMATION);
}

enum {
	FLAG_PIPE_CLIENT_SYNCHRONOUS = 0x01,
	FLAG_PIPE_CLIENT_INHERIT = 0x02,
	FLAG_PIPE_SERVER_SYNCHRONOUS = 0x04,
	FLAG_PIPE_SERVER_INHERIT = 0x8,
};

#define FILE_SHARE_VALID_FLAGS 0x00000007

NTSTATUS CreatePipeAnonymousPair(PHANDLE phServerPipe, PHANDLE phClientPipe, ULONG Flags, DWORD nInBufferSize = 0)
{
	HANDLE hFile;

	IO_STATUS_BLOCK iosb;

	UNICODE_STRING NamedPipe;
	RtlInitUnicodeString(&NamedPipe, L"\\Device\\NamedPipe\\");

	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &NamedPipe, OBJ_CASE_INSENSITIVE };

	NTSTATUS status;

	if (0 <= (status = NtOpenFile(&hFile, SYNCHRONIZE, &oa, &iosb, FILE_SHARE_VALID_FLAGS, 0)))
	{
		oa.RootDirectory = hFile;

		LARGE_INTEGER timeout = { 0, (LONG)MINLONG };
		UNICODE_STRING empty = {};

		oa.Attributes = (Flags & FLAG_PIPE_SERVER_INHERIT) ? OBJ_INHERIT : 0;
		oa.ObjectName = &empty;

		if (0 <= (status = NtCreateNamedPipeFile(phServerPipe,
			FILE_READ_ATTRIBUTES | FILE_READ_DATA |
			FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA |
			FILE_CREATE_PIPE_INSTANCE | SYNCHRONIZE,
			&oa, &iosb, FILE_SHARE_READ | FILE_SHARE_WRITE,
			FILE_CREATE,
			Flags & FLAG_PIPE_SERVER_SYNCHRONOUS ? FILE_SYNCHRONOUS_IO_NONALERT : 0,
			FILE_PIPE_MESSAGE_TYPE, FILE_PIPE_MESSAGE_MODE,
			FILE_PIPE_QUEUE_OPERATION, 1, nInBufferSize, nInBufferSize, &timeout)))
		{
			oa.RootDirectory = *phServerPipe;
			oa.Attributes = (Flags & FLAG_PIPE_CLIENT_INHERIT) ? OBJ_INHERIT : 0;

			if (0 > (status = NtOpenFile(phClientPipe, SYNCHRONIZE | FILE_READ_ATTRIBUTES | FILE_READ_DATA |
				FILE_WRITE_ATTRIBUTES | FILE_WRITE_DATA, &oa, &iosb, FILE_SHARE_VALID_FLAGS,
				Flags & FLAG_PIPE_CLIENT_SYNCHRONOUS ? FILE_SYNCHRONOUS_IO_NONALERT : 0)))
			{
				NtClose(oa.RootDirectory);
				*phServerPipe = 0;
			}
		}

		NtClose(hFile);
	}

	return status;
}

NTSTATUS PipeLoop(_In_ HANDLE hServer, _In_ HANDLE hProcess, _Out_ void** ppv)
{
	struct IN_REQ
	{
		enum { tProtect = 'prct', tStatus } op;
		union {
			DWORD flNewProtect;
			NTSTATUS status;
		};
		PVOID lpAddress;
		SIZE_T dwSize;
	} req;

	NTSTATUS status;
	IO_STATUS_BLOCK iosb;

	while (0 <= (status = NtReadFile(hServer, 0, 0, 0, &iosb, &req, sizeof(req), 0, 0)))
	{
		if (sizeof(IN_REQ) == iosb.Information)
		{
			ULONG op;
			switch (req.op)
			{
			case IN_REQ::tProtect:
				status = ZwProtectVirtualMemory(hProcess, &req.lpAddress, &req.dwSize, req.flNewProtect, &op);
				if (0 > (status = NtWriteFile(hServer, 0, 0, 0, &iosb, &status, sizeof(status), 0, 0)))
				{
					return status;
				}
				break;

			case IN_REQ::tStatus:
				*ppv = req.lpAddress;
				return req.status;

			default:
				return STATUS_BAD_DATA;
			}
		}
		else
		{
			return STATUS_INFO_LENGTH_MISMATCH;
		}
	}

	return status;
}

NTSTATUS Inject(ULONG dwProcessId, PBYTE pbSc, ULONG cbSc, ULONG Entry, BOOL bUnload)
{
	CLIENT_ID cid = { (HANDLE)(ULONG_PTR)dwProcessId };
	HANDLE hProcess;
	NTSTATUS status;
	OBJECT_ATTRIBUTES zoa = { sizeof(zoa) };

	PVOID RemoteBase = 0;

	if (0 <= (status = NtOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &zoa, &cid)))
	{
		HANDLE hServer, hClient;
		if (0 <= (status = CreatePipeAnonymousPair(&hServer, &hClient,
			FLAG_PIPE_CLIENT_SYNCHRONOUS | FLAG_PIPE_SERVER_SYNCHRONOUS, 0)))
		{
			PVOID buf = 0;
			SIZE_T size = cbSc;

			if (0 <= (status = NtAllocateVirtualMemory(hProcess, &buf, 0, &size, MEM_COMMIT, PAGE_EXECUTE_READWRITE)))
			{
				if (0 <= (status = NtDuplicateObject(NtCurrentProcess(), hClient,
					hProcess, (HANDLE*)(pbSc + Entry + 8), 0, 0, DUPLICATE_SAME_ACCESS | DUPLICATE_CLOSE_SOURCE)))
				{
					if (0 <= (status = NtWriteVirtualMemory(hProcess, buf, pbSc, cbSc, &size)) &&
						0 <= (status = RtlCreateUserThread(hProcess, 0, 0, 0, 0, 0,
							(PUSER_THREAD_START_ROUTINE)((PBYTE)buf + Entry + 3), buf, 0, 0)))
					{
						buf = 0;
					}
				}
				hClient = 0;

				if (buf) NtFreeVirtualMemory(hProcess, &buf, &(size = 0), MEM_RELEASE);
			}

			if (hClient) NtClose(hClient);

			if (0 <= status)
			{
				status = PipeLoop(hServer, hProcess, &RemoteBase);
			}

			NtClose(hServer);
		}

		if (0 <= status && RemoteBase)
		{
			if (bUnload)
			{
				dwProcessId = 0;

				Notify(status, RemoteBase);

				RtlCreateUserThread(hProcess, 0, 0, 0, 0, 0,
					(PUSER_THREAD_START_ROUTINE)LdrUnloadDll, RemoteBase, 0, 0);
			}
		}

		NtClose(hProcess);
	}

	if (dwProcessId) Notify(status, RemoteBase);

	return status;
}

void Inj(_In_ ULONG dwProcessId)
{
	ULONG cb = (ULONG)(dll_end - dll_begin), ss = (ULONG)(sc_end - sc_begin);
	ULONG s = (cb + 15) & ~15;

	if (PBYTE pb = new BYTE[s + ss])
	{
		memcpy(pb, dll_begin, cb);
		memcpy(pb + s, sc_begin, ss);

		Inject(dwProcessId, pb, s + ss, s, FALSE);
		delete[] pb;
	}
}

NTSTATUS ReadFromFileNt(_In_ PCWSTR lpFileName, _In_ ULONG cb, _Out_ PBYTE* ppb, _Out_ ULONG* pcb);
NTSTATUS GetProcessIdByName(PCUNICODE_STRING ImageName, ULONG SessionId, HANDLE* UniqueProcessId);

void Inj()
{
	UNICODE_STRING ImageName;
	RtlInitUnicodeString(&ImageName, L"fontdrvhost.exe");
	HANDLE dwProcessId;
	NTSTATUS status = GetProcessIdByName(&ImageName, 0, &dwProcessId);
	if (0 <= status)
	{
		union {
			PVOID pv;
			PBYTE pb;
		};

		ULONG cb, ss = (ULONG)(sc_end - sc_begin);

		if (0 <= (status = ReadFromFileNt(L"\\systemroot\\system32\\mswsock.dll", ss, &pb, &cb)))
		{
			ULONG s = (cb + 15) & ~15;
			memcpy(pb + s, sc_begin, ss);

			Inject((ULONG)(ULONG_PTR)dwProcessId, pb, s + ss, s, TRUE);

			LocalFree(pb);
		}
	}

	if (0 > status)
	{
		Notify(status, 0);
	}
}

void yy()
{
#ifndef _WIN64
	void* wow;
	if (0 > NtQueryInformationProcess(NtCurrentProcess(), ProcessWow64Information, &wow, sizeof(wow), 0))
	{
		return;
	}

	if (wow)
	{
		STARTUPINFOW si = { sizeof(si) };
		PROCESS_INFORMATION pi;
		WCHAR cmd[] = L"cmd.exe";
		if (CreateProcessW(0, cmd, 0, 0, 0, 0, 0, 0, &si, &pi))
		{
			NtClose(pi.hThread);
			NtClose(pi.hProcess);

			Sleep(1000);
			Inj(pi.dwProcessId);
		}

		return;
	}
#endif

	if (HWND hwnd = GetShellWindow())
	{
		ULONG dwProcessId;

		if (GetWindowThreadProcessId(hwnd, &dwProcessId))
		{
			Inj(dwProcessId);
		}
	}

	Inj();
}

void WINAPI ep(BOOLEAN we)
{
	RtlAdjustPrivilege(SE_DEBUG_PRIVILEGE, TRUE, FALSE, &we);
	yy();
	ExitProcess(0);
}