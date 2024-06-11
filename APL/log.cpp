#include "stdafx.h"

#include "log.h"

void DumpBytes(PCSTR msg, const BYTE* pb, ULONG cb, ULONG dwFlags)
{
	PSTR psz = 0;
	ULONG cch = 0;
	while (CryptBinaryToStringA(pb, cb, dwFlags, psz, &cch))
	{
		if (psz)
		{
			DbgPrint(msg);
			LOG(write(psz, cch));
			LOG(write("\r\n", 2));
			break;
		}

		psz = (PSTR)alloca(cch);
	}
}

CLogFile CLogFile::s_logfile;

NTSTATUS CLogFile::Init()
{
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName };
	RtlInitUnicodeString(&ObjectName, L"\\systemroot\\temp\\UAPL");

	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	NTSTATUS status = NtCreateFile(&hFile, FILE_ADD_FILE, &oa, &iosb, 0, FILE_ATTRIBUTE_DIRECTORY,
		FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_DIRECTORY_FILE, 0, 0);

	if (0 <= status)
	{
		NtClose(hFile);
	}

	return status;
}

NTSTATUS CLogFile::Init(_In_ PTIME_FIELDS tf)
{
	WCHAR lpFileName[128];

	if (0 >= swprintf_s(lpFileName, _countof(lpFileName), 
		L"\\systemroot\\temp\\UAPL\\%u-%02u-%02u.log", tf->Year, tf->Month, tf->Day))
	{
		return STATUS_INTERNAL_ERROR;
	}

	IO_STATUS_BLOCK iosb;
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
	RtlInitUnicodeString(&ObjectName, lpFileName);

	NTSTATUS status = NtCreateFile(&oa.RootDirectory, FILE_APPEND_DATA|SYNCHRONIZE, &oa, &iosb, 0, 0,
		FILE_SHARE_READ|FILE_SHARE_WRITE, FILE_OPEN_IF, FILE_SYNCHRONOUS_IO_NONALERT, 0, 0);

	if (0 <= status)
	{
		_hFile = oa.RootDirectory;
	}

	return status;
}

void CLogFile::printf(_In_ PCSTR format, ...)
{
	union {
		FILETIME ft;
		LARGE_INTEGER time;
	};

	TIME_FIELDS tf;

	GetSystemTimeAsFileTime(&ft);
	RtlTimeToTimeFields(&time, &tf);

	va_list ap;
	va_start(ap, format);

	PSTR buf = 0;
	int len = 0;

	enum { tl = _countof("[hh:mm:ss] ") - 1};

	while (0 < (len = _vsnprintf(buf, len, format, ap)))
	{
		if (buf)
		{
			if (tl - 1 == sprintf_s(buf -= tl, tl, "[%02u:%02u:%02u]", tf.Hour, tf.Minute, tf.Second))
			{
				buf[tl - 1] = ' ';

				write(buf, tl + len, &tf);
			}

			break;
		}

		buf = (PSTR)alloca(len + tl) + tl;
	}
}

void CLogFile::write(const void* pv, ULONG cb, _In_ PTIME_FIELDS tf)
{
	HANDLE hFile;

	if (_day != tf->Day)
	{
		AcquireSRWLockExclusive(&_SRWLock);	

		if (_day != tf->Day)
		{
			if (hFile = _hFile)
			{
				NtClose(hFile);
				_hFile = 0;
			}

			if (0 <= Init(tf))
			{
				_day = tf->Day;
			}
		}

		ReleaseSRWLockExclusive(&_SRWLock);
	}

	AcquireSRWLockShared(&_SRWLock);

	if (hFile = _hFile) WriteFile(hFile, pv, cb, &cb, 0);

	ReleaseSRWLockShared(&_SRWLock);
}

void CLogFile::write(const void* pv, ULONG cb)
{
	union {
		FILETIME ft;
		LARGE_INTEGER time;
	};

	TIME_FIELDS tf;

	GetSystemTimeAsFileTime(&ft);
	RtlTimeToTimeFields(&time, &tf);

	write(pv, cb, &tf);
}

void CLogFile::Destroy()
{
	if (HANDLE hFile = _hFile)
	{
		NtClose(hFile);
	}
}

