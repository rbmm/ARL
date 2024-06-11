#pragma once

class CLogFile
{
private:
	HANDLE _hFile = 0;
	SRWLOCK _SRWLock = SRWLOCK_INIT;
	CSHORT _day = MAXSHORT;

	NTSTATUS Init(_In_ PTIME_FIELDS tf);
	void write(const void* pv, ULONG cb, _In_ PTIME_FIELDS tf);

public:
	static CLogFile s_logfile;

	NTSTATUS Init();

	void write(const void* pv, ULONG cb);

	void printf(_In_ PCSTR format, ...);

	void Destroy();
};

#define DbgPrint CLogFile::s_logfile.printf

#define LOG(...)  CLogFile::s_logfile.__VA_ARGS__

void DumpBytes(PCSTR msg, const BYTE* pb, ULONG cb, ULONG dwFlags);

#pragma message("!!! LOG >>>>>>")
