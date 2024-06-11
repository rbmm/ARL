#include "stdafx.h"

#include "log.h"
ULONG _G_LsaVersion = 0;
ULONG_PTR _G_PackageId = 0;
PLSA_SECPKG_FUNCTION_TABLE _G_FunctionTable = 0;

SECPKG_PARAMETERS _G_Parameters;

#define LSA(...) _G_FunctionTable-> __VA_ARGS__

extern volatile const UCHAR guz = 0;

LPTOP_LEVEL_EXCEPTION_FILTER g_prevFilter;
PVOID gVex;

VOID PrintException(::PEXCEPTION_RECORD ExceptionRecord)
{
	DbgPrint("!!!!! UnhandledException(%x) %x at %p\r\n", ExceptionRecord->ExceptionFlags,
		ExceptionRecord->ExceptionCode, ExceptionRecord->ExceptionAddress);

	if (ULONG NumberParameters = ExceptionRecord->NumberParameters)
	{
		if (NumberParameters > EXCEPTION_MAXIMUM_PARAMETERS)
		{
			NumberParameters = EXCEPTION_MAXIMUM_PARAMETERS;
		}

		PSTR buf = (PSTR)alloca(8 + NumberParameters * 20), psz = buf;
		PULONG_PTR ExceptionInformation = ExceptionRecord->ExceptionInformation;
		*psz++ = '[';
		do 
		{
			psz += sprintf(psz, "%p, ", (PVOID)*ExceptionInformation++);
		} while (--NumberParameters);
		strcpy(psz - 2, "]\r\n");
		LOG(write(buf, 1 + RtlPointerToOffset(buf, psz)));
	}
}

void WaitDebugger()
{
	static const LARGE_INTEGER li = { (ULONG)(-10000000*60*5),  - 1};
	ZwDelayExecution(TRUE, const_cast<PLARGE_INTEGER>(&li));

	if (IsDebuggerPresent())
	{
		__debugbreak();
	}
}

LONG WINAPI OnException(_In_ ::PEXCEPTION_POINTERS ExceptionInfo)
{
	PrintException(ExceptionInfo->ExceptionRecord);

	WaitDebugger();

	return g_prevFilter ? g_prevFilter(ExceptionInfo) : EXCEPTION_CONTINUE_SEARCH;
}

LONG NTAPI Vex(::PEXCEPTION_POINTERS ExceptionInfo)
{
	::PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;

	switch (ExceptionRecord->ExceptionCode)
	{
	case DBG_PRINTEXCEPTION_WIDE_C:
		DbgPrint("%x>++WIDE_C:\r\n", GetCurrentThreadId());
		if (1 < ExceptionRecord->NumberParameters)
		{
			SIZE_T cch = ExceptionRecord->ExceptionInformation[0];

			if (--cch < MAXSHORT)
			{
				PWSTR pwz = (PWSTR)ExceptionRecord->ExceptionInformation[1];

				ULONG cb = 0;
				PSTR psz = 0;
				while (cb = WideCharToMultiByte(CP_UTF8, 0, pwz, (ULONG)cch, psz, cb, 0, 0))
				{
					if (psz)
					{
						LOG(write(psz, cb));
						DbgPrint("\r\n--WIDE_C:\r\n");
						return EXCEPTION_CONTINUE_EXECUTION;
					}

					if (!(psz = new char[cb]))
					{
						break;
					}
				}

				if (psz)
				{
					delete [] psz;
				}
			}
		}

		if (4 > ExceptionRecord->NumberParameters)
		{
			break;
		}

		ExceptionRecord->ExceptionInformation[0] = ExceptionRecord->ExceptionInformation[2];
		ExceptionRecord->ExceptionInformation[1] = ExceptionRecord->ExceptionInformation[3];
		[[fallthrough]];
	case DBG_PRINTEXCEPTION_C:
		DbgPrint("%x>++PRINT_C:\r\n", GetCurrentThreadId());
		if (1 < ExceptionRecord->NumberParameters)
		{
			SIZE_T cch = ExceptionRecord->ExceptionInformation[0];

			if (--cch < MAXSHORT)
			{
				LOG(write((PVOID)ExceptionRecord->ExceptionInformation[1], (ULONG)cch));
				DbgPrint("\r\n--PRINT_C:\r\n");
				return EXCEPTION_CONTINUE_EXECUTION;
			}
		}
		break;
	default:
		PrintException(ExceptionRecord);
	}

	if (ExceptionRecord->ExceptionFlags & EXCEPTION_NONCONTINUABLE_EXCEPTION )
	{
		if (HMODULE hmod = GetModuleHandleW(L"lsasrv.dll"))
		{
			// #9
			// BOOL ShutdownBegun;
			if (PBOOL ShutdownBegun = (PBOOL)GetProcAddress(hmod, MAKEINTRESOURCEA(9)))
			{
				if (*ShutdownBegun == TRUE)
				{
					DbgPrint("!!!! ShutdownBegun\r\n");
					*ShutdownBegun = FALSE;
					WaitDebugger();
				}
			}
		}
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

LONG WINAPI MyFilter(_In_ PCSTR ApiName, _In_ ::PEXCEPTION_POINTERS ExceptionInfo)
{
	DbgPrint("!!!!! %s !!!!!\r\n", ApiName);
	PrintException(ExceptionInfo->ExceptionRecord);

	return EXCEPTION_EXECUTE_HANDLER;
}

struct WaitData 
{
	SRWLOCK _M_SRWLock = RTL_SRWLOCK_INIT;
	HANDLE _M_hKey = 0, _M_hEvent = 0;
	HMODULE _M_hmod = 0;
	PSECPKG_FUNCTION_TABLE _M_pTable = 0;
	ULONG _M_hash = 0;
	ULONG _M_dwThreadId = 0;

	BOOL StartNotify()
	{
		IO_STATUS_BLOCK iosb;
		return 0 <= ZwNotifyChangeKey(_M_hKey, _M_hEvent, 0, 0, &iosb, 
			REG_NOTIFY_CHANGE_LAST_SET|REG_NOTIFY_THREAD_AGNOSTIC, FALSE, 0, 0, TRUE);
	}

	PTP_WAIT Create(POBJECT_ATTRIBUTES poa)
	{
		if (0 <= ZwCreateKey(&_M_hKey, KEY_NOTIFY|KEY_QUERY_VALUE, poa, 0, 0, 0, 0))
		{
			if (_M_hEvent = CreateEvent(0, FALSE, FALSE, 0))
			{
				if (0 <= LdrAddRefDll(0, (HMODULE)&__ImageBase))
				{
					if (PTP_WAIT pwa = CreateThreadpoolWait(_S_WaitCallback, this, 0))
					{
						WaitCallback(0, pwa);
						return pwa;
					}

					LdrUnloadDll((HMODULE)&__ImageBase);
				}

				NtClose(_M_hEvent);
				_M_hEvent = 0;
			}

			NtClose(_M_hKey);
			_M_hKey = 0;
		}

		return 0;
	}

	~WaitData()
	{
		if (_M_hEvent)
		{
			NtClose(_M_hEvent);
		}

		if (_M_hKey)
		{
			NtClose(_M_hKey);
		}
	}

	void Stop(PTP_WAIT pwa)
	{
		_M_dwThreadId = GetCurrentThreadId();

		if (SetEvent(_M_hEvent))
		{
			NtWaitForAlertByThreadId(0, 0);
		}

		CloseThreadpoolWait(pwa);

		AcquireSRWLockExclusive(&_M_SRWLock);

		if (_M_hmod)
		{
			FreeLibrary(_M_hmod);
			_M_hmod = 0;
		}

		ReleaseSRWLockExclusive(&_M_SRWLock);
	}

	static VOID CALLBACK _S_WaitCallback(
		__inout      PTP_CALLBACK_INSTANCE Instance,
		__inout_opt  PVOID Context,
		__inout      PTP_WAIT pwa,
		__in         TP_WAIT_RESULT WaitResult
		)
	{
		if (WAIT_OBJECT_0 != WaitResult)
		{
			__debugbreak();
		}

		reinterpret_cast<WaitData*>(Context)->WaitCallback(Instance, pwa);
	}

	VOID WaitCallback(_In_ PTP_CALLBACK_INSTANCE Instance, _In_ PTP_WAIT pwa);
};

inline BOOL IsRegSz(PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi)
{
	ULONG DataLength = pkvpi->DataLength;
	return pkvpi->Type == REG_SZ && DataLength - 1 < MAXUSHORT && !(DataLength & 1) && 
		!(PWSTR)RtlOffsetToPointer(pkvpi->Data, DataLength)[-1];
}

VOID WaitData::WaitCallback(_In_ PTP_CALLBACK_INSTANCE Instance, _In_ PTP_WAIT pwa)
{
	if (ULONG dwThreadId = _M_dwThreadId)
	{
		FreeLibraryWhenCallbackReturns(Instance, (HMODULE)&__ImageBase);
		NtAlertThreadByThreadId((HANDLE)(ULONG_PTR)dwThreadId);
		return ;
	}

	HANDLE hKey = _M_hKey;

	NTSTATUS status;
	union {
		PVOID buf;
		PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi;
	};

	UNICODE_STRING MyAP;
	RtlInitUnicodeString(&MyAP, L"MyAP");
	PVOID stack = alloca(guz);

	ULONG cb = 0, rcb = 0x80;
	do 
	{
		if (cb < rcb)
		{
			cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
		}

		status = ZwQueryValueKey(hKey, &MyAP, KeyValuePartialInformationAlign64, buf, cb, &rcb);

	} while (STATUS_BUFFER_OVERFLOW == status);

	if (0 <= status && IsRegSz(pkvpi))
	{
		ULONG hash;
		UNICODE_STRING ObjectName;
		RtlInitUnicodeString(&ObjectName, (PWSTR)pkvpi->Data);

		if (0 <= RtlHashUnicodeString(&ObjectName, TRUE, HASH_STRING_ALGORITHM_DEFAULT, &hash) && 
			hash != _M_hash)
		{
			_M_hash = hash;

			DbgPrint("new value \"%wZ\"\r\n", &ObjectName);

			AcquireSRWLockExclusive(&_M_SRWLock);
			if (_M_hmod)
			{
				DbgPrint("---unload %p\r\n", _M_hmod);
				_M_pTable->Shutdown();
				FreeLibrary(_M_hmod);
				_M_pTable = 0;
				_M_hmod = 0;
			}

			HMODULE hmod;
			if (0 <= LdrLoadDll(0, 0, &ObjectName, (void**) & hmod))
			{
				ANSI_STRING SpLsaModeInitialize;
				RtlInitString(&SpLsaModeInitialize, "SpLsaModeInitialize");

				union {
					PVOID pfn;
					NTSTATUS (NTAPI * Initialize)(
						__in   ULONG LsaVersion,
						__out  PULONG PackageVersion,
						__out  PSECPKG_FUNCTION_TABLE* ppTables,
						__out  PULONG pcTables
						);
				};

				if (0 <= LdrGetProcedureAddress(hmod, &SpLsaModeInitialize, 0, &pfn))
				{
					SECPKG_PARAMETERS Parameters = _G_Parameters;
					ULONG PackageVersion;
					ULONG cTables;
					PSECPKG_FUNCTION_TABLE pTables;

					__try
					{
						if (0 <= Initialize(_G_LsaVersion, &PackageVersion, &pTables, &cTables) 
							&& cTables == 1 &&
							PackageVersion >= SECPKG_INTERFACE_VERSION_10 &&
							0 <= pTables->Initialize(_G_PackageId, &Parameters, _G_FunctionTable))
						{
							DbgPrint("+++load %p\r\n", hmod);
							_M_pTable = pTables;
							_M_hmod = hmod;
							hmod = 0;
						}
					} 
					__except(MyFilter("Initialize", (::PEXCEPTION_POINTERS)_exception_info()))
					{
					}
				}

				if (hmod)
				{
					DbgPrint("---fail/unload %p\r\n", _M_hmod);
					LdrUnloadDll(hmod);
				}
			}

			ReleaseSRWLockExclusive(&_M_SRWLock);
		}
	}

	if (StartNotify())
	{
		SetThreadpoolWait(pwa, _M_hEvent, 0);
	}
}

WaitData* _G_pwd = 0;

NTSTATUS NTAPI LogonUserEx2(
							_In_ PLSA_CLIENT_REQUEST ClientRequest,
							_In_ SECURITY_LOGON_TYPE LogonType,
							_In_reads_bytes_(SubmitBufferSize) PVOID ProtocolSubmitBuffer,
							_In_ PVOID ClientBufferBase,
							_In_ ULONG SubmitBufferSize,
							_Outptr_result_bytebuffer_(*ProfileBufferSize) PVOID *ProfileBuffer,
							_Out_ PULONG ProfileBufferSize,
							_Out_ PLUID LogonId,
							_Out_ PNTSTATUS SubStatus,
							_Out_ PLSA_TOKEN_INFORMATION_TYPE TokenInformationType,
							_Outptr_ PVOID *TokenInformation,
							_Out_ PUNICODE_STRING *AccountName,
							_Out_ PUNICODE_STRING *AuthenticatingAuthority,
							_Out_ PUNICODE_STRING *MachineName,
							_Out_ PSECPKG_PRIMARY_CRED PrimaryCredentials,
							_Outptr_ PSECPKG_SUPPLEMENTAL_CRED_ARRAY * SupplementalCredentials
							)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;

	AcquireSRWLockShared(&_G_pwd->_M_SRWLock);

	if (_G_pwd->_M_pTable)
	{
		if (PLSA_AP_LOGON_USER_EX2 LogonUserEx2 = _G_pwd->_M_pTable->LogonUserEx2)
		{
			__try
			{
				status = LogonUserEx2(ClientRequest,
					LogonType,
					ProtocolSubmitBuffer,
					ClientBufferBase,
					SubmitBufferSize,
					ProfileBuffer,
					ProfileBufferSize,
					LogonId,
					SubStatus,
					TokenInformationType,
					TokenInformation,
					AccountName,
					AuthenticatingAuthority,
					MachineName,
					PrimaryCredentials,
					SupplementalCredentials);
			} 
			__except(MyFilter(__FUNCTION__, (::PEXCEPTION_POINTERS)_exception_info()))
			{
				status = GetExceptionCode();
			}
		}
	}

	ReleaseSRWLockShared(&_G_pwd->_M_SRWLock);

	return status;
}

NTSTATUS NTAPI CallPackage (
							_In_ PLSA_CLIENT_REQUEST ClientRequest,
							_In_reads_bytes_(SubmitBufferLength) PVOID ProtocolSubmitBuffer,
							_In_ PVOID ClientBufferBase,
							_In_ ULONG SubmitBufferLength,
							_Outptr_result_bytebuffer_(*ReturnBufferLength) PVOID *ProtocolReturnBuffer,
							_Out_ PULONG ReturnBufferLength,
							_Out_ PNTSTATUS ProtocolStatus
							)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;

	AcquireSRWLockShared(&_G_pwd->_M_SRWLock);

	if (_G_pwd->_M_pTable)
	{
		if (PLSA_AP_CALL_PACKAGE CallPackage = _G_pwd->_M_pTable->CallPackage)
		{
			__try
			{
				status = CallPackage(ClientRequest, ProtocolSubmitBuffer, ClientBufferBase,
					SubmitBufferLength, ProtocolReturnBuffer, ReturnBufferLength, ProtocolStatus);
			} 
			__except(MyFilter(__FUNCTION__, (::PEXCEPTION_POINTERS)_exception_info()))
			{
				status = GetExceptionCode();
			}
		}
	}

	ReleaseSRWLockShared(&_G_pwd->_M_SRWLock);

	return status;
}

VOID NTAPI LogonTerminated (_In_ PLUID LogonId)
{
	AcquireSRWLockShared(&_G_pwd->_M_SRWLock);
	if (_G_pwd->_M_pTable)
	{
		if (PLSA_AP_LOGON_TERMINATED LogonTerminated = _G_pwd->_M_pTable->LogonTerminated)
		{
			__try
			{
				LogonTerminated(LogonId);
			} 
			__except(MyFilter(__FUNCTION__, (::PEXCEPTION_POINTERS)_exception_info()))
			{
			}
		}
	}
	ReleaseSRWLockShared(&_G_pwd->_M_SRWLock);
}

NTSTATUS NTAPI PostLogonUser(_In_ PSECPKG_POST_LOGON_USER_INFO PostLogonUserInfo)
{
	NTSTATUS status = STATUS_NOT_SUPPORTED;

	AcquireSRWLockShared(&_G_pwd->_M_SRWLock);

	if (_G_pwd->_M_pTable)
	{
		if (LSA_AP_POST_LOGON_USER* PostLogonUser = _G_pwd->_M_pTable->PostLogonUser)
		{
			__try
			{
				status = PostLogonUser(PostLogonUserInfo);
			} 
			__except(MyFilter(__FUNCTION__, (::PEXCEPTION_POINTERS)_exception_info()))
			{
				status = GetExceptionCode();
			}
		}
	}

	ReleaseSRWLockShared(&_G_pwd->_M_SRWLock);

	return status;
}

NTSTATUS NTAPI SpShutdown()
{
	if (gVex)
	{
		RemoveVectoredExceptionHandler(gVex);
	}
	SetUnhandledExceptionFilter(g_prevFilter);
	DbgPrint("SpShutdown\r\n");
	LOG(Destroy());
	return STATUS_SUCCESS; 
}

NTSTATUS NTAPI SpGetInfo(_Out_ PSecPkgInfoW PackageInfo)
{
	DbgPrint("SpGetInfo\r\n");
	// SECPKG_FLAG_NEGOTIABLE2 !! (only 201, KerbCertificateLogon, KerbCertificateUnlockLogon )
	PackageInfo->fCapabilities = SECPKG_FLAG_LOGON|SECPKG_FLAG_NEGOTIABLE;
	PackageInfo->wVersion = SECURITY_SUPPORT_PROVIDER_INTERFACE_VERSION;
	PackageInfo->wRPCID = RPC_C_AUTHN_NONE;
	PackageInfo->Name = const_cast<PWSTR>(L"UAPL");
	PackageInfo->Comment = 0;
	PackageInfo->cbMaxToken = 0x2000;

	return STATUS_SUCCESS;
}

NTSTATUS NTAPI Initialize(
						  _In_ ULONG_PTR PackageId,
						  _In_ PSECPKG_PARAMETERS Parameters,
						  _In_ PLSA_SECPKG_FUNCTION_TABLE FunctionTable
						  )
{
	_G_PackageId = PackageId;
	_G_FunctionTable = FunctionTable;
	_G_Parameters = *Parameters;
	
	if (Parameters->DomainName.Length) RtlDuplicateUnicodeString(0, &Parameters->DomainName, &_G_Parameters.DomainName);
	if (Parameters->DnsDomainName.Length) RtlDuplicateUnicodeString(0, &Parameters->DnsDomainName, &_G_Parameters.DnsDomainName);
	
	if (PSID DomainSid = Parameters->DomainSid)
	{
		ULONG cb = RtlLengthSid(DomainSid);
		if (_G_Parameters.DomainSid = LocalAlloc(LMEM_FIXED, cb))
		{
			RtlCopySid(cb, _G_Parameters.DomainSid, DomainSid);
		}
	}

	if (_G_pwd = new WaitData)
	{
		UNICODE_STRING ObjectName;
		OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };
		RtlInitUnicodeString(&ObjectName, L"\\registry\\MACHINE\\SOFTWARE\\rbmm");

		if (_G_pwd->Create(&oa))
		{
			return STATUS_SUCCESS;
		}

		delete _G_pwd;
		_G_pwd = 0;
	}

	return STATUS_UNSUCCESSFUL;
}

const SECPKG_FUNCTION_TABLE g_Table = { 
	0, 
	0, 
	CallPackage, 
	LogonTerminated, 
	CallPackage, 
	CallPackage, 
	0, 
	LogonUserEx2, 
	Initialize, 
	SpShutdown, 
	SpGetInfo,
	0, 
	0,//SpAcquireCredentialsHandle, 
	0, 
	0,//SpFreeCredentialsHandle, 
	0, 
	0, 
	0, 
	0,//SpInitLsaModeContext, 
	0,//SpAcceptLsaModeContext, 
	0,//SpDeleteContext, 
	0, 
	0, 
	0,//SpGetExtendedInformation, 
	0,//SpQueryContextAttributes, 
	0, 
	0,//SpSetExtendedInformation, 
	0, 
	0, 
	0, 
	0,//SpQueryMetaData, 
	0,//SpExchangeMetaData, 
	0, 
	0, 
	0, 
	PostLogonUser
};

NTSTATUS NTAPI SpLsaModeInitialize(
								   __in   ULONG LsaVersion,
								   __out  PULONG PackageVersion,
								   __out  PSECPKG_FUNCTION_TABLE* ppTables,
								   __out  PULONG pcTables
								   )
{
	_G_LsaVersion = LsaVersion;
	*PackageVersion = SECPKG_INTERFACE_VERSION_10;
	*ppTables = const_cast<PSECPKG_FUNCTION_TABLE>(&g_Table);
	*pcTables = 1;
	LOG(Init());
	g_prevFilter = SetUnhandledExceptionFilter(OnException);
	gVex = AddVectoredExceptionHandler(TRUE, Vex);
	return STATUS_SUCCESS;
}
