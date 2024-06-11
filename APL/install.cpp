#include "stdafx.h"

#define MyPackageName const_cast<PWSTR>(L"APL.DLL\0")

const SECURITY_QUALITY_OF_SERVICE sqos = {
	sizeof (sqos), SecurityImpersonation, SECURITY_DYNAMIC_TRACKING, FALSE
};

const OBJECT_ATTRIBUTES soa = { sizeof(soa), 0, 0, 0, 0, const_cast<SECURITY_QUALITY_OF_SERVICE*>(&sqos) };
const volatile UCHAR guz = 0;

NTSTATUS AdjustPrivileges(const TOKEN_PRIVILEGES* ptp)
{
	NTSTATUS status;
	HANDLE hToken, hNewToken;

	if (0 <= (status = NtOpenProcessToken(NtCurrentProcess(), TOKEN_DUPLICATE, &hToken)))
	{
		status = NtDuplicateToken(hToken, TOKEN_ADJUST_PRIVILEGES|TOKEN_IMPERSONATE, 
			const_cast<OBJECT_ATTRIBUTES*>(&soa), FALSE, TokenImpersonation, &hNewToken);

		NtClose(hToken);

		if (0 <= status)
		{
			if (STATUS_SUCCESS == (status = NtAdjustPrivilegesToken(hNewToken, FALSE, 
				const_cast<PTOKEN_PRIVILEGES>(ptp), 0, 0, 0)))
			{
				status = NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hNewToken, sizeof(hNewToken));
			}

			NtClose(hNewToken);
		}
	}

	return status;
}

BOOLEAN IsMultiSzValid(_In_ ULONG Type, _In_ PUCHAR Data, _In_ ULONG DataLength)
{
	return Type == REG_MULTI_SZ && !(DataLength & (sizeof(WCHAR) - 1)) &&
		(DataLength <= sizeof(WCHAR) || (!*(WCHAR*)(Data += DataLength - sizeof(WCHAR)) && !*((WCHAR*)Data - 1)));
}

BOOLEAN RemoveStr(_In_ PWSTR psz, _In_ PCWSTR str, _Out_ PWSTR* ppsz)
{
	BOOLEAN bExist = FALSE;

	PWSTR qsz = psz;

	while (*psz)
	{
		size_t len = wcslen(psz) + 1;

		if (_wcsicmp(psz, str))
		{
			if (psz != qsz)
			{
				memcpy(qsz, psz, len * sizeof(WCHAR));
			}

			qsz += len;
		}
		else
		{
			bExist = TRUE;
		}

		psz += len;
	}

	*qsz = 0, *ppsz = qsz + 1;

	return bExist;
}

NTSTATUS RemoveSecurityPackage(_In_ PCWSTR pszPackageName)
{
	NTSTATUS status;
	HANDLE hKey;

	UNICODE_STRING SecurityPackages, ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName };
	RtlInitUnicodeString(&ObjectName, L"\\REGISTRY\\MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Lsa");
	RtlInitUnicodeString(&SecurityPackages, L"Security Packages");

	if (0 <= (status = ZwOpenKeyEx(&hKey, KEY_READ|KEY_WRITE, &oa, REG_OPTION_BACKUP_RESTORE)))
	{
		union {
			PVOID buf;
			PKEY_VALUE_PARTIAL_INFORMATION_ALIGN64 pkvpi;
		};

		PVOID stack = alloca(guz);

		ULONG cb = 0, rcb = sizeof(KEY_VALUE_PARTIAL_INFORMATION_ALIGN64) + 0x100;
		do 
		{
			if (cb < rcb)
			{
				cb = RtlPointerToOffset(buf = alloca(rcb - cb), stack);
			}

			status = ZwQueryValueKey(hKey, &SecurityPackages, KeyValuePartialInformationAlign64, pkvpi, cb, &rcb);

		} while (status == STATUS_BUFFER_OVERFLOW);

		if (0 <= status)
		{
			status = STATUS_OBJECT_TYPE_MISMATCH;

			union {
				PUCHAR Data;
				PWSTR psz;
			};

			Data = pkvpi->Data;
			ULONG DataLength = pkvpi->DataLength;

			if (IsMultiSzValid(pkvpi->Type, Data, DataLength))
			{
				status = STATUS_NOT_FOUND;

				if (DataLength && RemoveStr(psz, pszPackageName, &psz))
				{
					DataLength = RtlPointerToOffset(pkvpi->Data, psz);
					status = ZwSetValueKey(hKey, &SecurityPackages, 0, REG_MULTI_SZ, 
						pkvpi->Data, DataLength == sizeof(WCHAR) ? 0 : DataLength);
				}
			}
		}

		NtClose(hKey);
	}

	return status;
}

#define echo(x) x
#define label(x) echo(x)##__LINE__

#define BEGIN_PRIVILEGES(name, n) static const union { TOKEN_PRIVILEGES name;\
struct { ULONG PrivilegeCount; LUID_AND_ATTRIBUTES Privileges[n];} label(_) = { n, {

#define LAA(se) {{se}, SE_PRIVILEGE_ENABLED }
#define LAA_D(se) {{se} }

#define END_PRIVILEGES }};};


BEGIN_PRIVILEGES(tp_br, 2)
	LAA(SE_BACKUP_PRIVILEGE),
	LAA(SE_RESTORE_PRIVILEGE)
END_PRIVILEGES


STDAPI DllRegisterServer()
{
	SECURITY_PACKAGE_OPTIONS spo = { sizeof(spo), SECPKG_OPTIONS_TYPE_LSA, SECPKG_OPTIONS_PERMANENT };

	if (AdjustPrivileges(&tp_br) == STATUS_SUCCESS)
	{
		RemoveSecurityPackage(MyPackageName);
		HANDLE hToken = 0;
		NtSetInformationThread(NtCurrentThread(), ThreadImpersonationToken, &hToken, sizeof(hToken));
	}
	return AddSecurityPackageW(MyPackageName, &spo);
}

STDAPI DllUnregisterServer()
{
	AdjustPrivileges(&tp_br);

	if (0 > DeleteSecurityPackageW(MyPackageName))
	{
		RemoveSecurityPackage(MyPackageName);
	}

	return S_OK;
}
