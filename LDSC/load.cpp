#include "stdafx.h"

//#define _PRINT_CPP_NAMES_
#include "../inc/asmfunc.h"

//////////////////////////////////////////////////////////////////////////
//
// CL /cbstring /Oi
//
//////////////////////////////////////////////////////////////////////////

#pragma code_seg(".text$mn$cpp")

#pragma intrinsic(strcmp, strlen)

#ifdef _X86_

PCWSTR getSystem32()ASM_FUNCTION;

PCWSTR getDll()ASM_FUNCTION;

PCSTR GetMapViewOfSection()ASM_FUNCTION;

#else

PCWSTR getSystem32()
{
	return L"\\system32\\";
}

PCWSTR getDll()
{
	return L"*.dll";
}

PCSTR GetMapViewOfSection()
{
	return "ZwMapViewOfSection";
}

#endif // _X86_

//int __cdecl strcmp(const char* src, const char* dst)
//{
//	for (;;++src, ++dst)
//	{
//		ULONG a = *(unsigned char*)src, b = *(unsigned char*)dst;
//		if (int ret = a - b)
//		{
//			return ret;
//		}
//		if (!a) return 0;
//	}
//}

PVOID GetNtBase()
{
	return CONTAINING_RECORD(
		NtCurrentTeb()->ProcessEnvironmentBlock->Ldr->InInitializationOrderModuleList.Flink,
		LDR_DATA_TABLE_ENTRY, InInitializationOrderLinks)->DllBase;
}

PVOID __fastcall GetFuncAddress(PIMAGE_DOS_HEADER pidh, PCSTR ProcedureName)
{
	PIMAGE_NT_HEADERS pinth = (PIMAGE_NT_HEADERS)RtlOffsetToPointer(pidh, pidh->e_lfanew);

	PIMAGE_EXPORT_DIRECTORY pied = (PIMAGE_EXPORT_DIRECTORY)RtlOffsetToPointer(pidh, 
		pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

	PDWORD AddressOfNames = (PDWORD)RtlOffsetToPointer(pidh, pied->AddressOfNames);
	PDWORD AddressOfFunctions = (PDWORD)RtlOffsetToPointer(pidh, pied->AddressOfFunctions);
	PWORD AddressOfNameOrdinals = (PWORD)RtlOffsetToPointer(pidh, pied->AddressOfNameOrdinals);

	DWORD a = 0, b = pied->NumberOfNames, o;

	if (b) 
	{
		do
		{
			int i = strcmp(ProcedureName, RtlOffsetToPointer(pidh, AddressOfNames[o = (a + b) >> 1]));
			if (!i)
			{
				PVOID pv = RtlOffsetToPointer(pidh, AddressOfFunctions[AddressOfNameOrdinals[o]]);

				if ((ULONG_PTR)pv - (ULONG_PTR)pied < pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size)
				{
					ANSI_STRING as = { (USHORT)strlen(ProcedureName), as.Length, const_cast<PSTR>(ProcedureName) };
					if (0 > LdrGetProcedureAddress((HMODULE)pidh, &as, 0, &pv)) return 0;
				}

				return pv;
			}

			if (0 > i) b = o; else a = o + 1;

		} while (a < b);
	}

	return 0;
}

PVOID __fastcall GetFuncAddress(PCSTR ProcedureName)
{
	CPP_FUNCTION;
	return GetFuncAddress((PIMAGE_DOS_HEADER)GetNtBase(), ProcedureName);
}

BOOLEAN IsImageOk(_In_ ULONG SizeOfImage, _In_ HANDLE hSection)
{
	BOOLEAN fOk = FALSE;

	SIZE_T ViewSize = 0;
	union {
		PVOID BaseAddress = 0;
		PIMAGE_DOS_HEADER pidh;
	};

	if (0 <= ZwMapViewOfSection(hSection, NtCurrentProcess(), &BaseAddress, 0, 0, 0, 
		&ViewSize, ViewUnmap, 0, PAGE_READONLY))
	{
		if (ViewSize >= SizeOfImage && pidh->e_magic == IMAGE_DOS_SIGNATURE)
		{
			ULONG VirtualAddress = pidh->e_lfanew;

			if (VirtualAddress < ViewSize - sizeof(IMAGE_NT_HEADERS))
			{
				union {
					PVOID pv;
					PIMAGE_NT_HEADERS pinth;
					PIMAGE_LOAD_CONFIG_DIRECTORY picd;
				};

				pv = RtlOffsetToPointer(BaseAddress, VirtualAddress);
				PIMAGE_SECTION_HEADER pish = 0;
				DWORD NumberOfSections = 0;
				VirtualAddress = (pinth->OptionalHeader.SizeOfHeaders + PAGE_SIZE - 1) & ~(PAGE_SIZE - 1);

				if (pinth->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR_MAGIC && 
					pinth->OptionalHeader.SizeOfImage >= SizeOfImage)
				{
					if (NumberOfSections = pinth->FileHeader.NumberOfSections)
					{
						pish = IMAGE_FIRST_SECTION(pinth);
					}

					IMAGE_DATA_DIRECTORY DataDirectory = pinth->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG];

					if (!DataDirectory.VirtualAddress)
					{
						fOk = TRUE;
					}
					else
					{
						if (DataDirectory.VirtualAddress < ViewSize - sizeof(IMAGE_LOAD_CONFIG_DIRECTORY))
						{
							pv = RtlOffsetToPointer(BaseAddress, DataDirectory.VirtualAddress);

							fOk = picd->Size < __builtin_offsetof(IMAGE_LOAD_CONFIG_DIRECTORY, GuardFlags) || 
								!picd->GuardCFFunctionCount;
						}
					}

					if (fOk)
					{
						if (pish)
						{
							do
							{
								DWORD VirtualSize = pish->Misc.VirtualSize;

								if (!VirtualSize)
								{
									continue;
								}

								if (VirtualAddress != pish->VirtualAddress)
								{
									fOk = FALSE;
									break;
								}

								VirtualAddress += VirtualSize + PAGE_SIZE - 1;

								VirtualAddress &= ~(PAGE_SIZE - 1);

							} while (pish++, --NumberOfSections);
						}
						else
						{
							fOk = FALSE;
						}
					}
				}
			}
		}

		ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);
	}

	return fOk;
}

NTSTATUS FindNoCfgDll(_In_ ULONG SizeOfImage, _Inout_ PUNICODE_STRING FileName)
{
	HANDLE hFile;
	IO_STATUS_BLOCK iosb;
	UNICODE_STRING ObjectName;
	OBJECT_ATTRIBUTES oa = { sizeof(oa), 0, &ObjectName, OBJ_CASE_INSENSITIVE };

	NTSTATUS status = RtlDosPathNameToNtPathName_U_WithStatus(FileName->Buffer, &ObjectName, 0, 0);

	if (0 <= status)
	{
		status = NtOpenFile(&oa.RootDirectory,
			FILE_LIST_DIRECTORY | SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ,
			FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);

		RtlFreeUnicodeString(&ObjectName);
	}

	if (0 <= status)
	{
		status = STATUS_NO_MEMORY;

		enum { buf_size = 0x10000 };

		PVOID ProcessHeap = RtlGetCurrentPeb()->ProcessHeap;

		if (PVOID buf = RtlAllocateHeap(ProcessHeap, 0, buf_size))
		{
			UNICODE_STRING DLL;
			RtlInitUnicodeString(&DLL, getDll());

			while (0 <= (status = NtQueryDirectoryFile(oa.RootDirectory, 
				0, 0, 0, &iosb, buf, buf_size, FileDirectoryInformation,
				FALSE, const_cast<PUNICODE_STRING>(&DLL), FALSE)))
			{
				union {
					PVOID pv;
					PUCHAR pc;
					PFILE_DIRECTORY_INFORMATION pfdi;
				};

				pv = buf;

				ULONG NextEntryOffset = 0;

				do 
				{
					pc += NextEntryOffset;

					if (pfdi->EndOfFile.QuadPart >= SizeOfImage)
					{
						ObjectName.Buffer = pfdi->FileName;
						ObjectName.MaximumLength = ObjectName.Length = (USHORT)pfdi->FileNameLength;

						PVOID hmod;
						if (STATUS_DLL_NOT_FOUND != LdrGetDllHandle(0, 0, &ObjectName, &hmod))
						{
							// dll with such name already loaded
							continue;
						}

						if (0 <= NtOpenFile(&hFile, FILE_READ_DATA|SYNCHRONIZE, &oa, &iosb, FILE_SHARE_READ, 
							FILE_NON_DIRECTORY_FILE|FILE_SYNCHRONOUS_IO_NONALERT))
						{
							BOOLEAN fOk = FALSE;

							HANDLE hSection;

							if (0 <= NtCreateSection(&hSection, SECTION_MAP_READ, 0, 0, PAGE_READONLY, SEC_IMAGE_NO_EXECUTE, hFile))
							{
								fOk = IsImageOk(SizeOfImage, hSection);

								NtClose(hSection);
							}

							NtClose(hFile);

							if (0 <= status)
							{
								if (fOk)
								{
									//DbgPrint("%I64x %wZ\n", pfdi->EndOfFile.QuadPart, &ObjectName);
									status = RtlAppendUnicodeStringToString(FileName, &ObjectName);

									goto __exit;
								}
							}
						}
					}

				} while (NextEntryOffset = pfdi->NextEntryOffset);
			}
__exit:

			RtlFreeHeap(ProcessHeap, 0, buf);
		}

		NtClose(oa.RootDirectory);
	}

	return status;
}

struct IMAGE_Ctx : public TEB_ACTIVE_FRAME
{
	PIMAGE_NT_HEADERS _M_pinth;
	PVOID _M_retAddr = 0, _M_pvImage, *_M_pBaseAddress = 0;
	PCUNICODE_STRING _M_lpFileName;
	HANDLE _M_hPipe;
	NTSTATUS _M_status = STATUS_UNSUCCESSFUL;

	IMAGE_Ctx(PTEB_ACTIVE_FRAME_CONTEXT FrameContext, HANDLE hPipe,
		PVOID pvImage, PIMAGE_NT_HEADERS pinth, PCUNICODE_STRING lpFileName) 
		: _M_pvImage(pvImage), _M_pinth(pinth), _M_lpFileName(lpFileName), _M_hPipe(hPipe)
	{
		FrameContext->Flags = 0;
		FrameContext->FrameName = GetMapViewOfSection();
		Context = FrameContext;
		Flags = 0;
		RtlPushFrame(this);
	}

	~IMAGE_Ctx()
	{
		RtlPopFrame(this);
	}

	static IMAGE_Ctx* get()
	{
		if (TEB_ACTIVE_FRAME * frame = RtlGetFrame())
		{
			do 
			{
				if (GetMapViewOfSection() == frame->Context->FrameName)
				{
					return static_cast<IMAGE_Ctx*>(frame);
				}
			} while (frame = frame->Previous);
		}

		return 0;
	}
};

struct IN_REQ 
{
	enum { tProtect = 'prct', tStatus } op;
	union {
		DWORD flNewProtect;
		NTSTATUS status;
	};
	PVOID lpAddress;
	SIZE_T dwSize;
};

NTSTATUS ProtectEx(_In_ PVOID lpAddress,
				   _In_ SIZE_T dwSize,
				   _In_ DWORD flNewProtect,
				   _In_ HANDLE hPipe,
				   _Inout_ PBOOL pb)
{
	ULONG op;
	NTSTATUS status = ZwProtectVirtualMemory(NtCurrentProcess(), &lpAddress, &dwSize, flNewProtect, &op);

	if (STATUS_DYNAMIC_CODE_BLOCKED == status)
	{
		*pb = TRUE;

		IN_REQ buf = { IN_REQ::tProtect, flNewProtect, lpAddress, dwSize };

		IO_STATUS_BLOCK iosb;
		if (0 <= (status = NtWriteFile(hPipe, 0, 0, 0, &iosb, &buf, sizeof(buf), 0, 0)))
		{
			if (STATUS_PENDING == status)
			{
				__debugbreak();
			}

			NTSTATUS s;
			if (0 <= (status = NtReadFile(hPipe, 0, 0, 0, &iosb, &s, sizeof(s), 0, 0)))
			{
				if (STATUS_PENDING == status)
				{
					__debugbreak();
				}

				status = s;
			}
		}
	}

	return status;
}

void Relocate(PVOID hmod, LONG_PTR Delta)
{
	ULONG size;

	union {
		PVOID pv;
		PBYTE pb;
		PIMAGE_BASE_RELOCATION pibr;
	};

	if (pv = RtlImageDirectoryEntryToData(hmod, TRUE, IMAGE_DIRECTORY_ENTRY_BASERELOC, &size))
	{
		ULONG SizeOfBlock;
		do 
		{
			SizeOfBlock = pibr->SizeOfBlock;

			pibr = LdrProcessRelocationBlock((PBYTE)hmod + pibr->VirtualAddress, 
				(SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) >> 1, (PUSHORT)(pibr + 1), Delta);

		} while (size -= SizeOfBlock);
	}
}

NTSTATUS OverwriteSection(_In_ PVOID BaseAddress, _In_ PVOID pvImage, _In_ PIMAGE_NT_HEADERS pinth, _In_ HANDLE hPipe)
{
	BOOL bDynBlock = FALSE;
	ULONG cb = pinth->OptionalHeader.SizeOfHeaders, VirtualSize, SizeOfRawData;
	PVOID VirtualAddress;

	NTSTATUS status;
	if (0 > (status = ProtectEx(BaseAddress, cb, PAGE_READWRITE, hPipe, &bDynBlock)))
	{
		return status;
	}

	memcpy(BaseAddress, pvImage, cb);

	ProtectEx(BaseAddress, cb, PAGE_READONLY, hPipe, &bDynBlock);

	if (ULONG NumberOfSections = pinth->FileHeader.NumberOfSections)
	{
		PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth);

		do 
		{
			if (VirtualSize = pish->Misc.VirtualSize)
			{
				VirtualAddress = RtlOffsetToPointer(BaseAddress, pish->VirtualAddress);

				ULONG Characteristics = pish->Characteristics;

				if (0 > (status = ProtectEx(VirtualAddress, VirtualSize, 
					Characteristics & IMAGE_SCN_MEM_EXECUTE ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE, hPipe, &bDynBlock)))
				{
					return status;
				}

				if (cb = min(VirtualSize, SizeOfRawData = pish->SizeOfRawData))
				{
					memcpy(VirtualAddress, RtlOffsetToPointer(pvImage, pish->PointerToRawData), cb);
				}

				if (SizeOfRawData < VirtualSize)
				{
					RtlZeroMemory(RtlOffsetToPointer(VirtualAddress, cb), VirtualSize - SizeOfRawData);
				}

				if (!(Characteristics & IMAGE_SCN_MEM_WRITE))
				{
					if (0 > (status = ProtectEx(VirtualAddress, VirtualSize, 
						Characteristics & IMAGE_SCN_MEM_EXECUTE ? PAGE_EXECUTE_READ : PAGE_READONLY, hPipe, &bDynBlock)))
					{
						return status;
					}
				}
			}

		} while (pish++, --NumberOfSections);
	}

	if (bDynBlock)
	{
		if (LONG_PTR Delta = (LONG_PTR)BaseAddress - (LONG_PTR)pinth->OptionalHeader.ImageBase)
		{
			if (0 <= (status = ProtectEx(BaseAddress, pinth->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE, hPipe, &bDynBlock)))
			{
				Relocate(BaseAddress, Delta);
				pinth->OptionalHeader.ImageBase = (ULONG_PTR)BaseAddress;

				if (ULONG NumberOfSections = pinth->FileHeader.NumberOfSections)
				{
					PIMAGE_SECTION_HEADER pish = IMAGE_FIRST_SECTION(pinth);

					do 
					{
						if (VirtualSize = pish->Misc.VirtualSize)
						{
							VirtualAddress = RtlOffsetToPointer(BaseAddress, pish->VirtualAddress);

							ULONG Characteristics = pish->Characteristics;

							ULONG dwNewProtect = 0;

							switch (Characteristics & (IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE))
							{
							case IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_WRITE:
								continue;
							case IMAGE_SCN_MEM_EXECUTE:
								dwNewProtect = PAGE_EXECUTE_READ;
								break;
							case IMAGE_SCN_MEM_WRITE:
								dwNewProtect = PAGE_READWRITE;
								break;
							case 0:
								dwNewProtect = PAGE_READONLY;
								break;
							}

							ProtectEx(VirtualAddress, VirtualSize, dwNewProtect, hPipe, &bDynBlock);
						}

					} while (pish++, --NumberOfSections);
				}
			}
		}
	}

	return STATUS_SUCCESS;
}

NTSTATUS __fastcall retFromMapViewOfSection(NTSTATUS status)
{
	CPP_FUNCTION;

	if (IMAGE_Ctx* ctx = IMAGE_Ctx::get())
	{
		*(void**)_AddressOfReturnAddress() = ctx->_M_retAddr;

		if (0 <= status)
		{
			PVOID BaseAddress = *ctx->_M_pBaseAddress;

			PIMAGE_NT_HEADERS pinth = ctx->_M_pinth;

			if (0 <= (status = OverwriteSection(BaseAddress, ctx->_M_pvImage, pinth, ctx->_M_hPipe)))
			{
				if (BaseAddress != (PVOID)pinth->OptionalHeader.ImageBase)
				{
					status = STATUS_IMAGE_NOT_AT_BASE;
				}
			}

			if (0 > status)
			{
				ZwUnmapViewOfSection(NtCurrentProcess(), BaseAddress);

				*ctx->_M_pBaseAddress = 0;
			}
		}

		ctx->_M_status = status;
	}

	return status;
}

PVOID retFromMapViewOfSectionAddr()ASM_FUNCTION;

PVECTORED_EXCEPTION_HANDLER aMyVexHandler()ASM_FUNCTION;

LONG NTAPI MyVexHandler(::PEXCEPTION_POINTERS ExceptionInfo)
{
	CPP_FUNCTION;
	::PEXCEPTION_RECORD ExceptionRecord = ExceptionInfo->ExceptionRecord;
	::PCONTEXT ContextRecord = ExceptionInfo->ContextRecord;

	if (ExceptionRecord->ExceptionCode == STATUS_SINGLE_STEP && 
		ExceptionRecord->ExceptionAddress == (PVOID)ContextRecord->Dr3)
	{
		if (IMAGE_Ctx* ctx = IMAGE_Ctx::get())
		{
			UNICODE_STRING ObjectName;
			RtlInitUnicodeString(&ObjectName, (PCWSTR)reinterpret_cast<PNT_TIB>(NtCurrentTeb())->ArbitraryUserPointer);
			if (RtlEqualUnicodeString(&ObjectName, ctx->_M_lpFileName, TRUE))
			{
				ctx->_M_pBaseAddress =
#ifdef _WIN64
					(void**)ContextRecord->R8;

#define SP Rsp
#else
#define SP Esp
					((void***)ContextRecord->Esp)[3];
#endif

				*(PSIZE_T)((void**)ContextRecord->SP)[7] = ctx->_M_pinth->OptionalHeader.SizeOfImage;

				ctx->_M_retAddr = ((void**)ContextRecord->SP)[0];

				((void**)ContextRecord->SP)[0] = retFromMapViewOfSectionAddr();
			}
		}

		ContextRecord->EFlags |= 0x10000;

		return EXCEPTION_CONTINUE_EXECUTION;
	}

	return EXCEPTION_CONTINUE_SEARCH;
}

NTSTATUS LoadLibraryFromMem(_Out_ void** phmod, 
							_In_ HANDLE hPipe, 
							_In_ PVOID pvImage, 
							_In_ PIMAGE_NT_HEADERS pinth, 
							_In_ PCUNICODE_STRING lpFileName)
{
	GUID RtlpAddVectoredHandler = { 0x1FC98BCA, 0x1BA9, 0x4397, { 0x93, 0xF9, 0x34, 0x9E, 0xAD, 0x41, 0xE0, 0x57 } };

	ULONG_PTR OldValue;
	RtlSetProtectedPolicy(&RtlpAddVectoredHandler, 0, &OldValue);

	NTSTATUS status = STATUS_UNSUCCESSFUL;

	if (PVOID VectoredHandlerHandle = RtlAddVectoredExceptionHandler(TRUE, aMyVexHandler()))
	{
		CONTEXT ctx = {};
		ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
		ctx.Dr3 = (ULONG_PTR)GetFuncAddress(GetMapViewOfSection());
		ctx.Dr7 = 0x440;

		if (0 <= (status = ZwSetContextThread(NtCurrentThread(), &ctx)))
		{
			TEB_ACTIVE_FRAME_CONTEXT FrameContext;
			IMAGE_Ctx ictx(&FrameContext, hPipe, pvImage, pinth, lpFileName);

			status = LdrLoadDll(0, 0, const_cast<PUNICODE_STRING>(lpFileName), phmod);

			ctx.Dr3 = 0;
			ctx.Dr7 = 0x400;
			ZwSetContextThread(NtCurrentThread(), &ctx);

			if (0 <= status && (0 > ictx._M_status || !ictx._M_pBaseAddress || *ictx._M_pBaseAddress != *phmod))
			{
				if (0 > ictx._M_status)
				{
					status = ictx._M_status;
				}
				else
				{
					status = STATUS_UNSUCCESSFUL;
				}
			
				LdrUnloadDll(*phmod);
			}
		}

		RtlRemoveVectoredExceptionHandler(VectoredHandlerHandle);
	}

	if (OldValue) RtlSetProtectedPolicy(&RtlpAddVectoredHandler, OldValue, &OldValue);

	return status;
}

NTSTATUS __fastcall LoadLibraryFromMem(_In_ PVOID pvImage, _In_ HANDLE hPipe)
{
	CPP_FUNCTION;

	IN_REQ buf = { };

	if (PIMAGE_NT_HEADERS pinth = RtlImageNtHeader(pvImage))
	{
		RtlWow64EnableFsRedirection(TRUE);

		WCHAR FileName[0x180];

		UNICODE_STRING ObjectName = { 0, sizeof(FileName), FileName };

		if (0 <= (buf.status = RtlAppendUnicodeToString(&ObjectName, RtlGetNtSystemRoot())) &&
			0 <= (buf.status = RtlAppendUnicodeToString(&ObjectName, getSystem32())) &&
			0 <= (buf.status = FindNoCfgDll(pinth->OptionalHeader.SizeOfImage, &ObjectName)))
		{
			buf.status = LoadLibraryFromMem(&buf.lpAddress, hPipe, pvImage, pinth, &ObjectName);
		}
	}
	else
	{
		buf.status = STATUS_INVALID_IMAGE_FORMAT;
	}

	IO_STATUS_BLOCK iosb;
	buf.op = IN_REQ::tStatus;
	if (STATUS_PENDING == NtWriteFile(hPipe, 0, 0, 0, &iosb, &buf, sizeof(buf), 0, 0))
	{
		__debugbreak();
	}

	NtClose(hPipe);

	return buf.status;
}

#pragma code_seg(".text$mn$end")

void AsmEntry()ASM_FUNCTION;

SIZE_T SizeOfShellCode()
{
	return (((PBYTE)SizeOfShellCode - (PBYTE)AsmEntry) + 7) >> 3;
}

#pragma code_seg()