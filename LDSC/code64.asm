
; void *__cdecl GetFuncAddress(const char *)
extern ?GetFuncAddress@@YAPEAXPEBD@Z : PROC

; long __cdecl retFromMapViewOfSection(long)
extern ?retFromMapViewOfSection@@YAJJ@Z : PROC

; long __cdecl LoadLibraryFromMem(void *,void *)
extern ?LoadLibraryFromMem@@YAJPEAX0@Z : PROC

; long __cdecl MyVexHandler(struct _EXCEPTION_POINTERS *)
extern ?MyVexHandler@@YAJPEAU_EXCEPTION_POINTERS@@@Z : PROC

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; .text$mn$asm 

_TEXT$asm SEGMENT ALIGN(16)

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; must be at section begin !!

; void __cdecl AsmEntry(void)
?AsmEntry@@YAXXZ proc
	nop
	nop
	nop
	call @@1
	DQ 0 ; hPipe
@@1:
	pop rdx
	mov rdx,[rdx] ; rdx = hPipe
	mov [rsp + 8],rcx ; BaseAddress
	sub rsp,28h
	call ?LoadLibraryFromMem@@YAJPEAX0@Z
	add rsp,28h
	xor rcx,rcx
	mov r9,8000h ; MEM_RELEASE
	mov rdx,[rsp + 8] ; BaseAddress
	mov [rdx],rdx
	lea r8,[rdx + 8] ; RegionSize
	mov [r8],rcx ; RegionSize = 0
	dec rcx ; NtCurrentProcess()
	jmp NtFreeVirtualMemory
?AsmEntry@@YAXXZ endp

; void *__cdecl retFromMapViewOfSectionAddr()
?retFromMapViewOfSectionAddr@@YAPEAXXZ proc
	lea rax,@@1
	ret
@@1:
	mov ecx,eax
	call ?retFromMapViewOfSection@@YAJJ@Z
?retFromMapViewOfSectionAddr@@YAPEAXXZ endp

; long (__cdecl *__cdecl aMyVexHandler(void))(struct _EXCEPTION_POINTERS *)
?aMyVexHandler@@YAP6AJPEAU_EXCEPTION_POINTERS@@@ZXZ proc
	lea rax,@@1
	ret
@@1:
	jmp ?MyVexHandler@@YAJPEAU_EXCEPTION_POINTERS@@@Z
?aMyVexHandler@@YAP6AJPEAU_EXCEPTION_POINTERS@@@ZXZ endp

common_imp_call proc private
	push r9
	push r8
	push rdx
	push rcx
	sub rsp,28h
	mov rcx,rax
	call ?GetFuncAddress@@YAPEAXPEBD@Z
	add rsp,28h
	pop rcx
	pop rdx
	pop r8
	pop r9
	jmp rax
common_imp_call endp

NtApi MACRO name
name proc
	lea rax,@@1
	jmp common_imp_call
@@1: 
	DB '&name',0
name endp
ENDM

;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;; ++ Import

NtApi LdrGetProcedureAddress
NtApi LdrLoadDll
NtApi LdrUnloadDll
NtApi LdrGetDllHandle
NtApi LdrProcessRelocationBlock

NtApi NtCreateSection
NtApi ZwMapViewOfSection
NtApi ZwUnmapViewOfSection
NtApi ZwProtectVirtualMemory

NtApi NtOpenFile
NtApi NtQueryDirectoryFile
NtApi NtClose
NtApi NtReadFile
NtApi NtWriteFile

NtApi NtFreeVirtualMemory

NtApi ZwSetContextThread

NtApi RtlInitUnicodeString
NtApi RtlEqualUnicodeString
NtApi RtlAppendUnicodeStringToString
NtApi RtlAppendUnicodeToString
NtApi RtlGetNtSystemRoot
NtApi RtlDosPathNameToNtPathName_U_WithStatus
NtApi RtlFreeUnicodeString

NtApi RtlAllocateHeap
NtApi RtlFreeHeap

NtApi RtlPushFrame
NtApi RtlPopFrame
NtApi RtlGetFrame

NtApi RtlGetCurrentPeb

NtApi RtlImageNtHeader
NtApi RtlImageDirectoryEntryToData

NtApi RtlAddVectoredExceptionHandler
NtApi RtlRemoveVectoredExceptionHandler
NtApi RtlSetProtectedPolicy

NtApi RtlWow64EnableFsRedirection

NtApi memset
NtApi memcpy

;; -- Import
;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

_TEXT$asm ENDS

end