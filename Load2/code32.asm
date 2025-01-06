.686
.model flat

PAGELK SEGMENT READ WRITE EXECUTE 'CODE'

; long __stdcall LoadLibraryFromMem(void *,unsigned long,void **)

?LoadLibraryFromMem@@YGJPAXKPAPAX@Z PROC
include <..\..\SC\LFM\LFMpX86.asm>
?LoadLibraryFromMem@@YGJPAXKPAPAX@Z ENDP

PAGELK ENDS

END
