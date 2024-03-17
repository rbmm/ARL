.686
.MODEL FLAT

CONST segment

public ?sc_begin@@3PADA, ?sc_end@@3PADA
public ?dll_begin@@3PADA, ?dll_end@@3PADA

?dll_begin@@3PADA:
INCLUDE <..\Release\dll.asm>
?dll_end@@3PADA:

?sc_begin@@3PADA:
INCLUDE <..\Release\sc-load.asm>
?sc_end@@3PADA:

CONST ends

end