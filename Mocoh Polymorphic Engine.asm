;                            .__
;  _____   ____   ____  ____ |  |__
; /     \ /  _ \_/ ___\/  _ \|  |  \  Poly Engine
;|  Y Y  (  <_> )  \__(  <_> )   Y  \
;|__|_|  /\____/ \___  >____/|___|  /
;      \/            \/           \/
;
; [+] Simple Polymorphic PoC (code and decrypt routine)
; [+] 1byte XOR random key
; [+] The engine can change the key, and some instructions (code and order)
; [+] This is not new, not advanced... Just for education purposes
;
; By: SWaNk 2019 - Back in business, VX forever!
;
;https://pt.wikipedia.org/wiki/Mocó (Kerodon rupestris)

format PE GUI 4.0
entry start

include "%include%/win32a.inc"

; This is the poly encryption macro (1 byte xor).
; It is a simple XOR random 0x00 to 0xFF at compilation time.
;This is just a example how this can be done... Use your imagination to improve

macro encrypt dstart,dsize {
    local ..char

    key = %t and 0xff

    repeat dsize
        load ..char from dstart+%-1
        ..char = ..char xor key
        store ..char at dstart+%-1
    end repeat
}

;The idea was to create a didactic macro. this guy will split the 1 byte range in 2 (0xff / 2 = 0x7f)
;
;If the pseudo random key is bigger than 0x7f, edx will receive the real_start then ecx will receive
;the code_size. if the key is smaller than 0x7f, the order chage
;
;If the pseudo random key is bigger than 0x7f, the increase of edx will be made with "inc edx" otherwise
;with "add edx, 1"

macro simplePoly {
      if key > 0x7f
         mov edx,real_start
         mov ecx,code_size
      else
         mov ecx,code_size
         mov edx,real_start
      end if

 @@:  xor byte [edx],key

      if key > 0x7f
         inc edx
      else
         add edx,1
      end if

      loop @B
}

;this macro will generate this instructions starting at the entry point

;       mov edx,mocoh.401010       | The order of this instructions
;       mov ecx,1C                 | can change

;       xor byte ptr ds:[edx],F4   | The key will change (this case is F4)
;       inc edx                    | This can change to "add edx, 1"
;       loop mocoh.40100A

;============================================================
section ".code" code readable writeable
;============================================================
start:

simplePoly

real_start:

; Add your code here, start of encrypted code

        stdcall [MessageBox],0,msg,title,MB_ICONASTERISK
        stdcall [ExitProcess],0

; end of encrypted code


        display "Encrypting this shit... "
        code_size = $ - real_start
        encrypt real_start,code_size
        display "done",13,10

;============================================================
section ".data" data readable writeable import
;============================================================
        library kernel32,"kernel32.dll",user32,"user32.dll"
        include "%include%/api/kernel32.inc"
        include "%include%/api/user32.inc"

        title db "SWaNk 2019",0
        msg   db "compile 2 times and compare the hashes and decryption instruction bitches!",0