; Segment type: Pure code
; Segment permissions: Read/Execute
_text           segment para public 'CODE' use32
                assume cs:_text
                ;org 8049030h
                assume es:nothing, ss:nothing, ds:_data, fs:nothing, gs:nothing

; =============== S U B R O U T I N E =======================================

; Attributes: noreturn bp-based frame

; void __cdecl __noreturn main(int, char *s)
                public main
main            proc near               ; DATA XREF: LOAD:08048018↑o

s               = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                cmp     dword ptr [ebp+4], 2 ; Check for missing key (args != 2)
                jnz     short missing_key
                mov     edi, [ebp+s]
                test    edi, edi
                jz      short missing_key
                push    edi             ; param_ptr_key
                call    check_key
                call    exit
; ---------------------------------------------------------------------------

missing_key:                            ; CODE XREF: main+7↑j main+E↑j
                lea     edi, str_no_key ; "Mutter! Mutter! Gib mir arg!\n./prog <k"...
                push    edi             ; s
                call    _puts
                call    exit
main            endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __cdecl check_key(char *param_ptr_key)
check_key       proc near               ; CODE XREF: main+11↑p

param_ptr_key   = dword ptr  8

ref_ptr_key = edi
                push    ebp
                mov     ebp, esp
                mov     ref_ptr_key, [ebp+param_ptr_key]
                test    ref_ptr_key, ref_ptr_key
                call    shake
                push    ref_ptr_key     ; s
                call    _strlen
                cmp     eax, 16
;
; Must be = 16 chars
;
                jnz     wrong_key
                movzx   eax, byte ptr [ref_ptr_key]
                movzx   ebx, byte ptr [ref_ptr_key+2]
                sub     ebx, 20h
                cmp     ebx, eax
;
; [0] uppercase = [2] lowercase (-32)
;
                jnz     wrong_key
                movzx   eax, byte ptr [ref_ptr_key+1]
                movzx   ebx, byte ptr [ref_ptr_key+6]
                cmp     eax, ebx
;
; [1] = [6]
;
                jnz     wrong_key
                sub     eax, 30h
                test    eax, eax
;
; [1] = 0
;
                jnz     wrong_key
                movzx   ebx, byte ptr [ref_ptr_key+8]
                inc     eax
                sub     ebx, 30h
                cmp     eax, ebx
;
; [8] = 1
;
                jnz     wrong_key
                movzx   ebx, byte ptr [ref_ptr_key+12]
                inc     eax
                sub     ebx, 30h
                dec     ebx
                cmp     eax, ebx
;
; [12] = 3
;
                jnz     wrong_key
                movzx   eax, byte ptr [ref_ptr_key+4]
                movzx   ebx, byte ptr [ref_ptr_key+7]
                sub     eax, 20h
                xor     eax, ebx
                test    eax, eax
;
; [4] uppercase = [7] lowercase
;
                jnz     wrong_key
                movzx   eax, byte ptr [ref_ptr_key+9]
                movzx   ebx, byte ptr [ref_ptr_key+10]
                inc     eax
                cmp     eax, ebx
;
; [10] = [9]-1
;
                jnz     wrong_key
                movzx   eax, byte ptr [ref_ptr_key+3]
                cmp     eax, '_'
;
; [3] = '_'
;
                jnz     wrong_key
                movzx   eax, byte ptr [ref_ptr_key+4]
                movzx   ebx, byte ptr [ref_ptr_key+10]
                inc     eax
                dec     ebx
                cmp     eax, ebx
;
; [10] = [4]+2
;
                jnz     short wrong_key
                movzx   eax, byte ptr [ref_ptr_key+14]
                mov     ebx, 1
                shl     ebx, 5
                inc     ebx
                cmp     eax, ebx
;
; [14] = !
;
                jnz     short wrong_key
                movzx   ebx, byte ptr [ref_ptr_key+2]
                push    7
                push    ebx
                call    shake
                cmp     eax, 1
;
; [2] = w
;
                jnz     short wrong_key
                movzx   ebx, byte ptr [ref_ptr_key+4]
                push    6
                push    ebx
                call    shake
                cmp     eax, 1
;
; [4] = f
;
                jnz     short wrong_key
                movzx   eax, byte ptr [ref_ptr_key+5]
                movzx   ebx, byte ptr [ref_ptr_key+11]
                mov     ecx, eax
                xor     ecx, ebx
                cmp     ecx, 1Bh
;
; [5] ^ [11] = 0x1b
;
                jnz     short wrong_key
                mov     ecx, eax        ; eax = [5]
                add     ecx, ebx        ; ebx = [11]
                cmp     ecx, 0A3h       ; ecx = [5] + [11]
;
; [5] + [11] = 0xA3
;
                jnz     short wrong_key
                sub     ebx, eax        ; ebx = [11] - [5]
                cmp     ebx, 5          ; [11] - [5] = 5
;
; [11] - [5] = 5
;
                jnz     short wrong_key
                movzx   ebx, byte ptr [ref_ptr_key+13]
                cmp     ebx, 'r'
;
; [13] = r
;
                jnz     short wrong_key
                movzx   eax, byte ptr [ref_ptr_key+14]
                movzx   ebx, byte ptr [ref_ptr_key+15]
                cmp     eax, ebx
;
; [15] = [14]
;
                jnz     short wrong_key
                call    good_key
                leave
                retn
; ---------------------------------------------------------------------------

wrong_key:                              ; CODE XREF: check_key+16↑j
                                        ; check_key+28↑j ...
                lea     ref_ptr_key, str_wrong_key ; "Nope, wrong password\n"
                push    ref_ptr_key     ; s
                call    _puts
                call    exit
check_key       endp ; sp-analysis failed


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

; int __usercall good_key@<eax>(int key@<edi>)
good_key        proc near               ; CODE XREF: check_key+117↑p

arg_7           = byte ptr  0Fh

index = ebx
reg_str_enc_flag = esi
reg_key = edi
                push    ebp
                mov     ebp, esp
                xor     index, index
                xor     ecx, ecx
                lea     reg_str_enc_flag, str_encrypted_flag
;
; ebx = 0
; ecx = 0
; esi = ptr enc_flag
;

decrypt_flag_loop:                      ; CODE XREF: good_key+25↓j
                and     ecx, 0Fh
                movzx   eax, byte ptr [reg_str_enc_flag+index]
                movzx   edx, byte ptr [reg_key+ecx]
                xor     eax, edx
                mov     [reg_str_enc_flag+index], al
                inc     index
                inc     ecx
                cmp     index, 0D5h
                jl      short decrypt_flag_loop
                push    reg_str_enc_flag ; s
                call    _puts
                leave
                retn
good_key        endp


; =============== S U B R O U T I N E =======================================

; Attributes: bp-based frame

shake           proc near               ; CODE XREF: check_key+8↑p
                                        ; check_key+C3↑p ...

arg_0           = dword ptr  8
arg_4           = dword ptr  0Ch

                push    ebp
                mov     ebp, esp
                xor     eax, eax
                mov     edx, [ebp+arg_0]
                mov     esi, [ebp+arg_4]
                mov     ecx, edx
                and     ecx, 0F0h
                shr     ecx, 4
                and     edx, 0Fh
                cmp     ecx, edx
                jnz     short f0o_foO
                cmp     ecx, esi
                jnz     short f0o_foO
                inc     eax

f0o_foO:                                ; CODE XREF: shake+1B↑j
                                        ; shake+1F↑j
                leave
                retn
shake           endp


; =============== S U B R O U T I N E =======================================

; Attributes: noreturn

exit            proc near               ; CODE XREF: main+16↑p
                                        ; main+27↑p ...
                mov     eax, 1
                mov     ebx, 0          ; status
                int     80h             ; LINUX - sys_exit
exit            endp

_text           ends