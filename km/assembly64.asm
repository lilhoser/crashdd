
ifdef _WIN64

.code


; 
; @brief Calls the dump port driver's DiskDumpIoIssue routine and returns the
;        value in the EAX register.  Windows 8 only.
;
; @param[in] Pointer (rcx) - address of the DiskDumpIoIssue routine
;
; @param[in] Action (edx) - the action parameter
;
; @param[in] ScsiOp (r8) - the SCSI operation to perform
;
; @param[in] Offset (r9) - large integer offset on disk to operate on
;
; @param[in] Mdl (rsp+40) - MDL describing the output buffer.
;
; @return the value stored in the EAX register after the function call
;         or -1 if invalid parameter.
;
DiskDumpIoIssueProxyCall64 PROC

    sub rsp, 32

    ;
    ; Validate required arguments are present
    ;
    cmp rcx,0
    je Error

    cmp r9,0
    je Error

    cmp qword ptr [rsp + 40],0
    je Error

    mov r11, rcx
    
    mov ecx, edx                         ; action
    mov rdx, r9                          ; offset
    mov r9b, r8b                         ; scsiop
    mov qword ptr r8, [rsp + 32 + 40]    ; mdl

    ;
    ; Call target function
    ;
    call r11

    jmp Exit

    Error:
        mov rax,1
        
    Exit:
        add rsp, 32
        ret

DiskDumpIoIssueProxyCall64 ENDP


; 
; @brief Calls the dump port driver's StartIo routine and returns the
;        value in the RAX register.  Windows 7 and prior only.
;
; @param[in] Pointer (rcx) - address of the StartIo routine
;
; @param[in] Argument (rdx) - the SRB argument to pass to StartIo
;
; @return the value stored in the RAX register after the function call
;         or -1 if invalid parameter.
;
StartIoProxyCall64 PROC

    sub rsp, 32

    ;
    ; Validate all arguments are present
    ;
    cmp rcx,0
    je Error

    cmp rdx,0
    je Error

    mov r11, rcx
    mov rcx, rdx

    ;
    ; Call target function
    ;
    call r11

    jmp Exit

    Error:
        mov rax,1
        
    Exit:
        add rsp, 32
        ret

StartIoProxyCall64 ENDP

endif

END