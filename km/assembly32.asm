
ifndef _WIN64

.MODEL FLAT, C

.code

; 
; @brief Calls the dump port driver's StartIo routine and returns the
;        value in the EAX register.  Windows 7 and prior only.
;
; @param[in] Pointer - address of the StartIo routine
;
; @param[in] Argument - the SRB argument to pass to StartIo
;
; @return the value stored in the EAX register after the function call
;         or -1 if invalid parameter.
;
StartIoProxyCall32@8 PROC C PUBLIC arg1:ptr, arg2:ptr
    ;
    ; Validate all arguments are present
    ;
    cmp arg1,0
    je Error

    cmp arg2,0
    je Error

    ;
    ; Call target function
    ;
    push arg2
    call arg1

    jmp Exit

    Error:
        mov eax,1
        
    Exit:
        ret 8

StartIoProxyCall32@8 ENDP

; 
; @brief Calls the dump port driver's DiskDumpIoIssue routine and returns the
;        value in the EAX register.  Windows 8 only.
;
; @param[in] Pointer - address of the DiskDumpIoIssue routine
;
; @param[in] Action - the action parameter
;
; @param[in] ScsiOp - the SCSI operation to perform
;
; @param[in] Offset - large integer offset on disk to operate on
;
; @param[in] Mdl - MDL describing the output buffer.
;
; @return the value stored in the EAX register after the function call
;         or -1 if invalid parameter.
;
DiskDumpIoIssueProxyCall32@20 PROC C PUBLIC arg1:ptr, arg2:DWORD, arg3:BYTE, arg4:ptr, arg5:ptr
    ;
    ; Validate all arguments are present
    ;
    cmp arg1,0
    je Error

    cmp arg4,0
    je Error

    cmp arg5,0
    je Error

    ;
    ; DiskDumpIoIssue is a usercall convention function and
    ; expects the Action parameter to be in edi and the
    ; ScsiOp parameter to be in bl.
    ;
    push ebx
    push edi
    mov bl, arg3
    mov edi, arg2

    ;
    ; Call target function
    ;
    push arg5
    push arg4
    call arg1

    pop edi
    pop ebx
    jmp Exit

    Error:
        mov eax,1
        
    Exit:
        ret 20

DiskDumpIoIssueProxyCall32@20 ENDP

endif

END