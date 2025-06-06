; Hell's Gate
; Dynamic system call invocation 
; 
; by smelly__vx (@RtlMateusz) and am0nsec (@am0nsec)

.data
	wSystemCall DWORD 000h

.code 
	Gate PROC
		mov wSystemCall, 000h
		mov wSystemCall, ecx
		ret
	Gate ENDP

	Descent PROC
		mov r10, rcx
		mov eax, wSystemCall

		syscall
		ret
	Descent ENDP
end
