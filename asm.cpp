#include <stdio.h>
#include <Windows.h>

class Demo {
	public:
  int a = 10;
  virtual void func() { printf("内部 func\n");}

};


void func(Demo *obj) {   
	__asm {
		push obj
	}
	printf("外部 func: %d\n", obj->a);

  __asm {
		sub esp, 0x4
	}

}


__declspec(naked) int add(int a, int b, int c) {
	
	__asm {
		push ebp
		mov ebp, esp
		push ebx
		push esi
		push edi
		xor eax,eax;
		add eax, [ebp + 0x8]
		add eax, [ebp + 0xC]
		add eax, [ebp + 0x10]
		pop edi
		pop esi
		pop ebx
		pop ebp
		retn
	}

}


int main(int argc, const char *argv[]) { 
  int ret = 0;

  const char *aa[] = {"1234", "12345", "1111111111111", "132123"};

	const char *arg = aa[3];

	Demo demo;

	Demo *obj = &demo;

	LPVOID lpaddr;
  DWORD oldpro;
	
	__asm {
		mov eax, [obj]
		mov eax, [eax]
		mov lpaddr, eax
  }

	VirtualProtect(lpaddr, 0x4, PAGE_EXECUTE_READWRITE, &oldpro);

  __asm {
		mov edx, func
		mov ecx, [lpaddr]
		mov [ecx], edx
		push obj
	}

	obj->func();
	
	__asm {
		add esp, 0x4
	}

	_asm {
		mov edx, aa[12]
		mov eax, [edx]
		mov [arg], edx
		push 0x3
		push 0x2
		push 0x1
		call [add]
		add esp, 0xC
		mov [ebp - 0x8], eax;
  }
	
	printf("after:  %d, %s\n", ret,  arg);

	return 0; 
}