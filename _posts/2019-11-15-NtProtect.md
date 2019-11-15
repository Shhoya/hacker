---
layout: article
title: "[Rev]NtProtectVirtualMemory"
key: 20191115
tags:
  - Dev
  - Reversing
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] NtProtectVirtualMemory

<!--more-->

VMP 기능 중 Memory Protection 이라는 기능이 존재한다. 이 기능이 적용 된 프로그램에는 후킹이 안된다. 그 이유가 `NtProtectVirtualMemory` 함수를 VMP에서 후킹하기 때문이다.

후킹을 하기 위해서는 원하는 메모리 공간의 권한을 바꿔야 한다. 이 때 자주 사용하는 함수가 `VirtualProtect` 이다.

두 가지 방법을 사용하여 후킹에 성공했다.

첫 번째는 간단하게 `WriteProcessMemory` 함수를 이용하여 원래의 5바이트로 돌려놓은 것이다. 정말 쉽게 해결되었다. 

```c++
{
		BYTE unHooked[5] = { 0x4C,0x8B,0xD1,0xB8,0x50 };
		HMODULE hModule = GetModuleHandleA("ntdll.dll");
		FARPROC pNtVirtualProtect = GetProcAddress(hModule, "NtProtectVirtualMemory");
		WriteProcessMemory(GetCurrentProcess(), pNtVirtualProtect, unHooked, 5, NULL);

}
```



두 번째 방법은 `NtProtectVirtualMemory`의 원형을 알면 내가 구현하면 되지 않을까 싶었다. 내 운영체제에서 해당 함수의 번호는 0x50 이었다.

```
mov r10,rcx
mov eax,50
test byte ptr ds:[7FFE0308],1
jne ntdll.7FF98A63CAC5
syscall 
ret 
int 2E
ret 
```

재배치따위도 필요없다. 11바이트의 공간만있다면........

아래 소스코드를 컴파일하여 실행해보면 `VirtualProtect`를 호출하지 않고 내가 만든 `NtProtectVirtualMemory`로 메모리 공간의 권한이 변경되는 것을 확인할 수 있다.

## [+] Source

```c++
#include <stdio.h>
#include <Windows.h>
#include <ntstatus.h>

typedef NTSTATUS(NTAPI *PFNTPROTECTVIRTUALMEMORY)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection
	);

BYTE bNtProtect[11] = {
					 0x4C,0x8B,0xD1,
					 0xB8,0x50,0x00,0x00,0x00,
					 0x0F,0x05,
					 0xC3 };


void testFunction()
{
	MessageBoxA(NULL, "Hello", "Shh0ya", MB_OK);
}

int main()
{
	BYTE cc[1] = { 0xCC };
	DWORD dwProtect = 0;
	FARPROC pMem = (PROC)testFunction;
	MEMORY_BASIC_INFORMATION info;
	ZeroMemory(&info, sizeof(info));
	VirtualQuery(pMem, &info, sizeof(MEMORY_BASIC_INFORMATION));
	fprintf(stdout,"BaseAddress : %IX\nAllocProtect : %X\nProtect : %X\nState : %X\n", info.BaseAddress,info.AllocationProtect,info.Protect,info.State);
	
	//========================================================//
	//===============  NtProtectVirtualMemory  ===============//
	//========================================================//
	LPVOID NtProtectVirtualMemory_ = VirtualAlloc(NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);;
	ULONG size = 10;
	memcpy(NtProtectVirtualMemory_, bNtProtect, 11);
	ULONG uProtect = 0;
	PULONG pSize = &size;

	NTSTATUS Flag = ((PFNTPROTECTVIRTUALMEMORY)NtProtectVirtualMemory_)(GetCurrentProcess(), (PVOID*)&pMem, pSize, PAGE_EXECUTE_READWRITE, &uProtect);
	if (Flag != STATUS_SUCCESS)
	{
		fprintf(stderr, "[+] Syscall Error");
		return -1;
	}

	else
	{
		fprintf(stdout,"================================================================\n");
		VirtualQuery(pMem, &info, sizeof(MEMORY_BASIC_INFORMATION));
		fprintf(stdout,"BaseAddress : %IX\nAllocProtect : %X\nProtect : %X\nState : %X\n", info.BaseAddress, info.AllocationProtect, info.Protect, info.State);
		return 0;
	}
}
```

```
===============output

BaseAddress : 7FF7C4831000
AllocProtect : 80
Protect : 20	// PAGE_EXECUTE_READ
State : 1000
================================================================
BaseAddress : 7FF7C4831000
AllocProtect : 80
Protect : 80	// PAGE_EXECUTE_READWRITE(PAGE_EXECUTE_WRITECOPY)
State : 1000
```





