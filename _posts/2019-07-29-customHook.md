---
layout: article
title: "[Rev]User-defined Function Hooking"
key: 20190729
tags:
  - Dev
  - Reversing
  - Windows
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] 사용자 정의 함수 후킹

<!--more-->

음 여윽시나... 이런걸 해야 하는 순간은 생긴다. 그러나 다른 방법이 생각나지 않아 기존 후킹 방식을 이용해 스택 속이기를 시전해봤다.

요점은 이렇다. 함수 주소를 이용해 호출이 아니라 레지스터를 이용해 함수호출을 하는 경우... `CALL EAX, EBX 등등..` 이 때 함수 호출부분을 후킹하지 못하고 결국 함수 내부에서 후킹을 걸어야 하는데...

문제는 맘처럼 충분하지 않은 공간과 스택 상황, 레지스터 백업 등등 으로 인해 정상동작을 안하는 경우가 생긴다.

그래서 `PUSHAD` 명령와 `PUSHFD` 명령을 이용해 레지스터와 EFLAGS 를 백업하고 프로그램의 스택 공간에 맞춰 `POP`을 시전하여 스택을 맞춰보았다.

```c++
#include <Windows.h>
#include <stdio.h>

void targetFunc();
void newTarget();
void Hooking();

LPVOID test;
BYTE pBytes[5] = { 0, };
FARPROC pFunc = (PROC)targetFunc;
FARPROC pNew = (PROC)newTarget;
DWORD dwAddress, dwProtect;
BYTE pBuf[5] = { 0xE9,0 };

void targetFunc()
{
	printf("Hello!\n");
}

void newTarget()
{

	__asm
	{
		POP edi
		POP esi
		POP ebx
		POP ebp
		pushad
		pushfd
		MOV test, ECX
	}
	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwProtect);
	memcpy(pFunc, &pBytes, 5);
	VirtualProtect((LPVOID)pFunc, 5, dwProtect, &dwProtect);
	__asm
	{
		popfd
		popad
		CALL pFunc
	}
	Hooking();
	__asm
	{
		ret
	}
}

void Hooking()
{
	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwProtect);
	memcpy(pBytes, pFunc, 5);
	dwAddress = (DWORD)pNew - (DWORD)pFunc - 5;
	memcpy(&pBuf[1], &dwAddress, 4);
	memcpy(pFunc, pBuf, 5);
	VirtualProtect((LPVOID)pFunc, 5, dwProtect, &dwProtect);
}

int main()
{
	FARPROC pFunc = (PROC)targetFunc;
	Hooking();
	__asm
	{
		mov eax, pFunc
		CALL eax
	}
	printf("Success\n");
	return 0;

}
```

뭐 어차피 컴파일러 옵션과 빌드에 따라 항상 다를 것이지만... 실행마다 명령이 변하지는 않으니 의외로 잘 동작한다.
이제 DLL로 만들어 테스트만 하면 끄읕! 

역시 후킹은 단타용이다ㅏ!!! 내일은 저걸 이용해서 내가 원하는 작업을 해봐야겠당, 

끗!

1. 사용자 정의 함수를 레지스터를 이용해 호출 하는 상황(`CALL EAX, EBX, ECX 등등`)
2. 해당 함수 호출 시 내부에서 특정 레지스터 값만 필요함. (함수 동작 전 레지스터 값)

허접스러운 닝겐인지라 더 좋은 함수나 방법이 있으면 답변 달아주시면 감사하겠습니다.

 