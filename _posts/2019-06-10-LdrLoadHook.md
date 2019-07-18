---
layout: article
title: "[Rev]LdrLoadDll Hooking(2)"
key: 20190610
tags:
  - Dev
  - Reversing
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] LdrLoadDll Hooking(2)

<!--more-->

공부한건 써먹어야 된다. `Detours` 라이브러리를 이용하여 짧은 코드로 후킹!!!!

## [+] Source Code

```c++
#include <stdio.h>
#include <Windows.h>
#include <SubAuth.h>
#include "detours.h"

#pragma comment(lib,"detours.lib")

typedef NTSTATUS (NTAPI *PFLDRLOADDLL)(
	IN PWCHAR               PathToFile OPTIONAL,
	IN ULONG                *Flags OPTIONAL,
	IN UNICODE_STRING		*ModuleFileName,
	OUT PHANDLE             *ModuleHandle
	);

PVOID OrgLdr = DetourFindFunction("ntdll.dll", "LdrLoadDll");

NTSTATUS NTAPI NewLdrLoadDll(
	IN PWCHAR               PathToFile OPTIONAL,
	IN ULONG                *Flags OPTIONAL,
	IN UNICODE_STRING		*ModuleFileName,
	OUT PHANDLE             *ModuleHandle)
{
	TCHAR tmpPath[MAX_PATH];
	lstrcpynW(tmpPath,ModuleFileName->Buffer,ModuleFileName->Length);
	printf("[#] ModuleName : %ws\n", tmpPath);
	//printf("[#] ModuleName : %wZ\n", *ModuleFileName);
	NTSTATUS err=((PFLDRLOADDLL)OrgLdr)(NULL, Flags, ModuleFileName, ModuleHandle);
	return  err;
	
}

int main()
{
	LONG errcode;
	printf("[#] Detours Hooking Start...\n");
	Sleep(50);
	DetourRestoreAfterWith();
	printf("[#] Import Table Saved\n");
	DetourTransactionBegin();
	printf("[#] Ready\n");
	system("pause");
	DetourUpdateThread(GetCurrentThread());
	printf("[#] Get Thread\n");
	DetourAttach(&OrgLdr, NewLdrLoadDll);
	printf("[#] Detours Hooking Setup Complete\n");
	errcode = DetourTransactionCommit();
	if (errcode == NO_ERROR)
	{
		printf("[#] Detours Hooking Complete\n");
	}
	else
	{
		printf("[!] Error Code : %d\n", errcode);
	}
	LoadLibrary(L"wininet.dll");
	LoadLibrary(L"d3d9.dll");
	MessageBoxA(NULL, "Hello!", "Shh0ya", MB_OK);
	
	return 0;
}
```

DetourFindFunction 이란 좋은 함수를 알았다. Undoc API의 경우 어떻게 사용할라나... 하고 봤는데 저런 함수가 있어서 참 편하게 됐다.(물론 삽질함)

출력결과 :

```
[#] Detours Hooking Start...
[#] Import Table Saved
[#] Ready
계속하려면 아무 키나 누르십시오 . . .
[#] Get Thread
[#] Detours Hooking Setup Complete
[#] Detours Hooking Complete
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\System32\MSCTF.dll
[#] ModuleName : C:\WINDOWS\System32\MSCTF.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : kernel32.dll
[#] ModuleName : kernel32.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : kernel32.dll
[#] ModuleName : kernel32.dll
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : OLEAUT32.DLL
[#] ModuleName : C:\WINDOWS\System32\MSCTF.dll
[#] ModuleName : kernel32.dll
[#] ModuleName : kernel32.dll
[#] ModuleName : C:\WINDOWS\System32\MSCTF.dll
[#] ModuleName : C:\WINDOWS\System32\MSCTF.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : C:\WINDOWS\system32\uxtheme.dll
[#] ModuleName : wininet.dll
[#] ModuleName : d3d9.dll
[#] ModuleName : api-ms-win-appmodel-runtime-l1-1-2
```

스택 걱정없이 아름답게 후킹 성공!  에러 없이 잘 돌아간다.

끝!