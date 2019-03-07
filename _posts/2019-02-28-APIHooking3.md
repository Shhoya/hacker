---
layout: article
title: "[Rev]API Hooking(Code Patch)"
key: 20190228
tags:
  - Reversing
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] Windows Hooking(4)

<!--more-->

## [+] API Code patch

DLL 인젝션을 이용한 API 후킹은 IAT가 존재하지 않으면 후킹이 불가능했다. 그러나 코드패치는 그러한 제약이 없기 때문에 매우 유용한 후킹 기법이다.

이 기법은 말 그대로 프로세스에 로드된 라이브러리에서 원하는 API 함수를 찾아 수정하는 방식이다.

이번에 후킹하는 API는 `ZwQuerySystemInformation` 함수인데 이 함수를 이용해 프로세스를 은닉할 예정이다. 정상적인 프로세스의 경우 함수를 호출 시 다음과 같은 과정이 있다.

```sh
00001111	CALL DWORD PTR DS:[2222]
....
00002222	33330000	# ntdll!ZwQuerySystemInformation, IAT
....
00003333	MOV EAX	#ZwQuerySystemInformation 함수의 시작
.....
```

순서대로 보면 `CALL` 명령을 통해 0x00002222 오프셋에 있는 값(주소)을 호출한다. 해당 값은 `ZwQuerySystemInformation` 함수의 시작주소이다. 그리고 정상적으로 함수가 시작된다. 

코드패치를 통해 후킹된 프로세스의 경우 다음과 같이 동작하게 된다.

```sh
00001111	CALL DWORD PTR DS:[2222]
....
00002222	33330000	#ntdll!ZwQuerySystemInformation
....
00003333	JMP 4444	# Hooking Function
00003338	~~~~~
....
00004444	SUB ESP,10C
....
00004455	CALL unhook()
.....
00004xxx	CALL EAX	# EAX=ZwQuerySystemInformation()
....
00004xxxx	CALL hook()
....
00004xxxx	RETN 10
```

이해를 쉽게 해보기 위해 위와 같이 정리했다.
먼저 정상적인 프로세스와 마찬가지로 `ZwQuerySystemInformation` 함수를 호출한다. 그런데 해당 함수의 시작 주소의 5byte(Opcode)를 `JMP 00004444`로 패치를 해버렸다. 이 후킹된 프로세스의 흐름은 다음과 같이 진행된다.

1. `ntdll!ZwQuerySystemInformation` 함수 호출
2. `JMP 00004444`(변조된 5byte) 명령으로 인해 후킹 함수로 점프
3. `CALL unhook()`에 의해 언훅되어 변조되었던 5byte를 원래의 명령어로 복원
4. `CALL EAX`(원본 `ZwQuerySystemInformation`함수) 명령으로 원본 함수를 호출
5. 원본 함수는 리턴을하게 되고 실행 흐름이 다시 후킹 함수로 돌아옴
6. `CALL hook()` 명령에 의해 다시 원본 함수의 첫 5byte를 변조하여 후킹함
7. 실행이 완료되면 리턴을하고 원래 프로세스의 실행흐름으로 돌아감

뭔가 복잡하고 이리저리 왔다갔다 한다. 그런데 일단 책에는 제약이 없는 후킹 기법이라고 한다. 

## [+] Stealth Process

이제 프로세스를 숨기는 것에 대한 방법이다. 유저모드에서 가장 널리 사용되는 것이 `ntdll.ZwQuerySystemInformation`API 함수를 후킹하는 것이다.

 프로세스 은폐의 원리가 책에 알기 쉽게 나와있다. 스텔스 전투기에 비유하며 이야기하고 있는데, 스텔스 전투기는 뛰어난 기술력으로 전투기 자체를 은폐시킨다. 그러나 프로세스 은폐의 동작 원리는 그와 반대된다. 라고 한다.

마치 일반 비행기가 비행을 할 때 모든 레이더를 고장내면 비행기는 추적당하지 않는다. 와 같은 원리라고 설명하고 있다. 좋은 설명이다.

프로세스를 검색하는 API로는 `CreateToolhelp32Snapshot(),EnumProcess()`와 `ZwQuerySystemInformation()`이 있다. `ZwQuerySystemInformation` 함수는 실행 중인 모든 프로세스의 정보(구조체)를 연결 리스트 형태로 확인할 수 있다. 그 연결 리스트에서 특정 구조체를 빼내면 해당 프로세스가 은폐되는 것이다. 

그러나 여기에도 문제점이 존재한다. 예를 들어 `ProcExp` 툴과 `taskmgr` 에서 해당 함수를 이용하여 프로세스를 검색하고 있다고 생각해보면 이 두 개의 프로세스를 모두 후킹해야 한다. 두개라 쉬워보이지만 다수가 되는 순간 지옥구경이다.
또한 새로 생성되는 프로세스에 대해서는 어찌 후킹해야 하는가이다.

이에 대한 해결책은 특정 프로세스를 숨기기 위해 모든 프로세스의 `ZwQuerySystemInformation` API를 후킹해야 하고, 나중에 생성되는 프로세스에 대해서도 후킹이 되어야 한다. 이러한 기법을 글로벌 후킹이라고 한다.

책에서와 마찬가지로 글로벌 후킹은 다음에 다루기로 하고 우선 실습을 진행해본다.

### HideProc.exe & stealth.dll

예제파일인 `HideProc.exe`와 `stealth.dll` 을 이용하여 프로세스를 숨겨본다. 명령은 `HideProc.exe -hide | -show <process name> <Dll Name>` 으로 구성되어 있다. 해당 프로그램을 이용해 notepad를 숨겨보면 잘 숨겨지는 것을 확인할 수 있다.
물론 글로벌 후킹을 통해 모든 프로세스에 후킹이 된다. 단 새로 생성되는 것에 대한 문제는 해결되지 않은 프로그램이다.

사용해보고, 소스코드 분석으로 진행해본다.

## [+] Analysis

### HookProc.exe

전체 소스코드

```c
#include "windows.h"
#include "stdio.h"
#include "tlhelp32.h"
#include "tchar.h"

typedef void (*PFN_SetProcName)(LPCTSTR szProcName);
enum {INJECTION_MODE = 0, EJECTION_MODE};

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

    if( !LookupPrivilegeValue(NULL,            // lookup privilege on local system
                              lpszPrivilege,   // privilege to lookup 
                              &luid) )        // receives LUID of privilege
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

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE                  hProcess, hThread;
	LPVOID                  pRemoteBuf;
	DWORD                   dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE  pThreadProc;

	if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )
    {
        printf("OpenProcess(%d) failed!!!\n", dwPID);
		return FALSE;
    }

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, 
                                MEM_COMMIT, PAGE_READWRITE);

	WriteProcessMemory(hProcess, pRemoteBuf, 
                       (LPVOID)szDllPath, dwBufSize, NULL);

	pThreadProc = (LPTHREAD_START_ROUTINE)
                  GetProcAddress(GetModuleHandle(L"kernel32.dll"), 
                                 "LoadLibraryW");
	hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                 pThreadProc, pRemoteBuf, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);	

	VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return TRUE;
}

BOOL EjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	BOOL                    bMore = FALSE, bFound = FALSE;
	HANDLE                  hSnapshot, hProcess, hThread;
	MODULEENTRY32           me = { sizeof(me) };
	LPTHREAD_START_ROUTINE  pThreadProc;

	if( INVALID_HANDLE_VALUE == 
        (hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, dwPID)) )
		return FALSE;

	bMore = Module32First(hSnapshot, &me);
	for( ; bMore ; bMore = Module32Next(hSnapshot, &me) )
	{
		if( !_tcsicmp(me.szModule, szDllPath) || 
            !_tcsicmp(me.szExePath, szDllPath) )
		{
			bFound = TRUE;
			break;
		}
	}

	if( !bFound )
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}

	if( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )
	{
		CloseHandle(hSnapshot);
		return FALSE;
	}

	pThreadProc = (LPTHREAD_START_ROUTINE)
                  GetProcAddress(GetModuleHandle(L"kernel32.dll"), 
                                 "FreeLibrary");
	hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                 pThreadProc, me.modBaseAddr, 0, NULL);
	WaitForSingleObject(hThread, INFINITE);	

	CloseHandle(hThread);
	CloseHandle(hProcess);
	CloseHandle(hSnapshot);

	return TRUE;
}

BOOL InjectAllProcess(int nMode, LPCTSTR szDllPath)
{
	DWORD                   dwPID = 0;
	HANDLE                  hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32          pe;

	// Get the snapshot of the system
	pe.dwSize = sizeof( PROCESSENTRY32 );
	hSnapShot = CreateToolhelp32Snapshot( TH32CS_SNAPALL, NULL );

	// find process
	Process32First(hSnapShot, &pe);
	do
	{
		dwPID = pe.th32ProcessID;

        // 시스템의 안정성을 위해서
        // PID 가 100 보다 작은 시스템 프로세스에 대해서는
        // DLL Injection 을 수행하지 않는다.
		if( dwPID < 100 )
			continue;

        if( nMode == INJECTION_MODE )
		    InjectDll(dwPID, szDllPath);
        else
            EjectDll(dwPID, szDllPath);
	}
	while( Process32Next(hSnapShot, &pe) );

	CloseHandle(hSnapShot);

	return TRUE;
}

int _tmain(int argc, TCHAR* argv[])
{
    int                     nMode = INJECTION_MODE;
    HMODULE                 hLib = NULL;
    PFN_SetProcName         SetProcName = NULL;

	if( argc != 4 )
	{
		printf("\n Usage  : HideProc.exe <-hide|-show> "\
               "<process name> <dll path>\n\n");
		return 1;
	}

	// change privilege
    SetPrivilege(SE_DEBUG_NAME, TRUE);

    // load library
    hLib = LoadLibrary(argv[3]);

    // set process name to hide
    SetProcName = (PFN_SetProcName)GetProcAddress(hLib, "SetProcName");
    SetProcName(argv[2]);

    // Inject(Eject) Dll to all process
    if( !_tcsicmp(argv[1], L"-show") )
	    nMode = EJECTION_MODE;

    InjectAllProcess(nMode, argv[3]);
    // free library
    FreeLibrary(hLib);
	return 0;
}
```

`HookProc.exe`는 실행 중인 모든 프로세스에 DLL 인젝션/이젝션 하는 프로그램이다. 기존에 DLL인젝션 코드에서 `InjectAllProcess` 함수만 추가되었다.(InjectDll.exe)

#### InjectAllProcess()

```c
BOOL InjectAllProcess(int nMode, LPCTSTR szDllPath)
{
	DWORD                   dwPID = 0;
	HANDLE                  hSnapShot = INVALID_HANDLE_VALUE;
	PROCESSENTRY32          pe;
	// Get the snapshot of the system
	pe.dwSize = sizeof( PROCESSENTRY32 );
	hSnapShot = CreateToolhelp32Snapshot( TH32CS_SNAPALL, NULL );
	// find process
	Process32First(hSnapShot, &pe);
	do
	{
		dwPID = pe.th32ProcessID;

        // 시스템의 안정성을 위해서
        // PID 가 100 보다 작은 시스템 프로세스에 대해서는
        // DLL Injection 을 수행하지 않는다.
		if( dwPID < 100 )
			continue;
        if( nMode == INJECTION_MODE )
		    InjectDll(dwPID, szDllPath);
        else
            EjectDll(dwPID, szDllPath);
	}
	while( Process32Next(hSnapShot, &pe) );
	CloseHandle(hSnapShot);
	return TRUE;
}
```

해당 함수에서는 모든 프로세스에 DLL 인젝션을 수행한다. 프로세스를 찾기 위해 `CreateToolhelp32Snapshot`, `Process32First`, `Process32Next` 함수를 이용하는 것을 볼 수 있다. 또한 시스템 프로세스는 건들지 않기 위해 100 미만의 프로세스에는 인젝션을 수행하지 않는 것을 볼 수 있다. 

간략하게 현재 실행중인 프로세스의 PID와 프로세스 이름을 가져오는 코드를 가지고 소스코드를 이해해본다.

```c
#include <stdio.h>
#include <Windows.h>
#include <tlhelp32.h>
#include <tchar.h>

void main()
{
	HANDLE                  hSnapShot ;
	PROCESSENTRY32          pe;
	pe.dwSize = sizeof( PROCESSENTRY32 );
	hSnapShot = CreateToolhelp32Snapshot( TH32CS_SNAPALL, NULL );
	_tprintf(_T("<PID>\t\t<Process Name>\n"));
	Process32First(hSnapShot, &pe);
	do
	{
		_tprintf(_T("%d\t\t%s\n"),pe.th32ProcessID,pe.szExeFile);
	}
	while( Process32Next(hSnapShot, &pe) );

	CloseHandle(hSnapShot);

}
```

먼저 `PROCESSENTRY32` 라는 구조체를 이용해 `pe` 라는 변수를 생성한다.
해당 구조체는 다음과 같다.

```c
typedef struct tagPROCESSENTRY32 {
  DWORD     dwSize;
  DWORD     cntUsage;
  DWORD     th32ProcessID;
  ULONG_PTR th32DefaultHeapID;
  DWORD     th32ModuleID;
  DWORD     cntThreads;
  DWORD     th32ParentProcessID;
  LONG      pcPriClassBase;
  DWORD     dwFlags;
  CHAR      szExeFile[MAX_PATH];
} PROCESSENTRY32;
```

여기서 각 멤버를 살펴보면 중요한게 `dwSize`이다. 구조체의 사이즈인데 `Process32First` 함수를 호출하기 전에 `sizeof(PROCESSENTRY32)` 로 초기화 해줘야 한다고 MSDN에 친절히 설명이 되어있다. 그렇기 때문에 `pe.dWsize=sizeof(PROCESSENTRY32)` 로 크기를 초기화 해준 것 이다.

다음 `CreateToolhelp32Snapshot` 함수를 호출하는데 이 때 넘어가는 파라미터 값은 `TH32CS_SNAPALL`, `NULL` 이 넘어가는 시스템에 있는 프로세스,모듈,스레드 스냅샷을 찍는다. 리턴 값은 스냅샷의 열린 핸들을 리턴한다.(그래서 CloseHandle()을 사용한 것)

다음 `Process32First`를 이용하여 스냅샷의 첫번째 프로세스 정보를 가져오고 , `Process32Next`를 이용하여 다음 프로세스의 정보를 가지고 온다.

이게 프로세스의 정보를 가져오는 방식이다.

### stealth.dll

이번엔 실제 후킹을 담당하는 라이브러리의 소스코드를 분석한다.

```c
#include "windows.h"
#include "tchar.h"

#define STATUS_SUCCESS						(0x00000000L) 
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
    ULONG NumberOfThreads;
    BYTE Reserved1[48];
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

typedef NTSTATUS (WINAPI *PFZWQUERYSYSTEMINFORMATION)
                 (SYSTEM_INFORMATION_CLASS SystemInformationClass, 
                  PVOID SystemInformation, 
                  ULONG SystemInformationLength, 
                  PULONG ReturnLength);

#define DEF_NTDLL                       ("ntdll.dll")
#define DEF_ZWQUERYSYSTEMINFORMATION    ("ZwQuerySystemInformation")


// global variable (in sharing memory)
#pragma comment(linker, "/SECTION:.SHARE,RWS")
#pragma data_seg(".SHARE")
    TCHAR g_szProcName[MAX_PATH] = {0,};
#pragma data_seg()

// global variable
BYTE g_pOrgBytes[5] = {0,};


BOOL hook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
    FARPROC pfnOrg;
    DWORD dwOldProtect, dwAddress;
    BYTE pBuf[5] = {0xE9, 0, };
    PBYTE pByte;

    // 후킹 대상 API 주소를 구한다
    pfnOrg = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    pByte = (PBYTE)pfnOrg;

    // 만약 이미 후킹 되어 있다면 return FALSE
    if( pByte[0] == 0xE9 )
        return FALSE;

    // 5 byte 패치를 위하여 메모리에 WRITE 속성 추가
    VirtualProtect((LPVOID)pfnOrg, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // 기존 코드 (5 byte) 백업
    memcpy(pOrgBytes, pfnOrg, 5);

    // JMP 주소 계산 (E9 XXXX)
    // => XXXX = pfnNew - pfnOrg - 5
    dwAddress = (DWORD)pfnNew - (DWORD)pfnOrg - 5;
    memcpy(&pBuf[1], &dwAddress, 4);

    // Hook - 5 byte 패치 (JMP XXXX)
    memcpy(pfnOrg, pBuf, 5);

    // 메모리 속성 복원
    VirtualProtect((LPVOID)pfnOrg, 5, dwOldProtect, &dwOldProtect);
    
    return TRUE;
}


BOOL unhook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
    FARPROC pFunc;
    DWORD dwOldProtect;
    PBYTE pByte;

    // API 주소 구한다
    pFunc = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    pByte = (PBYTE)pFunc;

    // 만약 이미 언후킹 되어 있다면 return FALSE
    if( pByte[0] != 0xE9 )
        return FALSE;

    // 원래 코드(5 byte)를 덮어쓰기 위해 메모리에 WRITE 속성 추가
    VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // Unhook
    memcpy(pFunc, pOrgBytes, 5);

    // 메모리 속성 복원
    VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);

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
    
    // 작업 전에 unhook
    unhook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, g_pOrgBytes);

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandleA(DEF_NTDLL), 
                           DEF_ZWQUERYSYSTEMINFORMATION);
    status = ((PFZWQUERYSYSTEMINFORMATION)pFunc)
              (SystemInformationClass, SystemInformation, 
              SystemInformationLength, ReturnLength);

    if( status != STATUS_SUCCESS )
        goto __NTQUERYSYSTEMINFORMATION_END;

    // SystemProcessInformation 인 경우만 작업함
    if( SystemInformationClass == SystemProcessInformation )
    {
        // SYSTEM_PROCESS_INFORMATION 타입 캐스팅
        // pCur 는 single linked list 의 head
        pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

        while(TRUE)
        {
            // 프로세스 이름 비교
            // g_szProcName = 은폐하려는 프로세스 이름
            // (=> SetProcName() 에서 세팅됨)
            if(pCur->Reserved2[1] != NULL)
            {
                if(!_tcsicmp((PWSTR)pCur->Reserved2[1], g_szProcName))
                {
                    // 연결 리스트에서 은폐 프로세스 제거
                    if(pCur->NextEntryOffset == 0)
                        pPrev->NextEntryOffset = 0;
                    else
                        pPrev->NextEntryOffset += pCur->NextEntryOffset;
                }
                else		
                    pPrev = pCur;
            }

            if(pCur->NextEntryOffset == 0)
                break;

            // 연결 리스트의 다음 항목
            pCur = (PSYSTEM_PROCESS_INFORMATION)
                    ((ULONG)pCur + pCur->NextEntryOffset);
        }
    }

__NTQUERYSYSTEMINFORMATION_END:

    // 함수 종료 전에 다시 API Hooking
    hook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, 
                 (PROC)NewZwQuerySystemInformation, g_pOrgBytes);

    return status;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    char            szCurProc[MAX_PATH] = {0,};
    char            *p = NULL;

    // #1. 예외처리
    // 현재 프로세스가 HookProc.exe 라면 후킹하지 않고 종료
    GetModuleFileNameA(NULL, szCurProc, MAX_PATH);
    p = strrchr(szCurProc, '\\');
    if( (p != NULL) && !_stricmp(p+1, "HideProc.exe") )
        return TRUE;

    switch( fdwReason )
    {
        // #2. API Hooking
        case DLL_PROCESS_ATTACH : 
        hook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, 
                     (PROC)NewZwQuerySystemInformation, g_pOrgBytes);
        break;

        // #3. API Unhooking 
        case DLL_PROCESS_DETACH :
        unhook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, 
                       g_pOrgBytes);
        break;
    }

    return TRUE;
}

#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllexport) void SetProcName(LPCTSTR szProcName)
{
    _tcscpy_s(g_szProcName, szProcName);
}
#ifdef __cplusplus
}
#endif
```

음......구조체 선언부터 자세히 봐야 알 것 같다.
그러므로 연휴 끝나고 다시 작성해야겠다.

잠시 끗

-----------------------------------------------------19.03.04

#### SetProcName() & PreProcessor

먼저 Export 함수인 SetProcName() 함수부터 확인한다.

```c
// global variable (in sharing memory)
#pragma comment(linker, "/SECTION:.SHARE,RWS")
#pragma data_seg(".SHARE")
    TCHAR g_szProcName[MAX_PATH] = {0,};
#pragma data_seg()

#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllexport) void SetProcName(LPCTSTR szProcName)
{
    _tcscpy_s(g_szProcName, szProcName);
}
#ifdef __cplusplus
}
#endif
```

먼저 `.SHARE` 라는 이름의 공유 메모리 섹션을 생성한다. 후 하나하나 찾아가며 상세하게 설명을 해본다.

먼저 `pragma comment` 지시자는 msdn에 오브젝트 파일 또는 실행파일에 주석을 배치한다(?) 라고 번역이 되어있다..; 일단 대상 아키텍쳐와 같이 컴파일러 옵션을 지정할 수 있다고 한다.

꽤 많은 기능을 가지고 있는데 대표적으로 몇가지 살펴보면, `ImageBase`의 주소 설정도 가능하다.
`#pragma comment(linker,"/BASE:0x10000000")` 을 써서 컴파일 하면 실제 `ImageBase`가 변경되는 것을 확인할 수 있다. 또한 섹션의 속성변경도 가능한데 `#pragma comment(linker,"/SECTION:.text,EWR")` 을 전처리 구문으로 넣으면 `.text` 영역의 실행,쓰기,읽기 권한이 활성화 되는 것을 볼 수 있다.

위의 전처리구문을 해석하자면 `.SHARE` 섹션을 읽기,쓰기,공유 권한을 활성화 시키는 것으로 이해할 수 있다.(`#pragma comment(linker,"/SECTION:.SHARE,RWS")`)

`#pragma data_seg`는 msdn에 `.obj 파일에 초기화 된 변수가 저장되는 특정 데이터 세그먼트를 지정한다` 라고 되어있다. 네이버든 구글에 검색하면 메모리 공유를 위해 사용되는 것을 알 수 있다.

후킹을 하려는 DLL이 타겟 프로세스에 삽입되어 있을 때 공유섹션을 이용해 데이터를 전달할 수 있다. 해당 `data_seg`가 바로 그 공유섹션을 선언하는 부분이다.

```c
#pragma data_seg(".SHARE")	// 세그먼트 시작 선언, 미지정 시 .data 섹션으로 포함
    TCHAR g_szProcName[MAX_PATH] = {0,};	// 공유 섹션에 저장될 변수를 선언
#pragma data_seg()	// 세그먼트 종료, 해당 공유섹션에서는 g_szProcName 변수만 사용
```

위의 주석대로이다. 즉 해당 섹션의 데이터들을 외부에서도 접근이 가능해지는 것이다.

```c
#ifdef __cplusplus
extern "C" {
#endif
__declspec(dllexport) void SetProcName(LPCTSTR szProcName)
{
    _tcscpy_s(g_szProcName, szProcName);
}
#ifdef __cplusplus
}
#endif
```

전처리구문은 넘어가고... `_tcscpy_s()` 함수를 통해 은폐  프로세스 이름을 `g_szProcName`에 저장한다. 해당 함수는 export 함수로써 `HookProc.exe`에 의해서 호출된다. (dllimport,export에 대해 검색해보면 좋은 정보가 많이있다.)

다음은 dllmain 함수이다.

#### DllMain()

```c
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    char            szCurProc[MAX_PATH] = {0,};
    char            *p = NULL;

    // #1. 예외처리
    // 현재 프로세스가 HookProc.exe 라면 후킹하지 않고 종료
    GetModuleFileNameA(NULL, szCurProc, MAX_PATH);
    p = strrchr(szCurProc, '\\');
    if( (p != NULL) && !_stricmp(p+1, "HideProc.exe") )
        return TRUE;

    switch( fdwReason )
    {
        // #2. API Hooking
        case DLL_PROCESS_ATTACH : 
        hook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, 
                     (PROC)NewZwQuerySystemInformation, g_pOrgBytes);
        break;

        // #3. API Unhooking 
        case DLL_PROCESS_DETACH :
        unhook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, 
                       g_pOrgBytes);
        break;
    }

    return TRUE;
}
```

하나씩 분석해본다.

```c
    char            szCurProc[MAX_PATH] = {0,};
    char            *p = NULL;

    // #1. 예외처리
    // 현재 프로세스가 HookProc.exe 라면 후킹하지 않고 종료
    GetModuleFileNameA(NULL, szCurProc, MAX_PATH);
    p = strrchr(szCurProc, '\\');
    if( (p != NULL) && !_stricmp(p+1, "HideProc.exe") )
        return TRUE;
```

예외처리 구문이라고 되어있다. `GetModuleFileNameA` 함수에 첫번째 인자를 `NULL`을 보냄으로써 현재 프로세스의 절대경로를 가지고 온다. 
`strrchr` 함수를 이용해 `\` 문자를 찾고 마지막 위치에 포인터를 받아 `p` 에 저장한다.(`c:\work\test.exe`의 경우 `\test.exe`를 반환)

그리고 조건문을 통해 `p+1`의 값이 `HideProc.exe`일 경우 후킹을 하지 않도록 예외처리를 만든 것 이다. 해당 위의 함수 사용을 출력하여 확인할 수 있는 소스코드를 만들어봤다.

```c
#include <stdio.h>
#include <Windows.h>

void main()
{
    char szCurProc[MAX_PATH] = {0,};
    char *p = NULL;
    printf("Fully Path length = %p\n",GetModuleFileNameA(NULL, szCurProc, MAX_PATH));
	printf("strrchr() = %s\n",strrchr(szCurProc,'\\'));
	p=strrchr(szCurProc,'\\');
	if( (p != NULL) && !_stricmp(p+1, "getmodule.exe") )
        printf("Current Module Name = %s\n",p+1);
}
```

출력해보면 어떤 원리인지 쉽게 이해할 수 있다.

```c
    switch( fdwReason )
    {
        // #2. API Hooking
        case DLL_PROCESS_ATTACH : 
        hook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, 
                     (PROC)NewZwQuerySystemInformation, g_pOrgBytes);
        break;

        // #3. API Unhooking 
        case DLL_PROCESS_DETACH :
        unhook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, 
                       g_pOrgBytes);
        break;
    }

    return TRUE;
}
```

DLL 인젝션과 마찬가지로 이벤트 케이스를 나누어 `hook_by_code`와 `unhook_by_code` 함수를 호출한다.

#### hook_by_code()

이제 실제 코드패치를 해서 API후킹을 하는 함수를 분석해본다.

```c
BOOL hook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
    FARPROC pfnOrg;
    DWORD dwOldProtect, dwAddress;
    BYTE pBuf[5] = {0xE9, 0, };
    PBYTE pByte;

    // 후킹 대상 API 주소를 구한다
    pfnOrg = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    pByte = (PBYTE)pfnOrg;

    // 만약 이미 후킹 되어 있다면 return FALSE
    if( pByte[0] == 0xE9 )
        return FALSE;

    // 5 byte 패치를 위하여 메모리에 WRITE 속성 추가
    VirtualProtect((LPVOID)pfnOrg, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // 기존 코드 (5 byte) 백업
    memcpy(pOrgBytes, pfnOrg, 5);

    // JMP 주소 계산 (E9 XXXX)
    // => XXXX = pfnNew - pfnOrg - 5
    dwAddress = (DWORD)pfnNew - (DWORD)pfnOrg - 5;
    memcpy(&pBuf[1], &dwAddress, 4);

    // Hook - 5 byte 패치 (JMP XXXX)
    memcpy(pfnOrg, pBuf, 5);

    // 메모리 속성 복원
    VirtualProtect((LPVOID)pfnOrg, 5, dwOldProtect, &dwOldProtect);
    
    return TRUE;
}
```

우선 함수 호출 시 전달되는 파라미터를 확인하면 `hook_by_code(DEF_NTDLL,DEF_ZWQUERYSYSTEMINFORMATION,(PROC)NewZwQuerySystemInformation,g_pOrgBytes)` 로 호출하는 것을 볼 수 있다.
즉 `LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes` 을 순서대로 역할을 보면 후킹 할 API의 라이브러리, 후킹 할 API, 후킹 함수의 주소, 원본 5byte(이해가 안되면 이전 포스팅 확인)라고 볼 수 있다.

 맨 앞에 동작방식에 써놓은 것 처럼 `JMP` 명령을 이용해 후킹 함수를 사용한다. x86 명령에서 `JMP`는 opcode로 0xE9이다. 그리고 뒤에 주소 4byte가 따라오게 된다. 현재 중요한 점은 `E9 XXXXXXXX` 에서 x가 절대 값이 아니라 상대주소라는 점이다. 다음과 같은 공식으로 상대 거리를 구할 수 있다.

`XXXXXXXX = JMP 할 주소 - 현재 명령어 주소 - 명령어 길이(5)` 

예를 들어 0x402000 에 있는 JMP 명령어에서 0x401000으로 점프를 하는 경우 opcode는 다음과 같이 `0x401000 - 0x402000 - 5(jmp 명령 길이)=0xFFFFEFFB` 으로 `E9 FBEFFFFF`이 된다.

후 그래서 증명하기 위해 해당 예제코드를 기반으로 만들어보았다.

```c
#include <stdio.h>
#include <Windows.h>

void test2()
{
	printf("\nCall Success\n");
}

void main()
{
	MEMORY_BASIC_INFORMATION infos;
	FARPROC pfnOrg;
    DWORD dwOldProtect, dwAddress;
    BYTE pBuf[5] = {0xE9, 0, };	// JMP XXXXXXXX
    PBYTE pByte;
	LPCSTR szDllName; LPCSTR szFuncName; PROC pfnNew; PBYTE pOrgBytes[5]={0,};
	szDllName="user32.dll";
	szFuncName="MessageBoxA";
	pfnNew=(PROC)test2;
	printf("test2() Address = %p\n",pfnNew);
	
    // 후킹 대상 API 주소를 구한다
    pfnOrg = (FARPROC)GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    pByte = (PBYTE)pfnOrg;	//MessageBoxA 함수의 (opcode)
	printf("MessageBoxA Address = %p\n",pfnOrg);
	printf("MessageBoxA 5byte opcode = ");
	for(int i=0;i<sizeof(pByte);i++)
	{
		printf("%x",pByte[i]);
	}
	VirtualProtect((LPVOID)pfnOrg, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);	//보호속성 변경
	VirtualQuery((LPVOID)pfnOrg,&infos,sizeof(infos));
	printf("\nProtect Flag = 0x%x",infos.Protect);

	
    memcpy(pOrgBytes, pfnOrg, 5);	// 원본 5byte 백업
	printf("\nbackup = %x\n",*pOrgBytes);
    dwAddress = (DWORD)pfnNew - (DWORD)pfnOrg - 5;	//test2()주소 - MessageBoxA 시작주소 - 5byte
	memcpy(&pBuf[1], &dwAddress, 4); //pBuf[0] = e9, pBuf[1] 부터 new opcode를 삽입
	printf("New OPCode = ");
	for(int i=0;i<sizeof(pBuf);i++)
	{
		if(i==0){ printf("%X ",pBuf[i]);}
		printf("%X",pBuf[i]);
	}
    memcpy(pfnOrg, pBuf, 5);	//MessageBoxA 함수의 5byte를 새로운 Opcode로 변조(JMP test2())
	VirtualProtect((LPVOID)pfnOrg, 5, dwOldProtect, &dwOldProtect);	//보호속성을 복원
	MessageBoxA(0,"hello","Shh0ya",MB_OK);
}
```

확실히 직접 검색해보고 짜보는게 매우 도움이 된다. 음 보호속성을 보기위해 `VirtualQuery`API 함수를 이용했고, `MessageBoxA` 함수를 후킹하여 내가 의도한 함수를 호출하는 방식이다. 컴파일하여 실행하면 `MessageBoxA`는 호출되지 않고 `test2`함수가 호출되는 것을 확인할 수 있다.

#### unhook_by_code()

```c
BOOL unhook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
    FARPROC pFunc;
    DWORD dwOldProtect;
    PBYTE pByte;

    // API 주소 구한다
    pFunc = GetProcAddress(GetModuleHandleA(szDllName), szFuncName);
    pByte = (PBYTE)pFunc;

    // 만약 이미 언후킹 되어 있다면 return FALSE
    if( pByte[0] != 0xE9 )
        return FALSE;

    // 원래 코드(5 byte)를 덮어쓰기 위해 메모리에 WRITE 속성 추가
    VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect);

    // Unhook
    memcpy(pFunc, pOrgBytes, 5);

    // 메모리 속성 복원
    VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect);
    return TRUE;
}
```

`hook_by_code` 함수에 대부분의 api 및 로직을 설명해놔서 쉽게 이해할 수 있다. 핵심은 역시 원본 5byte 코드를 다시 덮어씌워주는데 있다.

#### NewZwQuerySystemInformation()

```c++
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
    
    // 작업 전에 unhook
    unhook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, g_pOrgBytes);

    // original API 호출
    pFunc = GetProcAddress(GetModuleHandleA(DEF_NTDLL), 
                           DEF_ZWQUERYSYSTEMINFORMATION);
    status = ((PFZWQUERYSYSTEMINFORMATION)pFunc)
              (SystemInformationClass, SystemInformation, 
              SystemInformationLength, ReturnLength);

    if( status != STATUS_SUCCESS )
        goto __NTQUERYSYSTEMINFORMATION_END;

    // SystemProcessInformation 인 경우만 작업함
    if( SystemInformationClass == SystemProcessInformation )
    {
        // SYSTEM_PROCESS_INFORMATION 타입 캐스팅
        // pCur 는 single linked list 의 head
        pCur = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;

        while(TRUE)
        {
            // 프로세스 이름 비교
            // g_szProcName = 은폐하려는 프로세스 이름
            // (=> SetProcName() 에서 세팅됨)
            if(pCur->Reserved2[1] != NULL)
            {
                if(!_tcsicmp((PWSTR)pCur->Reserved2[1], g_szProcName))
                {
                    // 연결 리스트에서 은폐 프로세스 제거
                    if(pCur->NextEntryOffset == 0)
                        pPrev->NextEntryOffset = 0;
                    else
                        pPrev->NextEntryOffset += pCur->NextEntryOffset;
                }
                else		
                    pPrev = pCur;
            }

            if(pCur->NextEntryOffset == 0)
                break;

            // 연결 리스트의 다음 항목
            pCur = (PSYSTEM_PROCESS_INFORMATION)
                    ((ULONG)pCur + pCur->NextEntryOffset);
        }
    }

__NTQUERYSYSTEMINFORMATION_END:

    // 함수 종료 전에 다시 API Hooking
    hook_by_code(DEF_NTDLL, DEF_ZWQUERYSYSTEMINFORMATION, 
                 (PROC)NewZwQuerySystemInformation, g_pOrgBytes);

    return status;
}
```

일단 기본 `ZwQuerySystemInformation` API에 대해 알아봐야 한다. zQuery라고 짧게 줄여 사용하겠다. zQuery의 함수 원형은 다음과 같다.

```c
NTSTATUS WINAPI ZwQuerySystemInformation(
  _In_      SYSTEM_INFORMATION_CLASS SystemInformationClass,
  _Inout_   PVOID                    SystemInformation,
  _In_      ULONG                    SystemInformationLength,
  _Out_opt_ PULONG                   ReturnLength
);
```

요건 정말 많이 찾아봐야했다. 책에서도 이 부분에 대한 설명은 좀 부족하다고 느꼈다.

**`SystemlnformationClass` 파라미터를 `SystemProcessInformation(5)`로 세팅하고, `ZwQuerySystemlnformation` API를 호출하면, `SysternInformation`파라미터에 `SYSTEM_PROCESS_INFORMATION`  단방향 연결 리스트(single linked list)의 시작 주소가 저장, 바로 이 구조체 연결 리스트에 실행 중인 모든 프로세스의 정보가 담겨 있다.**

라고 책에는 나와있다. 뭐 그런가보다 하고 넘어갈 수 있지만 좀 어려웠다. 찾아보면서 어느정도 이해는 되었으나 대부분 블로그에 딱 저정도만 있는 것을 볼 수 있다. `NTSTATUS` 부터 `SYSTEM_INFO` 구조체까지 모두 찾아보는게 좋다. 참고로 `SYSTEM_INFO` 구조체는 `WinBase.h` 문서안에 정의되어있다.

 그 외에는 주석처리를 살펴보면서 보면 된다. 휠 내리는 속도를 3초 정도 마다 내려주면 좋닼

끗 

# [+] Reference

1. ***리버싱 핵심 원리***









