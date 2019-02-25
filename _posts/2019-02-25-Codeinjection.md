---
layout: article
title: "[Rev]Code Injection"
key: 20190225
tags:
  - Reversing
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] Code Injection

<!--more-->

## [+] DLL Injection vs Code Injection

DLL 인젝션과의 차이점을 먼저 알아본다.
책에 나온 예제코드를 이용한다.

```c
DWORD WINAPI ThreadProc(LPVOID lpParam)
{
    MessageBoxA(NULL,"Shhy0a","Shh0ya.github.io",MB_OK);
    return 0;
}
```

저 `WINAPI ThreadProc` 이란 함수에 대해 먼저 알아본다.
<a href="https://msdn.microsoft.com/en-us/library/windows/desktop/ms686736(v=vs.85).aspx">MSDN</a> <- 클릭해서 확인하면 Callback function 이란 말이 나온다. 

일반 함수 호출과 콜백 함수 호출의 차이점은 제어권이 어디에 있느냐이다. 

```python
input_v=input("INPUT : ")
if input_v == 1:
    menu_1()
```

위의 파이썬 코드를 보면 보통 조건에 의한 함수호출의 모습이다. 특정 값이 입력 되고 그 값이 조건이 맞으면 함수를 호출하는 방식이다.

그런데 콜백 함수의 경우에는 다르다. 내가 필요할 때 사용하는 것이 아니라 **특정 이벤트가 발생 했을 때 호출되는 함수**를 의미한다.

`ThreadProc` 함수는 이러한 콜백 함수인데 `lpParam` 파라미터로 `CreateThread, CreateRemoteThread, CreateRemoteThreadEx` 함수의 `lpParameter` 를 사용하여 스레드 데이터가 전달된다. 그리고 실제 스레드가 생성되면 수행할 코드가 존재한다.

서론은 여기까지고 실제 DLL 인젝션과 코드 인젝션의 차이점은 바로 사실 거의 없다. 오히려 DLL 인젝션은 라이브러리를 통째로 삽입하기 때문에 사용하기 용이하고 코드 인젝션은 코드와 데이터를 같이 삽입해야 하기 때문에 오히려 손이 더 많이 간다.

그러나 사용하는 이유는 불필요한 메모리를 차지하지 않는다는 점과, 흔적을 찾기 어렵다라는 장점이 있기 때문이다. DLL 인젝션은 분명 그 흔적을 찾기가 매우 쉽다. 

책에는 이렇게 나와있다. 규모가 크고 복잡한 일을 수행할 때는 DLL 인젝션, 반대의 경우 코드 인젝션을 사용한다 라고 되어있다..

## [+] Example

### Codeinjection.exe

예제파일로 제공된 코드 인젝터의 소스코드는 다음과 같다.

```c
// CodeInjection.cpp
// reversecore@gmail.com
// http://www.reversecore.com
#include "windows.h"
#include "stdio.h"

typedef struct _THREAD_PARAM 
{
    FARPROC pFunc[2];               // LoadLibraryA(), GetProcAddress()
    char    szBuf[4][128];          // "user32.dll", "MessageBoxA", "www.reversecore.com", "ReverseCore"
} THREAD_PARAM, *PTHREAD_PARAM;

typedef HMODULE (WINAPI *PFLOADLIBRARYA)
(
    LPCSTR lpLibFileName
);

typedef FARPROC (WINAPI *PFGETPROCADDRESS)
(
    HMODULE hModule,
    LPCSTR lpProcName
);

typedef int (WINAPI *PFMESSAGEBOXA)
(
    HWND hWnd,
    LPCSTR lpText,
    LPCSTR lpCaption,
    UINT uType
);

DWORD WINAPI ThreadProc(LPVOID lParam)
{
    PTHREAD_PARAM   pParam      = (PTHREAD_PARAM)lParam;
    HMODULE         hMod        = NULL;
    FARPROC         pFunc       = NULL;

    // LoadLibrary()
    hMod = ((PFLOADLIBRARYA)pParam->pFunc[0])(pParam->szBuf[0]);    // "user32.dll"
    if( !hMod )
        return 1;

    // GetProcAddress()
    pFunc = (FARPROC)((PFGETPROCADDRESS)pParam->pFunc[1])(hMod, pParam->szBuf[1]);  // "MessageBoxA"
    if( !pFunc )
        return 1;

    // MessageBoxA()
    ((PFMESSAGEBOXA)pFunc)(NULL, pParam->szBuf[2], pParam->szBuf[3], MB_OK);

    return 0;
}

BOOL InjectCode(DWORD dwPID)
{
    HMODULE         hMod            = NULL;
    THREAD_PARAM    param           = {0,};
    HANDLE          hProcess        = NULL;
    HANDLE          hThread         = NULL;
    LPVOID          pRemoteBuf[2]   = {0,};
    DWORD           dwSize          = 0;

    hMod = GetModuleHandleA("kernel32.dll");

    // set THREAD_PARAM
    param.pFunc[0] = GetProcAddress(hMod, "LoadLibraryA");
    param.pFunc[1] = GetProcAddress(hMod, "GetProcAddress");
    strcpy_s(param.szBuf[0], "user32.dll");
    strcpy_s(param.szBuf[1], "MessageBoxA");
    strcpy_s(param.szBuf[2], "www.reversecore.com");
    strcpy_s(param.szBuf[3], "ReverseCore");

    // Open Process
    if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS,   // dwDesiredAccess
                                  FALSE,                // bInheritHandle
                                  dwPID)) )             // dwProcessId
    {
        printf("OpenProcess() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    // Allocation for THREAD_PARAM
    dwSize = sizeof(THREAD_PARAM);
    if( !(pRemoteBuf[0] = VirtualAllocEx(hProcess,          // hProcess
                                      NULL,                 // lpAddress
                                      dwSize,               // dwSize
                                      MEM_COMMIT,           // flAllocationType
                                      PAGE_READWRITE)) )    // flProtect
    {
        printf("VirtualAllocEx() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    if( !WriteProcessMemory(hProcess,                       // hProcess
                            pRemoteBuf[0],                  // lpBaseAddress
                            (LPVOID)&param,                 // lpBuffer
                            dwSize,                         // nSize
                            NULL) )                         // [out] lpNumberOfBytesWritten
    {
        printf("WriteProcessMemory() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    // Allocation for ThreadProc()
    dwSize = (DWORD)InjectCode - (DWORD)ThreadProc;
    if( !(pRemoteBuf[1] = VirtualAllocEx(hProcess,          // hProcess
                                      NULL,                 // lpAddress
                                      dwSize,               // dwSize
                                      MEM_COMMIT,           // flAllocationType
                                      PAGE_EXECUTE_READWRITE)) )    // flProtect
    {
        printf("VirtualAllocEx() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    if( !WriteProcessMemory(hProcess,                       // hProcess
                            pRemoteBuf[1],                  // lpBaseAddress
                            (LPVOID)ThreadProc,             // lpBuffer
                            dwSize,                         // nSize
                            NULL) )                         // [out] lpNumberOfBytesWritten
    {
        printf("WriteProcessMemory() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    if( !(hThread = CreateRemoteThread(hProcess,            // hProcess
                                       NULL,                // lpThreadAttributes
                                       0,                   // dwStackSize
                                       (LPTHREAD_START_ROUTINE)pRemoteBuf[1],     // dwStackSize
                                       pRemoteBuf[0],       // lpParameter
                                       0,                   // dwCreationFlags
                                       NULL)) )             // lpThreadId
    {
        printf("CreateRemoteThread() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);	

    CloseHandle(hThread);
    CloseHandle(hProcess);
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

    if( !LookupPrivilegeValue(NULL,           // lookup privilege on local system
                              lpszPrivilege,  // privilege to lookup 
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

int main(int argc, char *argv[])
{
    DWORD dwPID     = 0;
	if( argc != 2 )
	{
	    printf("\n USAGE  : %s <pid>\n", argv[0]);
		return 1;
	}
	// change privilege
	if( !SetPrivilege(SE_DEBUG_NAME, TRUE) )
        return 1;

    // code injection
    dwPID = (DWORD)atol(argv[1]);
    InjectCode(dwPID);
	return 0;
}
```

메인함수부터 쭉 분석해본다.

```c
int main(int argc, char *argv[])
{
    DWORD dwPID     = 0;
	if( argc != 2 )
	{
	    printf("\n USAGE  : %s <pid>\n", argv[0]);
		return 1;
	}
	// change privilege
	if( !SetPrivilege(SE_DEBUG_NAME, TRUE) )
        return 1;

    // code injection
    dwPID = (DWORD)atol(argv[1]);
    InjectCode(dwPID);
	return 0;
}
```

주 기능은 `InjectCode` 함수를 호출하는 것이다. 함수에 전달되는 인자인 `dwPID`는 삽입할 프로세스의 PID를 의미한다. `SetPrivilege` 함수를 통해 프로세스 접근 권한에 대한 검증이 있는 것 같다.

```c
DWORD WINAPI ThreadProc(LPVOID lParam)
{
    PTHREAD_PARAM   pParam      = (PTHREAD_PARAM)lParam;
    HMODULE         hMod        = NULL;
    FARPROC         pFunc       = NULL;
    // LoadLibrary()
    hMod = ((PFLOADLIBRARYA)pParam->pFunc[0])(pParam->szBuf[0]);    // "user32.dll"
    if( !hMod )
        return 1;
    // GetProcAddress()
    pFunc = (FARPROC)((PFGETPROCADDRESS)pParam->pFunc[1])(hMod, pParam->szBuf[1]);  // "MessageBoxA"
    if( !pFunc )
        return 1;
    // MessageBoxA()
    ((PFMESSAGEBOXA)pFunc)(NULL, pParam->szBuf[2], pParam->szBuf[3], MB_OK);
    return 0;
}
```

InjectCode 전에 위에서 설명했던 `ThreadProc` 함수를 확인해 본다.
아...ㅎㅎㅎㅎㅎㅎㅎㅎㅎㅎㅎㅎ; 다행히 책에 쉽게 설명해두었다.

```c
hMod=LoadLibraryA("user32.dll");
pFunc=GetProcAddress(hMod,"MessageBoxA");
pFunc(NULL,"www.reversecore.com","ReverseCore",MB_OK);
```

위와 같다고 볼 수 있다. 

코드 인젝션의 핵심은 독립적인 실행코드를 삽입한다는 것이다. 그러기 위해 코드와 코드에서 참조하는 데이터(문자열 등과 같은..)를 같이 인젝션 해주어야 한다. 또한 코드가 정확히 데이터를 참조할 수 있도록 해줘야 한다. 위에서 말한대로 `ThreadProc()` 함수는 API를 직접 호출하지 않으며 문자열도 직접 정의해서 사용하지 않는다. 

당연한게 프로세스 마다 다른 주소를 갖고 있는데 코드와 데이터를 정적으로 삽입하면 정상적으로 실행되지 않는다.

이러한 조건을 만족하기 위해 `ThreadProc` 함수는 `THREAD_PARAM` 구조체를 이용해 2개의 API 주소와 4개의 문자열 데이터를 받아 사용한다. 2개의 API는 `LoadLibraryA`와 `GetProcAddress` 이다.

실제 디버거로 확인하면 스레드 파라미터인 lpParam을 받아서 사용하는 것을 볼 수 있다. `ThreadProc`함수는 독립적인 실행 코드라고 말할 수 있는 이유가 바로 하드 코딩된 주소를 참조하지 않고 사용하기 때문이다.

```c
BOOL InjectCode(DWORD dwPID)
{
    HMODULE         hMod            = NULL;
    THREAD_PARAM    param           = {0,};
    HANDLE          hProcess        = NULL;
    HANDLE          hThread         = NULL;
    LPVOID          pRemoteBuf[2]   = {0,};
    DWORD           dwSize          = 0;

    hMod = GetModuleHandleA("kernel32.dll");

    // set THREAD_PARAM
    param.pFunc[0] = GetProcAddress(hMod, "LoadLibraryA");
    param.pFunc[1] = GetProcAddress(hMod, "GetProcAddress");
    strcpy_s(param.szBuf[0], "user32.dll");
    strcpy_s(param.szBuf[1], "MessageBoxA");
    strcpy_s(param.szBuf[2], "www.reversecore.com");
    strcpy_s(param.szBuf[3], "ReverseCore");

    // Open Process
    if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS,   // dwDesiredAccess
                                  FALSE,                // bInheritHandle
                                  dwPID)) )             // dwProcessId
    {
        printf("OpenProcess() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    // Allocation for THREAD_PARAM
    dwSize = sizeof(THREAD_PARAM);
    if( !(pRemoteBuf[0] = VirtualAllocEx(hProcess,          // hProcess
                                      NULL,                 // lpAddress
                                      dwSize,               // dwSize
                                      MEM_COMMIT,           // flAllocationType
                                      PAGE_READWRITE)) )    // flProtect
    {
        printf("VirtualAllocEx() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    if( !WriteProcessMemory(hProcess,                       // hProcess
                            pRemoteBuf[0],                  // lpBaseAddress
                            (LPVOID)&param,                 // lpBuffer
                            dwSize,                         // nSize
                            NULL) )                         // [out] lpNumberOfBytesWritten
    {
        printf("WriteProcessMemory() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    // Allocation for ThreadProc()
    dwSize = (DWORD)InjectCode - (DWORD)ThreadProc;
    if( !(pRemoteBuf[1] = VirtualAllocEx(hProcess,          // hProcess
                                      NULL,                 // lpAddress
                                      dwSize,               // dwSize
                                      MEM_COMMIT,           // flAllocationType
                                      PAGE_EXECUTE_READWRITE)) )    // flProtect
    {
        printf("VirtualAllocEx() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    if( !WriteProcessMemory(hProcess,                       // hProcess
                            pRemoteBuf[1],                  // lpBaseAddress
                            (LPVOID)ThreadProc,             // lpBuffer
                            dwSize,                         // nSize
                            NULL) )                         // [out] lpNumberOfBytesWritten
    {
        printf("WriteProcessMemory() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    if( !(hThread = CreateRemoteThread(hProcess,            // hProcess
                                       NULL,                // lpThreadAttributes
                                       0,                   // dwStackSize
                                       (LPTHREAD_START_ROUTINE)pRemoteBuf[1],     // dwStackSize
                                       pRemoteBuf[0],       // lpParameter
                                       0,                   // dwCreationFlags
                                       NULL)) )             // lpThreadId
    {
        printf("CreateRemoteThread() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);	

    CloseHandle(hThread);
    CloseHandle(hProcess);
    return TRUE;
}
```

코드를 보면 `THREAD_PARAM` 구조체의 변수를 각각 `LoadLibraryA`, `GetProcAddress`로 세팅하는 것을 확인할 수 있다. 이렇게 코드와 데이터들을 세팅하고 마지막으로 `CreateRemoteThread` 함수를 이용해 원격 스레드를 생성한다.

### Analysis

실제 디버깅을 하며 어떻게 돌아가는지 분석한다. 책과 똑같이 notepad.exe 에 코드 인젝션을 하면 메시지 박스가 출력될 것이다.

디버거에서 `Running` 상태로 만들고 디버깅 옵션에서 `Event` 탭에 `Break on new thread` 를 체크한다. 이는 새로운 스레드가 생성될 때 해당 스레드 함수의 시작부분에서 멈추게 된다.

`Process Explorer`로 notepad.exe의 pid를 확인한 다음, `Codeinjection.exe <pid>` 로 코드 인젝션을 시도한다.

```sh
00BE0000    55              PUSH    EBP
00BE0001    8BEC            MOV     EBP, ESP
00BE0003    56              PUSH    ESI
00BE0004    8B75 08         MOV     ESI, DWORD PTR SS:[EBP+8]	# lpParam 
00BE0007    8B0E            MOV     ECX, DWORD PTR DS:[ESI]
00BE0009    8D46 08         LEA     EAX, DWORD PTR DS:[ESI+8]	# "user32.dll"
00BE000C    50              PUSH    EAX
00BE000D    FFD1            CALL    ECX	# kernel32.LoadLibraryA
00BE000F    85C0            TEST    EAX, EAX
00BE0011    75 0A           JNZ     SHORT 00BE001D
00BE0013    B8 01000000     MOV     EAX, 1
00BE0018    5E              POP     ESI
00BE0019    5D              POP     EBP
00BE001A    C2 0400         RETN    4
00BE001D    8D96 88000000   LEA     EDX, DWORD PTR DS:[ESI+88]	# "MessageBoxA"
00BE0023    52              PUSH    EDX	
00BE0024    50              PUSH    EAX
00BE0025    8B46 04         MOV     EAX, DWORD PTR DS:[ESI+4]
00BE0028    FFD0            CALL    EAX	# GetProcAddress
00BE002A    85C0            TEST    EAX, EAX
00BE002C  ^ 74 E5           JE      SHORT 00BE0013
00BE002E    6A 00           PUSH    0
00BE0030    8D8E 88010000   LEA     ECX, DWORD PTR DS:[ESI+188]
00BE0036    51              PUSH    ECX
00BE0037    81C6 08010000   ADD     ESI, 108
00BE003D    56              PUSH    ESI
00BE003E    6A 00           PUSH    0
00BE0040    FFD0            CALL    EAX	# MessageBox Call
00BE0042    33C0            XOR     EAX, EAX
00BE0044    5E              POP     ESI
00BE0045    5D              POP     EBP
00BE0046    C2 0400         RETN    4
```

위의 주석과 같이 돌아가는 것을 볼 수 있다. 중요한 `ThreadProc` 함수의 파라미터는 바로 `MOV     ESI, DWORD PTR SS:[EBP+8]` 명령어 이다.

## [+] Assembly Code Injection

음 pwnable 에서 쉘코드를 짜는 것과 같다. 필요한건 `ThreadProc` 함수를 만들면 된다.

아래와 같은 코드를 이용한다.

```c
// CodeInjection2.cpp
// reversecore@gmail.com
// http://www.reversecore.com

#include "windows.h"
#include "stdio.h"

typedef struct _THREAD_PARAM 
{
    FARPROC pFunc[2];               // LoadLibraryA(), GetProcAddress()
} THREAD_PARAM, *PTHREAD_PARAM;

BYTE g_InjectionCode[] = 
{
    0x55, 0x8B, 0xEC, 0x8B, 0x75, 0x08, 0x68, 0x6C, 0x6C, 0x00,
    0x00, 0x68, 0x33, 0x32, 0x2E, 0x64, 0x68, 0x75, 0x73, 0x65,
    0x72, 0x54, 0xFF, 0x16, 0x68, 0x6F, 0x78, 0x41, 0x00, 0x68,
    0x61, 0x67, 0x65, 0x42, 0x68, 0x4D, 0x65, 0x73, 0x73, 0x54,
    0x50, 0xFF, 0x56, 0x04, 0x6A, 0x00, 0xE8, 0x0C, 0x00, 0x00,
    0x00, 0x52, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x43, 0x6F,
    0x72, 0x65, 0x00, 0xE8, 0x14, 0x00, 0x00, 0x00, 0x77, 0x77,
    0x77, 0x2E, 0x72, 0x65, 0x76, 0x65, 0x72, 0x73, 0x65, 0x63,
    0x6F, 0x72, 0x65, 0x2E, 0x63, 0x6F, 0x6D, 0x00, 0x6A, 0x00,
    0xFF, 0xD0, 0x33, 0xC0, 0x8B, 0xE5, 0x5D, 0xC3
};

/*
004010ED    55               PUSH EBP
004010EE    8BEC             MOV EBP,ESP
004010F0    8B75 08          MOV ESI,DWORD PTR SS:[EBP+8]       ; ESI = pParam           
004010F3    68 6C6C0000      PUSH 6C6C                      
004010F8    68 33322E64      PUSH 642E3233
004010FD    68 75736572      PUSH 72657375
00401102    54               PUSH ESP                           ; - "user32.dll"
00401103    FF16             CALL DWORD PTR DS:[ESI]            ; LoadLibraryA("user32.dll")
00401105    68 6F784100      PUSH 41786F
0040110A    68 61676542      PUSH 42656761
0040110F    68 4D657373      PUSH 7373654D
00401114    54               PUSH ESP                           ; - "MessageBoxA"
00401115    50               PUSH EAX                           ; - hMod
00401116    FF56 04          CALL DWORD PTR DS:[ESI+4]          ; GetProcAddress(hMod, "MessageBoxA")
00401119    6A 00            PUSH 0                             ; - MB_OK (0)
0040111B    E8 0C000000      CALL 0040112C
00401120                     <ASCII>                            ; - "ReverseCore", 0
0040112C    E8 14000000      CALL 00401145
00401131                     <ASCII>                            ; - "www.reversecore.com", 0
00401145    6A 00            PUSH 0                             ; - hWnd (0)
00401147    FFD0             CALL EAX                           ; MessageBoxA(0, "www.reversecore.com", "ReverseCore", 0)
00401149    33C0             XOR EAX,EAX                        
0040114B    8BE5             MOV ESP,EBP
0040114D    5D               POP EBP                            
0040114E    C3               RETN
*/

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

    if( !LookupPrivilegeValue(NULL,           // lookup privilege on local system
                              lpszPrivilege,  // privilege to lookup 
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

BOOL InjectCode(DWORD dwPID)
{
    HMODULE         hMod            = NULL;
    THREAD_PARAM    param           = {0,};
    HANDLE          hProcess        = NULL;
    HANDLE          hThread         = NULL;
    LPVOID          pRemoteBuf[2]   = {0,};

    hMod = GetModuleHandleA("kernel32.dll");

    // set THREAD_PARAM
    param.pFunc[0] = GetProcAddress(hMod, "LoadLibraryA");
    param.pFunc[1] = GetProcAddress(hMod, "GetProcAddress");

    // Open Process
    if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS,               // dwDesiredAccess
                                  FALSE,                            // bInheritHandle
                                  dwPID)) )                         // dwProcessId
    {
        printf("OpenProcess() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    // Allocation for THREAD_PARAM
    if( !(pRemoteBuf[0] = VirtualAllocEx(hProcess,                  // hProcess
                                         NULL,                      // lpAddress
                                         sizeof(THREAD_PARAM),      // dwSize
                                         MEM_COMMIT,                // flAllocationType
                                         PAGE_READWRITE)) )         // flProtect
    {
        printf("VirtualAllocEx() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    if( !WriteProcessMemory(hProcess,                               // hProcess
                            pRemoteBuf[0],                          // lpBaseAddress
                            (LPVOID)&param,                         // lpBuffer
                            sizeof(THREAD_PARAM),                   // nSize
                            NULL) )                                 // [out] lpNumberOfBytesWritten
    {
        printf("WriteProcessMemory() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    // Allocation for ThreadProc()
    if( !(pRemoteBuf[1] = VirtualAllocEx(hProcess,                  // hProcess
                                         NULL,                      // lpAddress
                                         sizeof(g_InjectionCode),   // dwSize
                                         MEM_COMMIT,                // flAllocationType
                                         PAGE_EXECUTE_READWRITE)) ) // flProtect
    {
        printf("VirtualAllocEx() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    if( !WriteProcessMemory(hProcess,                               // hProcess
                            pRemoteBuf[1],                          // lpBaseAddress
                            (LPVOID)&g_InjectionCode,               // lpBuffer
                            sizeof(g_InjectionCode),                // nSize
                            NULL) )                                 // [out] lpNumberOfBytesWritten
    {
        printf("WriteProcessMemory() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    if( !(hThread = CreateRemoteThread(hProcess,                    // hProcess
                                       NULL,                        // lpThreadAttributes
                                       0,                           // dwStackSize
                                       (LPTHREAD_START_ROUTINE)pRemoteBuf[1],
                                       pRemoteBuf[0],               // lpParameter
                                       0,                           // dwCreationFlags
                                       NULL)) )                     // lpThreadId
    {
        printf("CreateRemoteThread() fail : err_code = %d\n", GetLastError());
        return FALSE;
    }

    WaitForSingleObject(hThread, INFINITE);	

    CloseHandle(hThread);
    CloseHandle(hProcess);

    return TRUE;
}

int main(int argc, char *argv[])
{
    DWORD dwPID     = 0;

	if( argc != 2 )
	{
	    printf("\n USAGE  : %s <pid>\n", argv[0]);
		return 1;
	}

	// change privilege
	if( !SetPrivilege(SE_DEBUG_NAME, TRUE) )
        return 1;

    // code injection
    dwPID = (DWORD)atol(argv[1]);
    InjectCode(dwPID);

	return 0;
}
```

다른 점은 인젝션하는 코드에 필요한 데이터를 포함시키느냐 포함시키지 않느냐가 다르다. 확인해보면 문자열 데이터가 인젝션하는 코드 내에 포함되어 `THREAD_PARAM` 구조체에 문자열이 존재하지 않는 것을 확인할 수 있다.

# [+] Reference

1. ***리버싱 핵심 원리***

