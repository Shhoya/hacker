---
layout: article
title: "[Rev]API Hooking(Global Hooking_ex)"
key: 20190307
tags:
  - Reversing
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] Windows Hooking(6)

<!--more-->

Process Hacker2로 API 관련하여 찾다가 요런게 있었다.

프로세스를 선택하여 Modules를 확인하면 메모리에 올라온 모듈들의 Base Address가 존재한다. 그리고 그 모듈을 선택해서 Import, Export를 확인하면 메모리에 올라온 API의 VA주소가 존재한다. 
이 때 `Base Address + VA(.text Section) + VA(API) - 0x400` 하면 API의 시작 주소를 알 수 있다.. 인데 모르겠다 내가 그냥 계산했을 때 이렇게 하니깐 나왔다. - 0x400은 헤더의 크기만큼을 빼는 것 같기도하고... 우연히 찾은건데 뭔가 이유가 있겠지.

음 어쨋든 이번에는 IE(Internet Explorer)를 후킹하여 어디를 접속하든 내가 원하는 방향으로 접속하게끔 만들어 보도록 하겠다. 책에 내용에서 조금씩 변형해서 한다.

## [+] Global API Hooking

API 후킹에서 가장 중요한건 역시 대상 API를 선정하는 일이다. 네트워크 관련 API, 인터넷 관련 API, 프로세스 관련 API 등등 많은 API가 있으며 이전 포스팅에서 말한대로 Low Level의 API 일수록 좋다.

이번엔 인터넷 접속에 대한 API를 후킹하므로 `InternetConnect` API함수를 후킹한다. 인터넷 관련된 라이브러리는 `wininet.dll`, `winhttp.dll` 등이 존재하며 이는 직접 디버깅해서 어떤 API를 통해 인터넷에 접속하는지 찾아봐야한다.

실제 URL을 입력하여 인터넷에 접속하면 `InternetConnectW` 함수를 이용하여 접속하는 것을 확인할 수 있다.

내부적으로 더 Low Level의 API를 찾기위해 한번 함수를 쭉 들여봤다. 들여보니 `InternetConnectW` 함수는 `IdnToAscii` 함수를 걸쳐 `InternetConnectA` 함수를 호출하는 것을 확인했다. 아마 `W(Unicode)` 관련 함수는 다 이런식으로 호출하지 않을까 싶다. 더 내부적으로는 너무 많아서 여기까지만 일단 확인했다.

자 여기서 한가지.. IE에 Attach를 할 때 확인해보면 부모 프로세스가 아닌 자식 프로세스에게 Attach하여 확인했을꺼다. 최근에는 브라우저가 탭이라는 개념이 생기며 독립적인 프로세스로 돌아가게 되었다. 장점도 있지만 당연히 시스템 리소스에 대한 단점도 존재한다. 어쨋든 이 때 마찬가지로 `CreateProcess`가 호출된다. 

마찬가지로 `CreateProcess`와 `InternetConnectW` API를 후킹하면 원하는 방향으로 흐름을 바꿀 수 있다. 그러나 이번엔 이전 포스팅에서 말했던 Low Level의 API인 `ZwResumeThread` API를 후킹하여 좀 더 글로벌틱한 후킹을 해본다.

`CreateProcess` 함수를 좀 더 깊이 살펴본다. step into를 통해 함수 내부로 진입하면 내부적으로 `CreateProcessInternal` 함수를 호출한다.  마찬가지로 해당 함수로 진입하여 마우스 휠을 마구 내리다보면 `ZwCreateUserProcess` 를 만나게 된다.

이 함수가 호출되면 프로세스가 Suspend 상태로 생성되게 된다. 뭔가 삘이온다. 이 후 내부적으로 어떠한 로직을 걸치고 `ZwResumeThread` 함수를 통해 Suspend 상태가 풀리고 실행이 된다! 

간략한 호출 흐름을 정리하면,

1. CreateProcess 호출
2. CreateProcessInternal 호출
3. ZwCreateUserProcess 호출 // 프로세스 Suspend 상태로 생성
4. ZwResumeThread 호출 // 자식 프로세스의 메인 스레드 실행으로 프로세스 실행

## [+] Analysis

### Redirect.dll

```c
// redirect.cpp

#include "windows.h"
#include "wininet.h"
#include "stdio.h"
#include "tchar.h"

#define STR_MODULE_NAME					    (L"redirect.dll")
#define STATUS_SUCCESS						(0x00000000L) 

typedef LONG NTSTATUS;

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;

typedef struct _THREAD_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PVOID TebBaseAddress;
	CLIENT_ID ClientId;
	ULONG AffinityMask;
	LONG Priority;
	LONG BasePriority;
} THREAD_BASIC_INFORMATION;

typedef NTSTATUS (WINAPI *PFZWRESUMETHREAD)
(
    HANDLE ThreadHandle, 
    PULONG SuspendCount
);

typedef NTSTATUS (WINAPI *PFZWQUERYINFORMATIONTHREAD)
(
    HANDLE ThreadHandle, 
    ULONG ThreadInformationClass, 
    PVOID ThreadInformation, 
    ULONG ThreadInformationLength, 
    PULONG ReturnLength
);

typedef HINTERNET (WINAPI *PFINTERNETCONNECTW)
(
    HINTERNET hInternet,
    LPCWSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPCTSTR lpszUsername,
    LPCTSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext
);

BYTE g_pZWRT[5] = {0,};
BYTE g_pICW[5] = {0,};

void DebugLog(const char *format, ...)
{
	va_list vl;
	FILE *pf = NULL;
	char szLog[512] = {0,};

	va_start(vl, format);
	wsprintfA(szLog, format, vl);
	va_end(vl);

    OutputDebugStringA(szLog);
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
        DebugLog("OpenProcessToken error: %u\n", GetLastError());
        return FALSE;
    }

    if( !LookupPrivilegeValue(NULL,             // lookup privilege on local system
                              lpszPrivilege,    // privilege to lookup 
                              &luid) )          // receives LUID of privilege
    {
        DebugLog("LookupPrivilegeValue error: %u\n", GetLastError() ); 
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
        DebugLog("AdjustTokenPrivileges error: %u\n", GetLastError() ); 
        return FALSE; 
    } 

    if( GetLastError() == ERROR_NOT_ALL_ASSIGNED )
    {
        DebugLog("The token does not have the specified privilege. \n");
        return FALSE;
    } 

    return TRUE;
}

BOOL hook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PROC pfnNew, PBYTE pOrgBytes)
{
	FARPROC pFunc = NULL;
	DWORD dwOldProtect = 0, dwAddress = 0;
	BYTE pBuf[5] = {0xE9, 0, };
	PBYTE pByte = NULL;
    HMODULE hMod = NULL;

    hMod = GetModuleHandleA(szDllName);
    if( hMod == NULL )
    {
        DebugLog("hook_by_code() : GetModuleHandle(\"%s\") failed!!! [%d]\n",
                  szDllName, GetLastError());
        return FALSE;
    }

	pFunc = (FARPROC)GetProcAddress(hMod, szFuncName);
    if( pFunc == NULL )
    {
        DebugLog("hook_by_code() : GetProcAddress(\"%s\") failed!!! [%d]\n",
                  szFuncName, GetLastError());
        return FALSE;
    }

	pByte = (PBYTE)pFunc;
	if( pByte[0] == 0xE9 )
    {
        DebugLog("hook_by_code() : The API is hooked already!!!\n");
		return FALSE;
    }

	if( !VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect) )
    {
        DebugLog("hook_by_code() : VirtualProtect(#1) failed!!! [%d]\n", GetLastError());
        return FALSE;
    }

	memcpy(pOrgBytes, pFunc, 5);

	dwAddress = (DWORD)pfnNew - (DWORD)pFunc - 5;
	memcpy(&pBuf[1], &dwAddress, 4);

	memcpy(pFunc, pBuf, 5);

	if( !VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect) )
    {
        DebugLog("hook_by_code() : VirtualProtect(#2) failed!!! [%d]\n", GetLastError());
        return FALSE;
    }

	return TRUE;
}

BOOL unhook_by_code(LPCSTR szDllName, LPCSTR szFuncName, PBYTE pOrgBytes)
{
	FARPROC pFunc = NULL;
	DWORD dwOldProtect = 0;
	PBYTE pByte = NULL;
    HMODULE hMod = NULL;

    hMod = GetModuleHandleA(szDllName);
    if( hMod == NULL )
    {
        DebugLog("unhook_by_code() : GetModuleHandle(\"%s\") failed!!! [%d]\n",
                  szDllName, GetLastError());
        return FALSE;
    }

	pFunc = (FARPROC)GetProcAddress(hMod, szFuncName);
    if( pFunc == NULL )
    {
        DebugLog("unhook_by_code() : GetProcAddress(\"%s\") failed!!! [%d]\n",
                  szFuncName, GetLastError());
        return FALSE;
    }

	pByte = (PBYTE)pFunc;
	if( pByte[0] != 0xE9 )
    {
        DebugLog("unhook_by_code() : The API is unhooked already!!!");
        return FALSE;
    }

	if( !VirtualProtect((LPVOID)pFunc, 5, PAGE_EXECUTE_READWRITE, &dwOldProtect) )
    {
        DebugLog("unhook_by_code() : VirtualProtect(#1) failed!!! [%d]\n", GetLastError());
        return FALSE;
    }

	memcpy(pFunc, pOrgBytes, 5);

	if( !VirtualProtect((LPVOID)pFunc, 5, dwOldProtect, &dwOldProtect) )
    {
        DebugLog("unhook_by_code() : VirtualProtect(#2) failed!!! [%d]\n", GetLastError());
        return FALSE;
    }

	return TRUE;
}

BOOL IsVistaLater()
{
    OSVERSIONINFO osvi;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    GetVersionEx(&osvi);

    if( osvi.dwMajorVersion >= 6 )
        return TRUE;

    return FALSE;
}

typedef DWORD (WINAPI *PFNTCREATETHREADEX)
( 
    PHANDLE                 ThreadHandle,	
    ACCESS_MASK             DesiredAccess,	
    LPVOID                  ObjectAttributes,	
    HANDLE                  ProcessHandle,	
    LPTHREAD_START_ROUTINE  lpStartAddress,	
    LPVOID                  lpParameter,	
    BOOL	                CreateSuspended,	
    DWORD                   dwStackSize,	
    DWORD                   dw1, 
    DWORD                   dw2, 
    LPVOID                  Unknown 
); 

BOOL MyCreateRemoteThread(HANDLE hProcess, LPTHREAD_START_ROUTINE pThreadProc, LPVOID pRemoteBuf)
{
    HANDLE      hThread = NULL;
    FARPROC     pFunc = NULL;

    if( IsVistaLater() )    // Vista, 7, Server2008
    {
        pFunc = GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtCreateThreadEx");
        if( pFunc == NULL )
        {
            DebugLog("MyCreateRemoteThread() : GetProcAddress() failed!!! [%d]\n",
                   GetLastError());
            return FALSE;
        }

        ((PFNTCREATETHREADEX)pFunc)(&hThread,
                                    0x1FFFFF,
                                    NULL,
                                    hProcess,
                                    pThreadProc,
                                    pRemoteBuf,
                                    FALSE,
                                    NULL,
                                    NULL,
                                    NULL,
                                    NULL);
        if( hThread == NULL )
        {
            DebugLog("MyCreateRemoteThread() : NtCreateThreadEx() failed!!! [%d]\n", GetLastError());
            return FALSE;
        }
    }
    else                    // 2000, XP, Server2003
    {
        hThread = CreateRemoteThread(hProcess, NULL, 0, 
                                     pThreadProc, pRemoteBuf, 0, NULL);
        if( hThread == NULL )
        {
            DebugLog("MyCreateRemoteThread() : CreateRemoteThread() failed!!! [%d]\n", GetLastError());
            return FALSE;
        }
    }

	if( WAIT_FAILED == WaitForSingleObject(hThread, INFINITE) )
    {
        DebugLog("MyCreateRemoteThread() : WaitForSingleObject() failed!!! [%d]\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL InjectDll(DWORD dwPID, LPCTSTR szDllPath)
{
	HANDLE                  hProcess = NULL;
    HANDLE                  hThread = NULL;
	LPVOID                  pRemoteBuf = NULL;
    DWORD                   dwBufSize = (DWORD)(_tcslen(szDllPath) + 1) * sizeof(TCHAR);
	LPTHREAD_START_ROUTINE  pThreadProc = NULL;
    BOOL                    bRet = FALSE;
    HMODULE                 hMod = NULL;

	if ( !(hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPID)) )
    {
        DebugLog("InjectDll() : OpenProcess(%d) failed!!! [%d]\n", dwPID, GetLastError());
		goto INJECTDLL_EXIT;
    }

	pRemoteBuf = VirtualAllocEx(hProcess, NULL, dwBufSize, 
                                MEM_COMMIT, PAGE_READWRITE);
    if( pRemoteBuf == NULL )
    {
        DebugLog("InjectDll() : VirtualAllocEx() failed!!! [%d]\n", GetLastError());
        goto INJECTDLL_EXIT;
    }

	if( !WriteProcessMemory(hProcess, pRemoteBuf, 
                           (LPVOID)szDllPath, dwBufSize, NULL) )
    {
        DebugLog("InjectDll() : WriteProcessMemory() failed!!! [%d]\n", GetLastError());
        goto INJECTDLL_EXIT;
    }

    hMod = GetModuleHandle(L"kernel32.dll");
    if( hMod == NULL )
    {
        DebugLog("InjectDll() : GetModuleHandle() failed!!! [%d]\n", GetLastError());
        goto INJECTDLL_EXIT;
    }

	pThreadProc = (LPTHREAD_START_ROUTINE)GetProcAddress(hMod, "LoadLibraryW");
    if( pThreadProc == NULL )
    {
        DebugLog("InjectDll() : GetProcAddress() failed!!! [%d]\n", GetLastError());
        goto INJECTDLL_EXIT;
    }

    if( !MyCreateRemoteThread(hProcess, pThreadProc, pRemoteBuf) )
    {
        DebugLog("InjectDll() : MyCreateRemoteThread() failed!!!\n");
        goto INJECTDLL_EXIT;
    }

    bRet = TRUE;

INJECTDLL_EXIT:

    if( pRemoteBuf )
        VirtualFreeEx(hProcess, pRemoteBuf, 0, MEM_RELEASE);

    if( hThread )
	    CloseHandle(hThread);

    if( hProcess )
	    CloseHandle(hProcess);

	return bRet;
}



NTSTATUS WINAPI NewZwResumeThread(HANDLE ThreadHandle, PULONG SuspendCount)
{
    NTSTATUS status, statusThread;
    FARPROC pFunc = NULL, pFuncThread = NULL;
    DWORD dwPID = 0;
	static DWORD dwPrevPID = 0;
    THREAD_BASIC_INFORMATION tbi;
    HMODULE hMod = NULL;
    TCHAR szModPath[MAX_PATH] = {0,};

    DebugLog("NewZwResumeThread() : start!!!\n");

    hMod = GetModuleHandle(L"ntdll.dll");
    if( hMod == NULL )
    {
        DebugLog("NewZwResumeThread() : GetModuleHandle() failed!!! [%d]\n",
                  GetLastError());
        return NULL;
    }

    // call ntdll!ZwQueryInformationThread()
    pFuncThread = GetProcAddress(hMod, "ZwQueryInformationThread");
    if( pFuncThread == NULL )
    {
        DebugLog("NewZwResumeThread() : GetProcAddress() failed!!! [%d]\n",
                  GetLastError());
        return NULL;
    }

    statusThread = ((PFZWQUERYINFORMATIONTHREAD)pFuncThread)
                   (ThreadHandle, 0, &tbi, sizeof(tbi), NULL);
    if( statusThread != STATUS_SUCCESS )
    {
        DebugLog("NewZwResumeThread() : pFuncThread() failed!!! [%d]\n", 
                 GetLastError());
        return NULL;
    }

    dwPID = (DWORD)tbi.ClientId.UniqueProcess;
    if ( (dwPID != GetCurrentProcessId()) && (dwPID != dwPrevPID) )
    {
        DebugLog("NewZwResumeThread() => call InjectDll()\n");

        dwPrevPID = dwPID;

        // change privilege
       	if( !SetPrivilege(SE_DEBUG_NAME, TRUE) )
            DebugLog("NewZwResumeThread() : SetPrivilege() failed!!!\n");

        // get injection dll path
        GetModuleFileName(GetModuleHandle(STR_MODULE_NAME), 
                          szModPath, 
                          MAX_PATH);

        if( !InjectDll(dwPID, szModPath) )
            DebugLog("NewZwResumeThread() : InjectDll(%d) failed!!!\n", dwPID);
    }

    // call ntdll!ZwResumeThread()
    if( !unhook_by_code("ntdll.dll", "ZwResumeThread", g_pZWRT) )
    {
        DebugLog("NewZwResumeThread() : unhook_by_code() failed!!!\n");
        return NULL;
    }

    pFunc = GetProcAddress(hMod, "ZwResumeThread");
    if( pFunc == NULL )
    {
        DebugLog("NewZwResumeThread() : GetProcAddress() failed!!! [%d]\n",
                  GetLastError());
        goto __NTRESUMETHREAD_END;
    }

    status = ((PFZWRESUMETHREAD)pFunc)(ThreadHandle, SuspendCount);
    if( status != STATUS_SUCCESS )
    {
        DebugLog("NewZwResumeThread() : pFunc() failed!!! [%d]\n", GetLastError());
        goto __NTRESUMETHREAD_END;
    }

__NTRESUMETHREAD_END:

    if( !hook_by_code("ntdll.dll", "ZwResumeThread", 
                      (PROC)NewZwResumeThread, g_pZWRT) )
    {
        DebugLog("NewZwResumeThread() : hook_by_code() failed!!!\n");
    }

    DebugLog("NewZwResumeThread() : end!!!\n");

    return status;
}




HINTERNET WINAPI NewInternetConnectW
(
    HINTERNET hInternet,
    LPCWSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPCTSTR lpszUsername,
    LPCTSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext
)
{
    HINTERNET hInt = NULL;
    FARPROC pFunc = NULL;
    HMODULE hMod = NULL;

    // unhook
    if( !unhook_by_code("wininet.dll", "InternetConnectW", g_pICW) )
    {
        DebugLog("NewInternetConnectW() : unhook_by_code() failed!!!\n");
        return NULL;
    }

    // call original API
    hMod = GetModuleHandle(L"wininet.dll");
    if( hMod == NULL )
    {
        DebugLog("NewInternetConnectW() : GetModuleHandle() failed!!! [%d]\n",
                  GetLastError());
        goto __INTERNETCONNECT_EXIT;
    }

    pFunc = GetProcAddress(hMod, "InternetConnectW");
    if( pFunc == NULL )
    {
        DebugLog("NewInternetConnectW() : GetProcAddress() failed!!! [%d]\n",
                  GetLastError());
        goto __INTERNETCONNECT_EXIT;
    }

    if( !_tcsicmp(lpszServerName, L"www.naver.com") ||
        !_tcsicmp(lpszServerName, L"www.daum.net") ||
        !_tcsicmp(lpszServerName, L"www.nate.com") || 
        !_tcsicmp(lpszServerName, L"www.yahoo.com") )
    {
        DebugLog("[redirect] naver, daum, nate, yahoo => reversecore\n");
        hInt = ((PFINTERNETCONNECTW)pFunc)(hInternet,
                                           L"www.reversecore.com",
                                           nServerPort,
                                           lpszUsername,
                                           lpszPassword,
                                           dwService,
                                           dwFlags,
                                           dwContext);
    }
    else
    {
        DebugLog("[no redirect]\n");
        hInt = ((PFINTERNETCONNECTW)pFunc)(hInternet,
                                           lpszServerName,
                                           nServerPort,
                                           lpszUsername,
                                           lpszPassword,
                                           dwService,
                                           dwFlags,
                                           dwContext);
    }

__INTERNETCONNECT_EXIT:

    // hook
    if( !hook_by_code("wininet.dll", "InternetConnectW", 
                      (PROC)NewInternetConnectW, g_pICW) )
    {
        DebugLog("NewInternetConnectW() : hook_by_code() failed!!!\n");
    }
    
    return hInt;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    char            szCurProc[MAX_PATH] = {0,};
    char            *p = NULL;

    switch( fdwReason )
    {
        case DLL_PROCESS_ATTACH : 
            DebugLog("DllMain() : DLL_PROCESS_ATTACH\n");

            GetModuleFileNameA(NULL, szCurProc, MAX_PATH);
            p = strrchr(szCurProc, '\\');
            if( (p != NULL) && !_stricmp(p+1, "iexplore.exe") )
            {
                DebugLog("DllMain() : current process is [iexplore.exe]\n");

                // wininet!InternetConnectW() API 를 후킹하기 전에 
                // 미리 wininet.dll 을 로딩시킴
                if( NULL == LoadLibrary(L"wininet.dll") )
                {
                    DebugLog("DllMain() : LoadLibrary() failed!!! [%d]\n",
                             GetLastError());
                }
            }

            // hook
            hook_by_code("ntdll.dll", "ZwResumeThread", 
                         (PROC)NewZwResumeThread, g_pZWRT);
            hook_by_code("wininet.dll", "InternetConnectW", 
                         (PROC)NewInternetConnectW, g_pICW);
            break;

        case DLL_PROCESS_DETACH :
            DebugLog("DllMain() : DLL_PROCESS_DETACH\n");

            // unhook
            unhook_by_code("ntdll.dll", "ZwResumeThread", 
                           g_pZWRT);
            unhook_by_code("wininet.dll", "InternetConnectW", 
                           g_pICW);
            break;
    }

    return TRUE;
}
```

마찬가지로 해당 예제 코드를 분석한다.

#### DllMain()

```c
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    char            szCurProc[MAX_PATH] = {0,};
    char            *p = NULL;

    switch( fdwReason )
    {
        case DLL_PROCESS_ATTACH : 
            DebugLog("DllMain() : DLL_PROCESS_ATTACH\n");

            GetModuleFileNameA(NULL, szCurProc, MAX_PATH);
            p = strrchr(szCurProc, '\\');
            if( (p != NULL) && !_stricmp(p+1, "iexplore.exe") )
            {
                DebugLog("DllMain() : current process is [iexplore.exe]\n");

                // wininet!InternetConnectW() API 를 후킹하기 전에 
                // 미리 wininet.dll 을 로딩시킴
                if( NULL == LoadLibrary(L"wininet.dll") )
                {
                    DebugLog("DllMain() : LoadLibrary() failed!!! [%d]\n",
                             GetLastError());
                }
            }

            // hook
            hook_by_code("ntdll.dll", "ZwResumeThread", 
                         (PROC)NewZwResumeThread, g_pZWRT);
            hook_by_code("wininet.dll", "InternetConnectW", 
                         (PROC)NewInternetConnectW, g_pICW);
            break;

        case DLL_PROCESS_DETACH :
            DebugLog("DllMain() : DLL_PROCESS_DETACH\n");

            // unhook
            unhook_by_code("ntdll.dll", "ZwResumeThread", 
                           g_pZWRT);
            unhook_by_code("wininet.dll", "InternetConnectW", 
                           g_pICW);
            break;
    }

    return TRUE;
}
```

특이한 점은 `LoadLibrary` 를 이용해 `wininet.dll`을 로드하는 것이다. 그 이유는 책에 나와있는데 `ZwResumeThread` API는 메인스레드가 시작되기 전에 실행 제어를 가지고 온다. 그렇기 때문에 후킹 대상인 `wininet.dll`이 로드되지 않은 상태일 수 있고 이러한 경우에 당연히 후킹이 실패하기 뙤문이다. 그러기 위해 후킹 대상 API인 `InternetConnectW` 를 후킹하기 전 해당 함수를 Export 시키는 `wininet.dll`을 로드하는 것이다.

#### NewInternetConnectW()

```c
HINTERNET WINAPI NewInternetConnectW
(
    HINTERNET hInternet,
    LPCWSTR lpszServerName,
    INTERNET_PORT nServerPort,
    LPCTSTR lpszUsername,
    LPCTSTR lpszPassword,
    DWORD dwService,
    DWORD dwFlags,
    DWORD_PTR dwContext
)
{
    HINTERNET hInt = NULL;
    FARPROC pFunc = NULL;
    HMODULE hMod = NULL;

    // unhook
    if( !unhook_by_code("wininet.dll", "InternetConnectW", g_pICW) )
    {
        DebugLog("NewInternetConnectW() : unhook_by_code() failed!!!\n");
        return NULL;
    }

    // call original API
    hMod = GetModuleHandle(L"wininet.dll");
    if( hMod == NULL )
    {
        DebugLog("NewInternetConnectW() : GetModuleHandle() failed!!! [%d]\n",
                  GetLastError());
        goto __INTERNETCONNECT_EXIT;
    }

    pFunc = GetProcAddress(hMod, "InternetConnectW");
    if( pFunc == NULL )
    {
        DebugLog("NewInternetConnectW() : GetProcAddress() failed!!! [%d]\n",
                  GetLastError());
        goto __INTERNETCONNECT_EXIT;
    }

    if( !_tcsicmp(lpszServerName, L"www.naver.com") ||
        !_tcsicmp(lpszServerName, L"www.daum.net") ||
        !_tcsicmp(lpszServerName, L"www.nate.com") || 
        !_tcsicmp(lpszServerName, L"www.yahoo.com") )
    {
        DebugLog("[redirect] naver, daum, nate, yahoo => reversecore\n");
        hInt = ((PFINTERNETCONNECTW)pFunc)(hInternet,
                                           L"www.reversecore.com",
                                           nServerPort,
                                           lpszUsername,
                                           lpszPassword,
                                           dwService,
                                           dwFlags,
                                           dwContext);
    }
    else
    {
        DebugLog("[no redirect]\n");
        hInt = ((PFINTERNETCONNECTW)pFunc)(hInternet,
                                           lpszServerName,
                                           nServerPort,
                                           lpszUsername,
                                           lpszPassword,
                                           dwService,
                                           dwFlags,
                                           dwContext);
    }

__INTERNETCONNECT_EXIT:

    // hook
    if( !hook_by_code("wininet.dll", "InternetConnectW", 
                      (PROC)NewInternetConnectW, g_pICW) )
    {
        DebugLog("NewInternetConnectW() : hook_by_code() failed!!!\n");
    }
    
    return hInt;
}
```

핫패치 방식을 배웠는데 여기선 또 5byte 코드 패치를 이용해 언훅과 훅 과정이 반복된다. 그 이유는 `ZwResumeThread` API 함수를 들여다보면 7byte 패치 할 공간이 존재하지 않기 때문이다.

마찬가지로 언훅 후에 원본 `InternetConnectW` API 주소를 가져와 2번째 인자인 `lpszServerName`을 확인하여 특정 호스트가 넘어온 경우 리다이렉트 시키게 된다.

#### NewZwResumeThread()

```c
NTSTATUS WINAPI NewZwResumeThread(HANDLE ThreadHandle, PULONG SuspendCount)
{
    NTSTATUS status, statusThread;
    FARPROC pFunc = NULL, pFuncThread = NULL;
    DWORD dwPID = 0;
	static DWORD dwPrevPID = 0;
    THREAD_BASIC_INFORMATION tbi;
    HMODULE hMod = NULL;
    TCHAR szModPath[MAX_PATH] = {0,};

    DebugLog("NewZwResumeThread() : start!!!\n");

    hMod = GetModuleHandle(L"ntdll.dll");
    if( hMod == NULL )
    {
        DebugLog("NewZwResumeThread() : GetModuleHandle() failed!!! [%d]\n",
                  GetLastError());
        return NULL;
    }

    // call ntdll!ZwQueryInformationThread()
    pFuncThread = GetProcAddress(hMod, "ZwQueryInformationThread");
    if( pFuncThread == NULL )
    {
        DebugLog("NewZwResumeThread() : GetProcAddress() failed!!! [%d]\n",
                  GetLastError());
        return NULL;
    }

    statusThread = ((PFZWQUERYINFORMATIONTHREAD)pFuncThread)
                   (ThreadHandle, 0, &tbi, sizeof(tbi), NULL);
    if( statusThread != STATUS_SUCCESS )
    {
        DebugLog("NewZwResumeThread() : pFuncThread() failed!!! [%d]\n", 
                 GetLastError());
        return NULL;
    }

    dwPID = (DWORD)tbi.ClientId.UniqueProcess;
    if ( (dwPID != GetCurrentProcessId()) && (dwPID != dwPrevPID) )
    {
        DebugLog("NewZwResumeThread() => call InjectDll()\n");

        dwPrevPID = dwPID;

        // change privilege
       	if( !SetPrivilege(SE_DEBUG_NAME, TRUE) )
            DebugLog("NewZwResumeThread() : SetPrivilege() failed!!!\n");

        // get injection dll path
        GetModuleFileName(GetModuleHandle(STR_MODULE_NAME), 
                          szModPath, 
                          MAX_PATH);

        if( !InjectDll(dwPID, szModPath) )
            DebugLog("NewZwResumeThread() : InjectDll(%d) failed!!!\n", dwPID);
    }

    // call ntdll!ZwResumeThread()
    if( !unhook_by_code("ntdll.dll", "ZwResumeThread", g_pZWRT) )
    {
        DebugLog("NewZwResumeThread() : unhook_by_code() failed!!!\n");
        return NULL;
    }

    pFunc = GetProcAddress(hMod, "ZwResumeThread");
    if( pFunc == NULL )
    {
        DebugLog("NewZwResumeThread() : GetProcAddress() failed!!! [%d]\n",
                  GetLastError());
        goto __NTRESUMETHREAD_END;
    }

    status = ((PFZWRESUMETHREAD)pFunc)(ThreadHandle, SuspendCount);
    if( status != STATUS_SUCCESS )
    {
        DebugLog("NewZwResumeThread() : pFunc() failed!!! [%d]\n", GetLastError());
        goto __NTRESUMETHREAD_END;
    }

__NTRESUMETHREAD_END:

    if( !hook_by_code("ntdll.dll", "ZwResumeThread", 
                      (PROC)NewZwResumeThread, g_pZWRT) )
    {
        DebugLog("NewZwResumeThread() : hook_by_code() failed!!!\n");
    }

    DebugLog("NewZwResumeThread() : end!!!\n");

    return status;
}
```

```c
    // call ntdll!ZwQueryInformationThread()
    pFuncThread = GetProcAddress(hMod, "ZwQueryInformationThread");
    if( pFuncThread == NULL )
    {
        DebugLog("NewZwResumeThread() : GetProcAddress() failed!!! [%d]\n",
                  GetLastError());
        return NULL;
    }

    statusThread = ((PFZWQUERYINFORMATIONTHREAD)pFuncThread)
                   (ThreadHandle, 0, &tbi, sizeof(tbi), NULL);
    if( statusThread != STATUS_SUCCESS )
    {
        DebugLog("NewZwResumeThread() : pFuncThread() failed!!! [%d]\n", 
                 GetLastError());
        return NULL;
    }

    dwPID = (DWORD)tbi.ClientId.UniqueProcess;
    if ( (dwPID != GetCurrentProcessId()) && (dwPID != dwPrevPID) )
    {
        DebugLog("NewZwResumeThread() => call InjectDll()\n");

        dwPrevPID = dwPID;

        // change privilege
       	if( !SetPrivilege(SE_DEBUG_NAME, TRUE) )
            DebugLog("NewZwResumeThread() : SetPrivilege() failed!!!\n");

        // get injection dll path
        GetModuleFileName(GetModuleHandle(STR_MODULE_NAME), 
                          szModPath, 
                          MAX_PATH);

        if( !InjectDll(dwPID, szModPath) )
            DebugLog("NewZwResumeThread() : InjectDll(%d) failed!!!\n", dwPID);
    }
```

코드를 보면 처음에 `ZwQueryInformationThread`를 호출하는 것을 볼 수 있다. 그 이유는 새로 생성되는 프로세스의 메인 스레드가 소속되있는 프로세스의 PID를 가져오기 위함이다.

가져온 PID(`dwPID`)를 가지고 조건문을 통해 후킹 DLL을 인젝트한다.

```c
    // call ntdll!ZwResumeThread()
    if( !unhook_by_code("ntdll.dll", "ZwResumeThread", g_pZWRT) )
    {
        DebugLog("NewZwResumeThread() : unhook_by_code() failed!!!\n");
        return NULL;
    }

    pFunc = GetProcAddress(hMod, "ZwResumeThread");
    if( pFunc == NULL )
    {
        DebugLog("NewZwResumeThread() : GetProcAddress() failed!!! [%d]\n",
                  GetLastError());
        goto __NTRESUMETHREAD_END;
    }

    status = ((PFZWRESUMETHREAD)pFunc)(ThreadHandle, SuspendCount);
    if( status != STATUS_SUCCESS )
    {
        DebugLog("NewZwResumeThread() : pFunc() failed!!! [%d]\n", GetLastError());
        goto __NTRESUMETHREAD_END;
    }

__NTRESUMETHREAD_END:

    if( !hook_by_code("ntdll.dll", "ZwResumeThread", 
                      (PROC)NewZwResumeThread, g_pZWRT) )
    {
        DebugLog("NewZwResumeThread() : hook_by_code() failed!!!\n");
    }

    DebugLog("NewZwResumeThread() : end!!!\n");

    return status;
}
```

이 다음은 그대로 특이점이 없으므로 넘어간드아ㅏㅏ

정말 헷갈릴 수 있다. 나도 헷갈려서 한시간동안 머릿속으로 정리를 쭈욱했다.

`NewZwResumeThread` 부분이 헷갈릴 수 있는데 나중에 내가 이걸 다시 봤을때 다시 떠올리면 좋겠다.

후킹의 동작원리를 떠올려랏...

끗

# [+] Reference

1. ***리버싱 핵심 원리***