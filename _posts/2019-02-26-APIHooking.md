---
layout: article
title: "[Rev]API Hooking(debug)"
key: 20190226
tags:
  - Reversing
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] Windows Hooking(2)

<!--more-->

## [+] API Hooking(Debug)

메모장을 가지고 메모장에서 사용하는 `WriteFile` 함수를 이용해 파일에 쓴다. 이 때 이 API를 후킹하여 원하는 데이터로 변조하거나 아예 함수를 호출하지 않도록하는 등의 행위를 해볼 것 이다.  먼저 디버거를 이용한 후킹이다.

## [+] Hookdbg.exe

### main()

예제로 사용하는 hookdbg.exe 에 대한 소스코드 분석을 통해 흐름을 파악해본다.

```c
/* main */
int main(int argc, char* argv[])
{
    DWORD dwPID;
    if( argc != 2 )
    {
        printf("\nUSAGE : hookdbg.exe <pid>\n");
        return 1;
    }
    // Attach Process
    dwPID = atoi(argv[1]);
    if( !DebugActiveProcess(dwPID) )
    {
        printf("DebugActiveProcess(%d) failed!!!\n"
               "Error Code = %d\n", dwPID, GetLastError());
        return 1;
    }
    // 디버거 루프
    DebugLoop();

    return 0;
}
```

메인함수를 보면 명령어가 제대로 입력 됐는지 검증하고 프로세스에 `DebugActiveProcess` 함수를 이용하여(`CreateProcess`의 플래그를 이용하여 디버깅도 가능) 해당 프로세스에 어태치 한다. 그 다음 `DebugLoop()`를 호출한다.

### DebugLoop()

```c
void DebugLoop()
{
    DEBUG_EVENT de;
    DWORD dwContinueStatus;

    // Debuggee 로부터 event 가 발생할 때까지 기다림
    while( WaitForDebugEvent(&de, INFINITE) )
    {
        dwContinueStatus = DBG_CONTINUE;

        // Debuggee 프로세스 생성 혹은 attach 이벤트
        if( CREATE_PROCESS_DEBUG_EVENT == de.dwDebugEventCode )
        {
            OnCreateProcessDebugEvent(&de);
        }
        // 예외 이벤트
        else if( EXCEPTION_DEBUG_EVENT == de.dwDebugEventCode )
        {
            if( OnExceptionDebugEvent(&de) )
                continue;
        }
        // Debuggee 프로세스 종료 이벤트
        else if( EXIT_PROCESS_DEBUG_EVENT == de.dwDebugEventCode )
        {
            // debuggee 종료 -> debugger 종료
            break;
        }
        // Debuggee 의 실행을 재개시킴
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, dwContinueStatus);
    }
}
```

주석의 내용이 끝이다 `WaitForDebugEvent` 에서 이벤트 발생을 기다리고 `ContinueDebugEvent`에서 디버기 실행을 재개한다.

### OnCreateProcessDebugEvent()

```c
/* OnCreateProcessDebugEvent () */
BOOL OnCreateProcessDebugEvent(LPDEBUG_EVENT pde)
{
    // WriteFile() API 주소 구하기
    g_pfWriteFile = GetProcAddress(GetModuleHandleA("kernel32.dll"), "WriteFile");

    // API Hook - WriteFile()
    //   첫 번째 byte 를 0xCC (INT 3) 으로 변경 
    //   (orginal byte 는 백업)
    memcpy(&g_cpdi, &pde->u.CreateProcessInfo, sizeof(CREATE_PROCESS_DEBUG_INFO));
    ReadProcessMemory(g_cpdi.hProcess, g_pfWriteFile, 
                      &g_chOrgByte, sizeof(BYTE), NULL);
    WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, 
                       &g_chINT3, sizeof(BYTE), NULL);

    return TRUE;
}
```

먼저 로드되어 있는 라이브러리에서 `WriteFile`함수의 주소를 구한다.
강조되는 점인데 Windows에서 시스템 라이브러리는 모든 프로세스에서 동일한 주소에 올라간다.

```c
/* Global Variable */
LPVOID g_pfWriteFile = NULL;
CREATE_PROCESS_DEBUG_INFO g_cpdi;
BYTE g_chINT3 = 0xCC, g_chOrgByte = 0;
```

전역변수에 있는 `g_cpdi` 는 `CREATE_PROCESS_DEBUG_INFO` 구조체의 변수이다. 해당 구조체는 다음과 같은 멤버를 가지고 있으며 이 중에 `hProcess` 멤버를 이용해 후킹이 가능하다. 

```c
typedef struct _CREATE_PROCESS_DEBUG_INFO {
  HANDLE                 hFile;
  HANDLE                 hProcess;
  HANDLE                 hThread;
  LPVOID                 lpBaseOfImage;
  DWORD                  dwDebugInfoFileOffset;
  DWORD                  nDebugInfoSize;
  LPVOID                 lpThreadLocalBase;
  LPTHREAD_START_ROUTINE lpStartAddress;
  LPVOID                 lpImageName;
  WORD                   fUnicode;
} CREATE_PROCESS_DEBUG_INFO, *LPCREATE_PROCESS_DEBUG_INFO;
```

이후 나오는 `ReadProcessMemory`와 `WriteProcessMemory`를 이용해 자유롭게 읽고 쓰는 작업을 할 수 있다.(디버그 권한을 가지고 있기 때문)

`ReadProcessMemory`함수를 보면 unhook 과정에서 필요한 `WriteFile`의 시작 첫 바이트를 읽어서 `g_chOrgByte` 변수에 저장한다.

그리고 `WriteProcessMemory` 함수를 통해 첫 바이트 값을 0xCC(int 3, bp)로 변조한다. 이제 CPU는 해당 명령어를 만나 프로그램을 멈추고 예외를 발생시킨다.

### OnExceptionDebugEvent()

```c
BOOL OnExceptionDebugEvent(LPDEBUG_EVENT pde)
{
    CONTEXT ctx;
    PBYTE lpBuffer = NULL;
    DWORD dwNumOfBytesToWrite, dwAddrOfBuffer, i;
    PEXCEPTION_RECORD per = &pde->u.Exception.ExceptionRecord;

    // BreakPoint exception (INT 3) 인 경우
    if( EXCEPTION_BREAKPOINT == per->ExceptionCode )
    {
        // BP 주소가 WriteFile() 인 경우
        if( g_pfWriteFile == per->ExceptionAddress )
        {
            //코드 실행
        }
    }
    return FALSE;
}
```

첫 if문에서 예외코드가 브레이크 포인트 예외인지 확인한다. 그리고 예외가 발생한 주소가 `WriteFile` 함수의 시작 주소와 같은지(OnCreateProcessDebugEvent()에서 구해놓음) 확인한다. 이 조건이 맞으면 코드가 실행된다.

 ```c
// #1. Unhook
            //   0xCC 로 덮어쓴 부분을 original byte 로 되돌림
            WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, 
                               &g_chOrgByte, sizeof(BYTE), NULL);

            // #2. Thread Context 구하기
            ctx.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(g_cpdi.hThread, &ctx);

            // #3. WriteFile() 의 param 2, 3 값 구하기
            //   함수의 파라미터는 해당 프로세스의 스택에 존재함
            //   param 2 : ESP + 0x8
            //   param 3 : ESP + 0xC
            ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0x8), 
                              &dwAddrOfBuffer, sizeof(DWORD), NULL);
            ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0xC), 
                              &dwNumOfBytesToWrite, sizeof(DWORD), NULL);

            // #4. 임시 버퍼 할당
            lpBuffer = (PBYTE)malloc(dwNumOfBytesToWrite+1);
            memset(lpBuffer, 0, dwNumOfBytesToWrite+1);

            // #5. WriteFile() 의 버퍼를 임시 버퍼에 복사
            ReadProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer, 
                              lpBuffer, dwNumOfBytesToWrite, NULL);
            printf("\n### original string ###\n%s\n", lpBuffer);

            // #6. 소문자 -> 대문자 변환
            for( i = 0; i < dwNumOfBytesToWrite; i++ )
            {
                if( 0x61 <= lpBuffer[i] && lpBuffer[i] <= 0x7A )
                    lpBuffer[i] -= 0x20;
            }

            printf("\n### converted string ###\n%s\n", lpBuffer);

            // #7. 변환된 버퍼를 WriteFile() 버퍼로 복사
            WriteProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer, 
                               lpBuffer, dwNumOfBytesToWrite, NULL);
            
            // #8. 임시 버퍼 해제
            free(lpBuffer);

            // #9. Thread Context 의 EIP 를 WriteFile() 시작으로 변경
            //   (현재는 WriteFile() + 1 만큼 지나왔음)
            ctx.Eip = (DWORD)g_pfWriteFile;
            SetThreadContext(g_cpdi.hThread, &ctx);

            // #10. Debuggee 프로세스를 진행시킴
            ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
            Sleep(0);

            // #11. API Hook
            WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, 
                               &g_chINT3, sizeof(BYTE), NULL);

            return TRUE;
 ```

코드 실행 부분이다. 초기에 언훅을 하는 이유는 이후에 `WriteFile` 함수를 똑같이 사용하여 문자열 패치 등을 하기 때문에 정상적으로 호출해야 하기 때문이다.

책에서 사용한 방법은 위에서 저장해둔 `g_chOrgByte` 변수에 담긴 `WriteFile` 함수의 첫 바이트를 다시 원래대로 돌려놓는 것이다.

그리고 Thread Context를 구한다. 이 때 `ctx`변수는 `CONTEXT` 구조체의 변수인데 CPU의 레지스터 정보를 구하는 구조체가 `CONTEXT` 구조체이다.

 ```c
GetThreadContext(g_cpdi.hThread, &ctx);
 ```

`g_cpdi`(디버기의 메인 스레드 핸들) 스레드의 Context를 저장한다. 

```c
            ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0x8), 
                              &dwAddrOfBuffer, sizeof(DWORD), NULL);
            ReadProcessMemory(g_cpdi.hProcess, (LPVOID)(ctx.Esp + 0xC), 
                              &dwNumOfBytesToWrite, sizeof(DWORD), NULL);
```

이제 구해야 할 것은 `WriteFile`을 호출하며 넘어온 값 중 버퍼의 주소와 버퍼의 크기를 알아내야 한다. 함수를 호출하기전 `PUSH` 명령을 이용해 파라미터를 넣는 것을 생각하면 2,3 번째 파라미터(`LPCVOID lpBuffer`,`DWORD nNumberOfBytesToWrite`)는 `ESP` 레지스터 기준으로 +8, +C 만큼에 위치하게 된다.

그러기 때문에 thread context를 이용해 해당 레지스터에서 값을 가져온다.

```c
            // #4. 임시 버퍼 할당
            lpBuffer = (PBYTE)malloc(dwNumOfBytesToWrite+1);
            memset(lpBuffer, 0, dwNumOfBytesToWrite+1);

            // #5. WriteFile() 의 버퍼를 임시 버퍼에 복사
            ReadProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer, 
                              lpBuffer, dwNumOfBytesToWrite, NULL);
            printf("\n### original string ###\n%s\n", lpBuffer);

            // #6. 소문자 -> 대문자 변환
            for( i = 0; i < dwNumOfBytesToWrite; i++ )
            {
                if( 0x61 <= lpBuffer[i] && lpBuffer[i] <= 0x7A )
                    lpBuffer[i] -= 0x20;
            }
            printf("\n### converted string ###\n%s\n", lpBuffer);

            // #7. 변환된 버퍼를 WriteFile() 버퍼로 복사
            WriteProcessMemory(g_cpdi.hProcess, (LPVOID)dwAddrOfBuffer, 
                               lpBuffer, dwNumOfBytesToWrite, NULL);
            
            // #8. 임시 버퍼 해제
            free(lpBuffer);
```

그 다음은 임시버퍼를 할당하고, 위에서 알아낸 `WriteFile`의 버퍼를 복사한다. 그리고 원래 버퍼를 대문자로 변환해주는 작업을 진행하고 임시 버퍼를 해제 하여 준다.

```c
            ctx.Eip = (DWORD)g_pfWriteFile;
            SetThreadContext(g_cpdi.hThread, &ctx);
```

`0xCC` 명령으로 인해 증가한 EIP를 `WriteFile`의 시작 위치로 다시 변경한다.

```c
            ContinueDebugEvent(pde->dwProcessId, pde->dwThreadId, DBG_CONTINUE);
            Sleep(0);	// Memory Access Error 방지
```

그리고 다시 디버거 프로세스를 실행시킨다. 바로 위에서 eip도 `WriteFile` 함수의 시작위치로 돌렸기 때문에 정상적으로 동작할 것이다.

```c
            WriteProcessMemory(g_cpdi.hProcess, g_pfWriteFile, 
                               &g_chINT3, sizeof(BYTE), NULL);
```

마지막 요건 다음에 후킹을 위해 hook을 설치하는 것이다. unhook 과정이 있었기 때문에 필요하다.

실제 해당 소스코드를 이용해 메모장을 후킹하고 파일을 저장하면 소문자가 대문자로 바뀌어 저장된다

간단하지만 원리는 복잡하다

1. 후킹할 프로세스를 디버기 상태로 만듬
2. 후킹할 함수의 주소 확인
3. unhook을 위해 첫 바이트 백업 후 0xcc로 변조
4. 이벤트 발생 대기 로직 구현(예외처리)
5. 이벤트 발생 시 로직 구현, 후킹할 함수의 첫 바이트가 0xcc인 경우 원하는 로직을 구현, CONTEXT 구조체 이용.
6. unhook을 해서 해당 함수를 정상적으로 사용한 경우 다시 hook을 설치

# [+] Reference

1. ***리버싱 핵심 원리***

