---
title: Kernel Debugging (2)
keywords: documentation, technique, debugging
tags: [Windows, Reversing, Dev]
summary: "커널 디버깅의 원리 (2)"
sidebar: antikernel_sidebar
permalink: antikernel_kerneldebugging2.html
folder: antikernel
---

## [0x00] Overview

이번 챕터에서는 본격적인 커널 디버깅 방지 우회에 들어가기 앞서, 커널 디버깅 중에 시스템에서 어떠한 변화가 있는지 살펴볼 것입니다. 매우 중요한 내용입니다. 커널 디버깅 시 시스템에서의 변화를 많이 알면 알수록 우회할 수 있는 포인트나 커널 디버깅을 방지할 수 있는 기법 개발이 가능합니다.

몇 가지 커널 디버깅 관련 함수와 전역변수들에 대해 알아 볼 것입니다. 



## [0x01] KdInitSystem

`ntoskrnl.exe`를 IDA의 Hexray 기능을 이용해 해당 함수를 확인하면 다음과 같습니다. 함수가 매우 길기 때문에 처음과 끝 부분은 생략했습니다. 직접 확인해보길 바랍니다.

```c
char __fastcall KdInitSystem(int a1, __int64 a2)
{
  __int64 v2; // rsi
  char v3; // r13
  char v4; // r12
  char v5; // r15
  __int64 v6; // rcx
  struct _KPRCB *v7; // rcx
  char *v8; // rbp
  char v9; // di
  char *v10; // rax
  __int64 v11; // rdi
  unsigned int v13; // eax
  const char *v14; // r14
  char *v15; // rdx
  char v16; // al
  signed __int64 v17; // rcx
  const char *i; // rcx
  char v19; // al
  const char *v20; // r14
  signed __int64 v21; // rdx
  int v22; // eax
  unsigned int v23; // er15
  __int64 *j; // rdi
  char *v25; // r9
  signed __int64 v26; // r8
  __int64 v27; // rdx
  char v28; // al
  unsigned int v29; // edi
  PVOID v30; // rax
  PVOID v31; // rsi
  int v32; // [rsp+0h] [rbp-178h]
  STRING DestinationString; // [rsp+20h] [rbp-158h]
  char SourceString[256]; // [rsp+30h] [rbp-148h]

  v2 = a2;
  v3 = 0;
  v4 = 0;
// ...
// ...
// ...
    
  if ( v2 )
  {
    v7 = *(struct _KPRCB **)(*(_QWORD *)(v2 + 16) + 48i64);
    off_1403967F8 = &KdpLoaderDebuggerBlock;
    KdpLoaderDebuggerBlock = v2 + 16;
    v8 = *(char **)(v2 + 216);
    *(_QWORD *)&xmmword_140399DA0 = v7;
    if ( !v8 )
    {
      KdPitchDebugger = 1;
      v9 = 0;
      KdPageDebuggerSection = 1;
      goto LABEL_19;
    }
    strupr(v8);
    LODWORD(KdPrintBufferAllocateSize) = 0;
    v9 = 0;
    v10 = strstr(v8, "DBGPRINT_LOG_SIZE=");
    if ( v10 )
    {
      v13 = ((unsigned __int64)atol(v10 + 18) + 4095) & 0xFFFFF000;
      LODWORD(KdPrintBufferAllocateSize) = v13;
      if ( v13 > 0x1000000 )
      {
        LODWORD(KdPrintBufferAllocateSize) = 0x1000000;
        v13 = 0x1000000;
      }
      if ( v13 <= 0x1000 )
        LODWORD(KdPrintBufferAllocateSize) = 0;
    }
    if ( strstr(v8, "CRASHDEBUG") )
    {
      KdPitchDebugger = 0;
      KdpBootedNodebug = 0;
    }
    else if ( strstr(v8, "NODEBUG") )
    {
      KdPitchDebugger = 1;
      KdPageDebuggerSection = 1;
      KdpBootedNodebug = 1;
    }
    else if ( strstr(v8, "DEBUGPORT=LOCAL") )
    {
      KdPitchDebugger = 1;
      v5 = 1;
      KdPageDebuggerSection = 1;
      LOBYTE(KdDebuggerNotPresent) = 1;
      KdLocalDebugEnabled = 1;
      KdpBootedNodebug = 0;
    }
    else
    {
      v14 = v8;
      do
      {
        v15 = strstr(v14, " DEBUG=");
        if ( !v15 )
        {
          v15 = strstr(v14, " DEBUG");
          if ( !v15 )
            break;
        }
        v14 = v15 + 6;
        v16 = v15[6];
        if ( (unsigned __int8)v16 <= 0x3Du )
        {
          v17 = 2305843013508661249i64;
          if ( _bittest64(&v17, v16) )
          {
            v9 = 1;
            KdpBootedNodebug = 0;
            if ( v15[6] == 61 )
            {
              for ( i = v15 + 7; ; i = v20 + 1 )
              {
                v19 = *i;
                v20 = i;
                while ( v19 )
                {
                  if ( (unsigned __int8)v19 <= 0x2Cu )
                  {
                    v21 = 17596481012224i64;
                    if ( _bittest64(&v21, v19) )
                      break;
                  }
                  v19 = *++v20;
                }
                v22 = (_DWORD)v20 - (_DWORD)i;
                if ( (_DWORD)v20 == (_DWORD)i )
                  break;
                if ( v22 == 10 )
                {
                  if ( !strncmp(i, "AUTOENABLE", 0xAui64) )
                  {
                    v3 = 1;
                    KdAutoEnableOnEvent = 1;
                    v4 = 0;
                  }
                }
                else if ( v22 == 7 )
                {
                  if ( !strncmp(i, "DISABLE", 7ui64) )
                  {
                    v3 = 1;
                    KdAutoEnableOnEvent = 0;
                    v4 = 1;
                  }
                }
                else if ( v22 == 6 && !strncmp(i, "NOUMEX", 6ui64) )
                {
                  KdIgnoreUmExceptions = 1;
                }
                if ( *v20 != 44 )
                  break;
              }
            }
            break;
          }
        }
      }
      while ( v15 != (char *)-6i64 );
    }
    if ( strstr(v8, "NOEVENT") )
    {
      KdEventLoggingEnabled = 0;
      goto LABEL_19;
    }
    if ( !strstr(v8, "EVENT") )
      goto LABEL_19;
    KdEventLoggingEnabled = 1;
    KdPageDebuggerSection = 0;
  }
  else
  {
    *(_QWORD *)&xmmword_140399DA0 = PsNtosImageBase;
  }
  v9 = 1;
LABEL_19:
  qword_140396538 = xmmword_140399DA0;
  if ( !v5 )
  {
    if ( v2 && *(_DWORD *)(v2 + 12) != 1 )
      v9 = 0;
    if ( !v9 )
    {
      LOBYTE(KdDebuggerNotPresent) = 1;
      goto LABEL_25;
    }
    if ( (signed int)KdInitialize(0i64, v2, &KdpContext) < 0 )
    {
      KdPitchDebugger = 0;
      v9 = 0;
      LOBYTE(KdDebuggerNotPresent) = 1;
      KdLocalDebugEnabled = 1;
    }
    else
    {
      KdpDebugRoutineSelect = 1;
    }
  }
  if ( !KdpDebuggerStructuresInitialized )
  {
    BYTE4(KdpContext) = 0;
    LODWORD(KdpContext) = 20;
    KeInitializeDpc(&KdpTimeSlipDpc, KdpTimeSlipDpcRoutine, 0i64);
    KeInitializeTimerEx(&KdpTimeSlipTimer, 0);
    KdpTimeSlipWorkItem.Parameter = 0i64;
    KdpTimeSlipWorkItem.WorkerRoutine = (void (__fastcall *)(void *))KdpTimeSlipWork;
    KdpTimeSlipWorkItem.List.Flink = 0i64;
    KdpDebuggerStructuresInitialized = 1;
  }
  KdTimerStart = 0i64;
  if ( KdEventLoggingEnabled && KdpBootedNodebug )
  {
    KdPitchDebugger = 1;
    KdEventLoggingPresent = v9;
    LOBYTE(KdDebuggerNotPresent) = 1;
    KdLocalDebugEnabled = 0;
  }
  else
  {
    LOBYTE(KdDebuggerEnabled) = 1;
    MEMORY[0xFFFFF780000002D4] = 1;
    if ( KdLocalDebugEnabled )
      goto LABEL_25;
  }
// ...
// ...
```

이 함수는 레퍼런스를 확인하면 약 10개의 로직에서 호출됩니다. 함수로는 `KdEnabledDebuggerWithLock`, `KdEnterKernelDebugger`, `KiSystemStartup`, `KiSetProcessorSignature`, `KiSetFeatureBits`, `PopHiberCheckResume`, `Phase1InitializationDiscard` 에서 호출하는 걸 알 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/kd_00.png?raw=true">



첫 번째 파라미터는  `Phase1InitializationDiscard` 함수를 제외하고는 모두 0을 전달합니다.
두 번째 파라미터는 `KiSystemStartup` 함수를 제외하고는 모두 0을 전달합니다.

이 중에 `KiSystemStartup` 함수에서 호출 될 때의 로직을 한번 살펴보겠습니다.

`KiSystemStartup` 함수는 운영체제가 부팅 될 때 호출되는 함수 중 하나입니다. 이 때 `KdInitSystem`의 두 번째 파라미터로 `KeLoaderBlock` 를 전달하게 됩니다.

중간에 보면 `DEBUG`, `DEBUGPORT` 등의 어디선가 익숙한 문자열들이 있습니다. 좀 더 자세히 살펴보겠습니다.



### [-] Check boot options

```c
if ( v2 )
    {
      ...
      v10 = *(char **)(v2 + 0xD8);
      *(_QWORD *)&xmmword_140400F18 = v9;
      if ( v10 )
      {
        strupr(v10);
        LODWORD(KdPrintBufferAllocateSize) = 0;
        v11 = 0;
        v12 = strstr(v10, "DBGPRINT_LOG_SIZE=");
        if ( v12 )
        {
          v14 = ((unsigned __int64)atol(v12 + 0x12) + 0xFFF) & 0xFFFFF000;
          LODWORD(KdPrintBufferAllocateSize) = v14;
          if ( v14 > 0x1000000 )
          {
            LODWORD(KdPrintBufferAllocateSize) = 0x1000000;
            v14 = 0x1000000;
          }
          if ( v14 <= 0x1000 )
            LODWORD(KdPrintBufferAllocateSize) = 0;
        }
        if ( strstr(v10, "CRASHDEBUG") )
        {
          KdPitchDebugger = 0;
          KdpBootedNodebug = 0;
        }
        else if ( strstr(v10, "NODEBUG") )
        {
          KdPitchDebugger = 1;
          KdPageDebuggerSection = 1;
          KdpBootedNodebug = 1;
        }
        else if ( strstr(v10, "DEBUGPORT=LOCAL") )
        {
          KdPitchDebugger = 1;
          v6 = 1;
          KdPageDebuggerSection = 1;
          LOBYTE(KdDebuggerNotPresent) = 1;
          KdLocalDebugEnabled = 1;
          KdpBootedNodebug = 0;
        }
   ...
```

`v2`  변수는 두 번째 파라미터를 의미합니다. `KeLoaderBlock` 이 존재하는 경우 위의 로직이 동작하게 됩니다. 이 때 `KeLoaderBlock+0xD8` 위치에서 어떤 값을 읽어오고, 분기에 따라 디버깅과 관련된 전역변수들을 설정하는 것을 볼 수 있습니다. 문자열들로 볼 때 `Debug Mode`와 관련된 옵션의 오프셋으로 확인됩니다.

우선 부팅 옵션을 확인하기 위해 부팅 시 `windbg`를 이용해 확인해보면 아래와 같이 옵션을 확인할 수 있습니다.

```
kd> db poi(poi(KeLoaderBlock)+d8)
fffff803`13173450  20 54 45 53 54 53 49 47-4e 49 4e 47 20 20 4e 4f   TESTSIGNING  NO
fffff803`13173460  45 58 45 43 55 54 45 3d-4f 50 54 49 4e 20 20 44  EXECUTE=OPTIN  D
fffff803`13173470  45 42 55 47 20 20 44 45-42 55 47 50 4f 52 54 3d  EBUG  DEBUGPORT=
fffff803`13173480  43 4f 4d 31 20 20 42 41-55 44 52 41 54 45 3d 31  COM1  BAUDRATE=1
fffff803`13173490  31 35 32 30 30 20 20 44-49 53 41 42 4c 45 5f 49  15200  DISABLE_I
fffff803`131734a0  4e 54 45 47 52 49 54 59-5f 43 48 45 43 4b 53 00  NTEGRITY_CHECKS.
fffff803`131734b0  00 35 17 13 03 f8 ff ff-40 34 17 13 03 f8 ff ff  .5......@4......
fffff803`131734c0  60 f2 24 13 03 f8 ff ff-70 75 17 13 03 f8 ff ff  `.$.....pu......
```

현재 `VirtualKD`를 이용하여 디버깅 모드와 코드 테스팅 모드에 대한 내용이 존재하는 것을 알 수 있습니다.

{% include note.html content="초기 부팅 시에만 확인이 가능합니다. 부팅 후에는 해당 블럭이 초기화 됩니다." %}

위 노트에 적힌대로 부팅 후에는 초기화 됩니다. 정확히는 어딘가에 값을 써넣고 초기화 합니다. 바로 레지스트리 입니다.
`HKLM/SYSTEM/CurrentControlSet/Control` 키의 `SystemStartOptions(REG_SZ)` 값에서 확인할 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/kd_01.png?raw=true">



## [0x02] Conclusion

이번에는 `KdInitSystem` 함수에 대해 알아봤습니다. 로직이 복잡하지만 우선 디버그 모드로 부팅 시, 이 함수에서 부트 옵션을 읽어와 처리한다는 것을 알았습니다.

직접 조사한 전역변수에 대한 내용은 이 챕터 후반부에 정리하겠습니다.



