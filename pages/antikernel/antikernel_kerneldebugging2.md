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



## [0x01] KdEnableDebuggerWIthLock

`KdEnableDebugger` 함수가 호출되면, 실제 로직이 존재하는 함수입니다. 이름에서 알 수 있듯이 Disable 함수도 존재하며 디버거를 활성화/비활성화 하는 함수입니다.

`ntoskrnl.exe`를 IDA의 Hexray 기능을 이용해 해당 함수를 확인하면 다음과 같습니다.

```c
signed __int64 __fastcall KdEnableDebuggerWithLock(char a1)
{
  unsigned __int8 v1; // di
  char v2; // bl
  int v4; // eax

  v1 = 0;
  v2 = a1;
  if ( KdPitchDebugger )
    return 0xC0000354i64;	//STATUS_DEBUGGER_INACTIVE
  if ( KdBlockEnable )
    return 0xC0000022i64;	//STATUS_ACCESS_DENIED
  if ( a1 )
  {
    v1 = KeGetCurrentIrql();
    __writecr8(2ui64);
    KxAcquireSpinLock(&KdDebuggerLock);
  }
  v4 = KdDisableCount;
  if ( KdDisableCount )
  {
    --KdDisableCount;
    if ( v4 == 1 && KdPreviouslyEnabled )
    {
      if ( v2 )
      {
        KdPowerTransitionEx(1i64);
        KdpDebugRoutineSelect = 1;
        LOBYTE(KdDebuggerEnabled) = 1;
        MEMORY[0xFFFFF780000002D4] = 1;
        KdpRestoreAllBreakpoints();
      }
      else
      {
        PoHiberInProgress = 1;
        KdInitSystem(0, 0i64);
        KdpRestoreAllBreakpoints();
        PoHiberInProgress = 0;
      }
    }
    if ( v2 )
    {
      KxReleaseSpinLock(&KdDebuggerLock);
      __writecr8(v1);
    }
  }
  else
  {
    if ( v2 )
    {
      KxReleaseSpinLock(&KdDebuggerLock);
      __writecr8(v1);
      return 0xC000000Di64;
    }
    KdInitSystem(0, 0i64);
  }
  return 0i64;
}
```

첫 번째 파라미터는 `Lock`의 사용여부를 판단하는 파라미터 입니다.

먼저 해당 함수에 진입하면 두 가지 전역변수를 이용해 활성화가 가능한지를 판단합니다.

```c
  if ( KdPitchDebugger )
    return 0xC0000354i64;	//STATUS_DEBUGGER_INACTIVE
  if ( KdBlockEnable )
    return 0xC0000022i64;	//STATUS_ACCESS_DENIED
```

`KdInitSystem`에서도 볼 수 있는 변수들입니다. 이 두 변수에 대한 간략한 설명을 하고 넘어가겠습니다.

- KdPitchDebugger

  `KdInitSystem` 함수에서 부팅 옵션에 따라 값이 설정됩니다. `/NODEBUG` 옵션의 경우 TRUE로 설정되고, 이 때 `KdEnableDebugger` 함수를 호출하면 디버그 모드가 아니므로 디버거 비활성화 오류 메시지를 반환합니다.

- KdBlockEnable

  마찬가지로 디버깅이 허용되어 있는지에 대한 확인을 하는 변수입니다. `KdChangeOption` 또는 `NtSystemDebugControl` 함수에 의해 설정이 가능하며, 이 값이 TRUE 인 경우 디버깅이 차단되어 있음을 의미하므로 접근 거부 오류를 반환하게 됩니다.





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



