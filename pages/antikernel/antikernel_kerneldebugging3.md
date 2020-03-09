---
title: Kernel Debugging (3)
keywords: documentation, technique, debugging
date: 2020-03-09
tags: [Windows, Reversing, Dev]
summary: "커널 디버깅의 원리 (3)"
sidebar: antikernel_sidebar
permalink: antikernel_kerneldebugging3.html
folder: antikernel
---

## [0x00] Overview

이번 챕터에서는 본격적인 커널 디버깅 방지 우회에 들어가기 앞서, 커널 디버깅 중에 시스템에서 어떠한 변화가 있는지 살펴볼 것입니다. 매우 중요한 내용입니다. 커널 디버깅 시 시스템에서의 변화를 많이 알면 알수록 우회할 수 있는 포인트나 커널 디버깅을 방지할 수 있는 기법 개발이 가능합니다.

몇 가지 커널 디버깅 관련 함수와 전역변수들에 대해 알아 볼 것입니다. 



## [0x01] KdTrap

`KdEnableDebugger` 함수에서 `KdpDebugRoutineSelect` 변수의 참조를 통해 찾은 함수입니다. 
`ntoskrnl.exe`를 IDA의 Hexray 기능을 이용해 해당 함수를 확인하면 다음과 같습니다.

```c
char __fastcall KdTrap(char a1, __int64 a2, __int64 a3, __int64 a4)
{
  char result; // al

  if ( KdpDebugRoutineSelect )
    result = KdpTrap(a1, a2, a3);
  else
    result = KdpStub(a1, a2, a3, a4);
  return result;
}
```

매우 간략합니다. `KdpDebugRoutineSelect` 변수의 값이 존재하면 `KdpTrap` 을 호출하고 아닌 경우, `KdpStub` 함수를 호출합니다. 

- **KdpDebugRoutineSelect**

  어떤 디버그 루틴을 호출할지 결정하는 변수입니다. 전에는 `KiDebugRoutine` 이라는 변수였던 것으로 보입니다. 이전에는 디버깅 엔진이 활성화 되면 `KdpTrap` 함수의 주소를 가지고 있고, 비활성화 시에는 `KdpStub` 함수의 주소를 갖고 있었습니다. 현재는 `BOOLEAN` 형으로 디버그 루틴이 존재하는가에 대한 참, 거짓을 나타내는 것으로 보입니다.



### [-] KdpSymbol in KdpTrap

`KdpTrap` 내부로 진입하여 확인하면 `KdpSymbol` 함수가 존재하는 것을 볼 수 있습니다. 해당 함수는 아래와 같습니다.

```c
void __fastcall KdpSymbol(__int64 a1, __int64 a2, char a3, char a4, __int64 a5, __int64 a6)
{
  char v6; // r14
  __int64 v7; // r15
  __int64 v8; // r12
  char v9; // al
  struct _KPRCB *v10; // rdi
  char v11; // bp
  __int64 v12; // r8
  __int64 v13; // rax

  if ( !a4 )
  {
    v6 = a3;
    v7 = a2;
    v8 = a1;
    if ( !(_BYTE)KdDebuggerNotPresent )
    {
      v9 = KdEnterDebugger(a6);	// Enter Debugger
      v10 = KeGetCurrentPrcb();
      v11 = v9;
      KiSaveProcessorControlState(&v10->ProcessorState);
      KdpCopyContext(v10->Context, *(unsigned int *)(a5 + 48), a5);
      LOBYTE(v12) = v6;
      KdpReportLoadSymbolsStateChange(v8, v7, v12, v10->Context);
      KdpCopyContext(a5, v10->Context->ContextFlags, v10->Context);
      v13 = KiRestoreProcessorControlState(&v10->ProcessorState);
      KdExitDebugger(v13, v11);
    }
  }
}
```

`KdEnterDebugger` 함수를 호출하는 것을 볼 수 있습니다. 또한 `KdExitDebugger` 함수도 같이 존재합니다. `KdDebuggerNotPresent` 가 FALSE 인 경우, 즉 디버그 모드가 활성화 되어있는 경우 동작합니다.



### [-] KdEnterDebugger

```c
char __fastcall KdEnterDebugger(__int64 a1)
{
  __int64 v1; // rdi
  int v2; // ebx
  unsigned __int8 v3; // bp
  char v4; // r14
  struct _KPRCB *prcb; // rsi
  __int64 v6; // rdi
  _XSAVE_AREA_HEADER *v7; // rcx
  unsigned int *v8; // rdx
  unsigned __int64 *v9; // rcx
  unsigned __int64 v10; // rax
  char result; // al

  v1 = a1;
  v2 = 0;
  if ( (unsigned int)VfIsVerifierEnabled() )
    VfNotifyVerifierOfEvent(3i64);
  if ( v1 )
  {
    KdTimerStop = __rdtsc();
    KdTimerDifference = KdTimerStop - KdTimerStart;
  }
  else
  {
    KdTimerStop = 0i64;
  }
  v3 = KeGetCurrentIrql();
  v4 = KeFreezeExecution();
  off_1403FFC98();
  prcb = KeGetCurrentPrcb();
  v6 = prcb->Number;
  v7 = prcb->ExtendedSupervisorState;
  qword_1404DCBE0 = ~KdIgnoredSavingSupervisorXStateFeatures & (MEMORY[0xFFFFF780000005F0] | 0x100i64);
  KeSaveSupervisorState(v7);
  if ( !(KiBugCheckActive & 3) || (unsigned int)KiBugCheckActive >> 4 != (_DWORD)v6 )
    prcb->DebuggerSavedIRQL = v3;
  v8 = (unsigned int *)KdLogBuffer[v6];
  if ( v8 )
  {
    v9 = (unsigned __int64 *)&v8[4 * (*v8 + 1i64)];
    v10 = __rdtsc();
    *v9 = ((unsigned __int64)HIDWORD(v10) << 32) | (unsigned int)v10;
    v9[1] = 4 * ((unsigned __int8)KdDebuggerNotPresent & 1) | 1u;
  }
  ++KdDebuggerEnteredCount;
  result = v4;
  LOBYTE(v2) = KdPortLocked == 0;
  KdDebuggerEnteredWithoutLock += v2;
  KdEnteredDebugger = 1;
  return result;
}
```

마지막 부분만 눈여겨 보겠습니다. `KdEnteredDebugger` 라는 변수에 1을 저장하는 것을 볼 수 있습니다. 즉 디버깅 중이냐를 판단하는 것으로도 볼 수 있습니다.



## [0x02] Conclusion

여기까지 커널 디버깅과 관련된 몇 가지 함수를 살펴봤습니다. 내용에서 정리되지 않은 변수들이 몇 가지 있지만, 다음 내용에서 디버그 모드 활성화와 비활성화 시 전역변수에 값을 비교한 내용을 보면 도움이 될 것 같습니다.



