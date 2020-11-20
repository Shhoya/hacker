---
title: PatchGuard Initialize
keywords: documentation, technique, reversing, kernel, windows
date: 2020-11-10
tags: [Windows, Reversing, Vulnerability, Kernel]
summary: "Windows PG Initialize"
sidebar: windows_sidebar
permalink: windows_pginit.html
folder: windows
---

## [0x00] Overview

현재까지 많은 패치가드에 대한 연구가 진행되어 왔습니다. 가장 최근 문헌들과 과거 문헌들을 확인하며 분석하였습니다.

- Target OS : Windows 10, 1909(18363)

## [0x01] Initialization Patch Guard

`KiFilterFiberContext` 루틴은 패치가드에 대한 연구 및 분석 자료를 확인하면 가장 많이 거론되는 함수의 이름 중 하나입니다. 그 이유는 바로 해당 함수에서 패치가드에 대한 중요 구조체, 콜백 등을 등록하기 때문입니다.

`KiFilterFiberContext` 가 호출되는 방법에는 두 가지가 있습니다.

### [-] KeInitAmd64SpecificState

먼저 `KeInitAmd64SpecificState` 함수에서 예외 핸들러 기반으로 동작하는 경우가 있습니다.
부팅 시 디버거를 통해 `KeInitAmd64SpecificState` 에 BreakPoint(이하 "BP")를 설치하고 진행하면 멈추는 것을 확인할 수 있습니다.

해당 위치에서의 콜 스택은 아래와 같습니다.

```
3: kd> k
 # Child-SP          RetAddr           Call Site
00 fffffa8e`c7606888 fffff803`31e1175a nt!KeInitAmd64SpecificState
01 fffffa8e`c7606890 fffff803`31e11ed1 nt!PipInitializeCoreDriversAndElam+0x42
02 fffffa8e`c76068c0 fffff803`31e07778 nt!IopInitializeBootDrivers+0x135
03 fffffa8e`c7606a70 fffff803`31e10e75 nt!IoInitSystemPreDrivers+0xa00
04 fffffa8e`c7606bb0 fffff803`31b69552 nt!IoInitSystem+0x9
05 fffffa8e`c7606be0 fffff803`31531a85 nt!Phase1Initialization+0x42
06 fffffa8e`c7606c10 fffff803`315ca2e8 nt!PspSystemThreadStartup+0x55
07 fffffa8e`c7606c60 00000000`00000000 nt!KiStartSystemThread+0x28
```

`IDA`를 이용하여 확인하면 아래와 같습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/pginit_00.png?raw=true">

{% include tip.html content="lfence 명령은 Memory Barrier로 연산 순서에 대한 보장을 위해 사용됩니다."%}

1. 먼저 `InitSaveBootMode` 전역변수가 0인지를 비교합니다. 이는 안전모드에 대한 전역변수를 의미합니다.

2. 다음으로 `KdDebuggerNotPresent` 와 `KdPitchDebugger` 변수를 각 레지스터에 저장하고 OR 연산한 결과를 ecx에 저장한 후 부호를 반전(neg) 시킵니다.(해당 전역 변수들에 대해 더 알고 싶다면 블로그 내 [포스팅](https://shhoya.github.io/antikernel_kerneldebugging4.html)을 참조하십시오.)

3. 그리고 `r8d - r8d - [Carry Flag]`(sbb) 명령을 수행합니다.
   

만약 **디버깅 중(FALSE)**이라는 가정하에 위의 명령들을 실행하면 `sbb r8d, r8d` 이전의 연산은 0일 것 입니다.

`neg` 명령으로 부호반전을 하여도 0이기 때문에 `CF(Carry Flag)` 역시 0 입니다.

`sbb` 명령에서도 동일한 값을 뺀 후 CF 값(0)을 빼기 때문에 `r8d`에는 0이 저장되고 아래 `add` 명령을 통해 `r8d`의 값은 0x11이 됩니다. 0을 11로 나누기 때문에 `eax`에는 0이 저장되고 정상적으로 리턴합니다.



다음은 디버깅이 아닌 상황에 대한 연산입니다. `KdDebuggerNotPresent`와 `KdPitchDebugger`가 1인 경우 입니다.

```
fffff801`74a132b4 0fb615f1aba3ff  movzx   edx,byte ptr [nt!KdDebuggerNotPresent (fffff801`7444deac)]
fffff801`74a132bb 0fb6052a51a1ff  movzx   eax,byte ptr [nt!KdPitchDebugger (fffff801`744283ec)]
fffff801`74a132c2 0bd0            or      edx,eax
fffff801`74a132c4 8bca            mov     ecx,edx
fffff801`74a132c6 f7d9            neg     ecx

[*] ecx = 0xfffffffff
[*] edx = 1
[*] CF = 1
(Because "neg" instruction)

fffff801`74a132c8 451bc0          sbb     r8d,r8d
fffff801`74a132cb 4183e0ee        and     r8d,0FFFFFFEEh
fffff801`74a132cf 4183c011        add     r8d,11h
fffff801`74a132d3 d1ca            ror     edx,1
fffff801`74a132d5 8bc2            mov     eax,edx

[*] r8d = 0xffffffff ( 0xffffffff & 0xffffffee + 11h = 0xffffffff)
[*] edx = 0x80000000 ( 1 Rotation Right 1 , 1000 0000 0000 0000 | 0000 0000 0000 0000 | 0000 0000 0000 0000 | 0000 0000 0000 0000 )
[*] eax = edx
```

마지막 `cdq` 명령을 이용하여 부호를 저장하고 `idiv` 명령으로 연산이 발생하면 나눗셈 오류가 발생합니다.
부호 있는 나눗셈에서 범위를 벗어나기 때문입니다.
해당 예외가 발생하면 `KiDivideErrorFault` 루틴이 실행되며 핸들러에 예외를 전달합니다.

예외를 통해 `KiFIlterFiberContext`가 호출됩니다.

```
3: kd> k
 # Child-SP          RetAddr           Call Site
00 ffffbf01`a0a05618 fffff806`362282ec nt!KiFilterFiberContext
01 ffffbf01`a0a05620 fffff806`3599da79 nt!KeInitAmd64SpecificState$filt$0+0x10
02 ffffbf01`a0a05650 fffff806`359cbacf nt!_C_specific_handler+0xa9
03 ffffbf01`a0a056c0 fffff806`3580cca5 nt!RtlpExecuteHandlerForException+0xf
04 ffffbf01`a0a056f0 fffff806`3580b33e nt!RtlDispatchException+0x4a5
05 ffffbf01`a0a05e40 fffff806`359d4c5d nt!KiDispatchException+0x16e
06 ffffbf01`a0a064f0 fffff806`359cd90a nt!KiExceptionDispatch+0x11d
07 ffffbf01`a0a066d0 fffff806`362132d8 nt!KiDivideErrorFault+0x30a                 <= Exception Trigger
08 ffffbf01`a0a06860 fffff806`3621175a nt!KeInitAmd64SpecificState+0x34
09 ffffbf01`a0a06890 fffff806`36211ed1 nt!PipInitializeCoreDriversAndElam+0x42
0a ffffbf01`a0a068c0 fffff806`36207778 nt!IopInitializeBootDrivers+0x135
0b ffffbf01`a0a06a70 fffff806`36210e75 nt!IoInitSystemPreDrivers+0xa00
0c ffffbf01`a0a06bb0 fffff806`35f69552 nt!IoInitSystem+0x9
0d ffffbf01`a0a06be0 fffff806`35931a85 nt!Phase1Initialization+0x42
0e ffffbf01`a0a06c10 fffff806`359ca2e8 nt!PspSystemThreadStartup+0x55
0f ffffbf01`a0a06c60 00000000`00000000 nt!KiStartSystemThread+0x28

3: kd> u KeInitAmd64SpecificState+34  <= Exception Point
nt!KeInitAmd64SpecificState+0x34:
fffff801`200132d8 41f7f8          idiv    eax,r8d
fffff801`200132db 89442430        mov     dword ptr [rsp+30h],eax
fffff801`200132df eb00            jmp     nt!KeInitAmd64SpecificState+0x3d (fffff801`200132e1)
fffff801`200132e1 4883c428        add     rsp,28h
fffff801`200132e5 c3              ret
fffff801`200132e6 cc              int     3
fffff801`200132e7 cc              int     3
fffff801`200132e8 cc              int     3

3: kd> u nt!KeInitAmd64SpecificState$filt$0 la    <= KiFilterFiberContext Caller
nt!KeInitAmd64SpecificState$filt$0:
fffff801`200282dc 4055            push    rbp
fffff801`200282de 4883ec20        sub     rsp,20h
fffff801`200282e2 488bea          mov     rbp,rdx
fffff801`200282e5 33c9            xor     ecx,ecx
fffff801`200282e7 e88488faff      call    nt!KiFilterFiberContext (fffff801`1ffd0b70)
fffff801`200282ec 90              nop
fffff801`200282ed 4883c420        add     rsp,20h
fffff801`200282f1 5d              pop     rbp
fffff801`200282f2 c3              ret
```

마지막에 `except` 구문에서 `KiFilterFiberContext` 를 호출하는 것을 볼 수 있습니다. 눈썰미가 있다면 여기서 특이한 점을 찾을 수 있습니다. `ecx` 를 0으로 초기화 하고 함수를 호출하는 것 입니다. 이것은 `KiFilterFiberContext`에 첫 번째 파라미터가 존재하는 것이며 어디선가는 0이 아닌 값을 파라미터로 전달할 수 있다라는 의미가 됩니다.

### [-] ExpLicenseWatchInitWorker

이 루틴은 `KeInitAmd64SpecificState` 보다 부트 프로세스에서 먼저 실행됩니다. 다음은 콜 스택입니다.

```
3: kd> k
 # Child-SP          RetAddr           Call Site
00 fffff307`a4006878 fffff805`52e0be85 nt!ExpLicenseWatchInitWorker
01 fffff307`a4006880 fffff805`52e0af39 nt!ExpWatchProductTypeInitialization+0x1ad
02 fffff307`a4006a20 fffff805`52e09729 nt!ExInitSystemPhase2+0x9
03 fffff307`a4006a50 fffff805`52b6953a nt!Phase1InitializationDiscard+0xdf5
04 fffff307`a4006be0 fffff805`52531a85 nt!Phase1Initialization+0x2a
05 fffff307`a4006c10 fffff805`525ca2e8 nt!PspSystemThreadStartup+0x55
06 fffff307`a4006c60 00000000`00000000 nt!KiStartSystemThread+0x28
```

해당 루틴의 의사코드는 다음과 같습니다.

```c++
__int64 __fastcall ExpLicenseWatchInitWorker(__int64 a1, __int64 a2, __int64 a3, __int64 a4)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  _mm_lfence();
  KPRCB = KiProcessorBlock;
  KiServiceTablesLocked = KiProcessorBlock->HalReserved[6];
  KiProcessorBlock->HalReserved[6] = 0i64;
  pKiFilterFiberContext = KPRCB->HalReserved[5]; // KiFilterFiberContext
  KPRCB->HalReserved[5] = 0i64;
  LOBYTE(a4) = (InitSafeBootMode != 0) | (MEMORY[0xFFFFF780000002D4] >> 1);
  v7 = __rdtsc();
  v8 = v7 >> 3;
  v9 = (v7 >> 3) / 0x64;
  result = (100 * v9);
  v11 = (v8 - result);
  if ( v11 > 3 )
    LOBYTE(a4) = (MEMORY[0xFFFFF780000002D4] >> 1) | 1;
  if ( !a4 )                                    // Check Debugger
  {
    result = pKiFilterFiberContext(KiServiceTablesLocked, v9, v11, a4);
    if ( result != 1 )
      KeBugCheckEx(0x9Au, 'BBBB', 0xC000026Aui64, 0i64, 0i64);
  }
  return result;
}
```

`KPRCB` 구조체 내 `HalReserved` 멤버를 이용하는 것을 볼 수 있습니다. 

```
3: kd> dt_KPRCB -a -c poi(KiProcessorBlock) HalReserved
nt!_KPRCB
+0x048 HalReserved 
 [00] 0 [01] 0 [02] 0 [03] 0 [04] 0 [05] 0xfffff807`4e7d0b70 [06] 0xfffff807`4e850010 [07] 0  

3: kd> u 0xfffff807`4e7d0b70 l1
nt!KiFilterFiberContext:
fffff807`4e7d0b70 4055            push    rbp

3: kd> u 0xfffff807`4e850010 l1
nt!KiServiceTablesLocked:
fffff807`4e850010 0f0d09          prefetchw [rcx]
```

이 때 콜 스택은 아래와 같습니다.

```
3: kd> k
 # Child-SP          RetAddr           Call Site
00 fffffc83`9bc06838 fffff807`4e8322c4 nt!KiFilterFiberContext
01 fffffc83`9bc06840 fffff807`4e80be85 nt!ExpLicenseWatchInitWorker+0x25e7c
02 fffffc83`9bc06880 fffff807`4e80af39 nt!ExpWatchProductTypeInitialization+0x1ad
03 fffffc83`9bc06a20 fffff807`4e809729 nt!ExInitSystemPhase2+0x9
04 fffffc83`9bc06a50 fffff807`4e56953a nt!Phase1InitializationDiscard+0xdf5
05 fffffc83`9bc06be0 fffff807`4df31a85 nt!Phase1Initialization+0x2a
06 fffffc83`9bc06c10 fffff807`4dfca2e8 nt!PspSystemThreadStartup+0x55
07 fffffc83`9bc06c60 00000000`00000000 nt!KiStartSystemThread+0x28
```

마찬가지로 `InitSafeBootMode` 와 `KUSER_SHARED_DATA.KdDebuggerEnabled` 필드를 확인하고 디버깅 중인 경우 `KiFilterFiberContext`를 호출하지 않습니다.

## [0x02] KiFilterFiberContext

작성중