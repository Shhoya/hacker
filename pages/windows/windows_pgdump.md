---
title: PatchGuard Dump Analysis
keywords: documentation, technique, reversing, kernel, windows
date: 2020-11-20
tags: [Windows, Reversing, Vulnerability, Kernel]
summary: "PatchGuard 분석 팁(2)"
sidebar: windows_sidebar
permalink: windows_pgdump.html
folder: windows
---

## [0x00] Overview

패치가드의 동작을 분석하기 위해 크래시 유형과 크래시 상황에서의 메모리 조사는 매우 중요한 부분입니다.
간단하게 메모리 상에 `ntoskrnl` 이미지의 코드를 변조하여 크래시 트리거하고 덤프를 분석했습니다/(ex. 익스큐티브 함수 후킹)

## [0x01] Dump Analysis

```
2: kd> !analyze -v
*******************************************************************************
*                                                                             *
*                        Bugcheck Analysis                                    *
*                                                                             *
*******************************************************************************

CRITICAL_STRUCTURE_CORRUPTION (109)
This bugcheck is generated when the kernel detects that critical kernel code or
data have been corrupted. There are generally three causes for a corruption:
1) A driver has inadvertently or deliberately modified critical kernel code
 or data. See http://www.microsoft.com/whdc/driver/kernel/64bitPatching.mspx
2) A developer attempted to set a normal kernel breakpoint using a kernel
 debugger that was not attached when the system was booted. Normal breakpoints,
 "bp", can only be set if the debugger is attached at boot time. Hardware
 breakpoints, "ba", can be set at any time.
3) A hardware corruption occurred, e.g. failing RAM holding kernel code or data.
Arguments:
Arg1: a39fedd944f17635, Reserved
Arg2: b3b6fa5f976fbedb, Reserved
Arg3: fffff80361f6e010, Failure type dependent information
Arg4: 0000000000000001, Type of corrupted region, can be
```

`CRITICAL_STRUCTURE_CORRUPTION(0x109)` BugCheck 가 호출됐으며 각 인자들이 나와있습니다.

- Arg1 : PatchGuard Context 주소
- Arg2 : 손상을 감지한 유효성 검사의 구조체 주소
- Arg3 : 손상 된 데이터 주소
- Arg4 : 손상 영역의 유형

이는 MSDN 에 민감한 정보를 제외하고 상세하게 설명되어 있습니다.([Link](https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/bug-check-0x109---critical-structure-corruption))
본인의 덤프는 1번 유형으로 함수가 변조되었음을 의미하며 인자를 확인하여 손상된 함수를 확인하면 아래와 같습니다.

```
2: kd> u @r9 l30
nt!ExAllocatePoolWithTag:
fffff803`61f6e010 48895c2408      mov     qword ptr [rsp+8],rbx
fffff803`61f6e015 48896c2410      mov     qword ptr [rsp+10h],rbp
fffff803`61f6e01a 4889742418      mov     qword ptr [rsp+18h],rsi
fffff803`61f6e01f 57              push    rdi
...
fffff803`61f6e08b 4883c430        add     rsp,30h
fffff803`61f6e08f 415f            pop     r15
fffff803`61f6e091 415e            pop     r14
fffff803`61f6e093 5f              pop     rdi
fffff803`61f6e094 90              nop             <= Corruption Point
fffff803`61f6e095 c3              ret
fffff803`61f6e096 0000            add     byte ptr [rax],al
fffff803`61f6e098 cc              int     3
fffff803`61f6e099 cc              int     3
fffff803`61f6e09a cc              int     3
fffff803`61f6e09b cc              int     3
fffff803`61f6e09c cc              int     3
fffff803`61f6e09d cc              int     3
fffff803`61f6e09e cc              int     3
fffff803`61f6e09f cc              int     3
```

패치가드 분석을 위해 가장 중요한 부분인 `Arg1`과 `Arg2`에 대해 살펴보겠습니다.

`Arg1`, `Arg2`는 어떠한 연산에 의한 결과 값입니다. 그리고 이 값들을 어떠한 주소라고 한 것은 많은 문헌에서 말하는 `KiInitializePatchGuard` 루틴에서 찾을 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/pgdump_00.png?raw=true">

`Arg1`, `Arg2`와 매우 비슷한 숫자들을 볼 수 있습니다! `PG Context`의 주소와 `ADD` 후 `PG Context+900h, 908h` 에 저장하는 모습을 볼 수 있습니다.

물론 저 위의 로직 외에도 저 숫자를 사용하는 로직을 많이 찾을 수 있습니다.(위의 매직넘버를 검색하면 많은 참조를 찾을 수 있습니다.) 다만 저 매직 넘버를 사용하는 모든 로직이 패치가드와 연관이 있을 뿐 입니다.

역연산을 통해 `Arg1`, `Arg2`를 계산해봅니다.

```
2: kd> ? @rdx - a3a03f58`91c8b4e8
Evaluate expression: -89607191871155 = ffffae80`b328c14d  <= Pg Context
2: kd> ? @r8 - b3b74bde`e4453415
Evaluate expression: -89607191754042 = ffffae80`b32a8ac6  <= Corrupted information

2: kd> dps ffffae80`b328c14d l20
ffffae80`b328c14d  f0d44424`8ad519a8
...
ffffae80`b328c1dd  e2e86eb9`2c734b6a
ffffae80`b328c1e5  0fb2d0d0`b06bcf48
ffffae80`b328c1ed  486847b7`f4d08644
ffffae80`b328c1f5  3caf0b95`59c101b4
ffffae80`b328c1fd  25c8cc92`da5813b0
ffffae80`b328c205  7efcd306`c007feed
ffffae80`b328c20d  0ccbe8b2`aa00c3bf
ffffae80`b328c215  00000000`00000000
ffffae80`b328c21d  00000000`00000000
ffffae80`b328c225  00000000`00000000
ffffae80`b328c22d  00000000`00000000
ffffae80`b328c235  fffff803`61c31ac0 nt!ExAcquireResourceSharedLite
ffffae80`b328c23d  fffff803`61c316e0 nt!ExAcquireResourceExclusiveLite
ffffae80`b328c245  fffff803`61f6e010 nt!ExAllocatePoolWithTag

2: kd> dps ffffae80`b32a8ac6
ffffae80`b32a8ac6  00000000`00000001
ffffae80`b32a8ace  fffff803`6210f000 nt!Ports <PERF> (nt+0x50f000)
ffffae80`b32a8ad6  0af22205`0005e1a0
ffffae80`b32a8ade  fffff803`6210f000 nt!Ports <PERF> (nt+0x50f000)
ffffae80`b32a8ae6  fffff803`61c00000 nt!SeConvertSecurityDescriptorToStringSecurityDescriptor <PERF> (nt+0x0)
ffffae80`b32a8aee  0005e1a0`00ab5000
...
ffffae80`b32a8b1e  01694572`604be2fe
ffffae80`b32a8b26  6973a296`72c47581
ffffae80`b32a8b2e  5c8a6a1f`717987c4
ffffae80`b32a8b36  57d2b745`7accf142
ffffae80`b32a8b3e  0d3a1160`1c4e61a9
```

위에서 말한 설명대로 첫 인자는 PG Context(패치가드 동작에 사용되는 큰 구조체), 두 번째 인자는 손상된 시점에서의 정보들을 담고 있습니다.

이러한 내용을 이용하여 Context의 구조 확인이 가능합니다.

예를 들어, 현재 `ExAcquireResourceSharedLite` 루틴의 주소가 PG Context에 저장되어 있습니다. 그렇다면 PG Context가 초기화 되는 과정에서 `lea register, ExAcquireResourceSharedLite` 라는 명령을 이용할 가능성이 높습니다.

실제 참조를 찾아보면 대부분 `CALL` 명령을 통한 함수 호출인데 단 하나의 함수에서만 `LEA` 명령으로 해당 루틴의 주소를 가져옵니다.

패치가드의 초기화 루틴을 찾았습니다. 물론 이런 방법 외에도 단순히 `ntoskrnl` 에서 가장 크기가 큰 함수가 보통 패치가드의 초기화 함수입니다.

## [0x02] Reference

1. [Satoshi's Note-some tips to analyze patchguard](http://standa-note.blogspot.com/2015/10/some-tips-to-analyze-patchguard.html)

