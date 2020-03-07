---
title: Kernel Global Variable
keywords: documentation, technique, debugging
tags: [Windows, Reversing, Dev]
summary: "커널 디버깅의 원리 (4)"
sidebar: antikernel_sidebar
permalink: antikernel_kerneldebugging4.html
folder: antikernel
---

## [0x00] Overview

위에서 몇 가지 함수와 변수에 대해 설명하였습니다. 실제 디버그 모드가 활성화 되어있을 때와, 그렇지 않은 경우의 값을 비교해 놓은 표입니다.

{% include warning.html content="이는 어떠한 문서화도 이루어져있지 않습니다. 개인이 직접 테스트했으므로 무조건 이렇다라고 할 수 없습니다." %}



## [0x01] Global Variable

표를 볼 때 주의해야 할 점은 디버그 모드(디버깅 가능 상태)와 디버깅 중일 때에 대한 구분입니다. 단순히 디버그 모드가 활성화 되어있는것과 디버깅을 실제 하고 있을 때와 다르기 때문입니다.

| Variable                         | DebugMode             | NoDebugMode             |
| :------------------------------- | --------------------- | ----------------------- |
| KdLocalDebugEnabled              | TRUE(Local Debugging) | FALSE                   |
| KdDebuggerEnabled                | TRUE(Debugging)       | FALSE                   |
| KdDebuggerNotPresent             | FALSE(Debugging)      | FALSE                   |
| KdPitchDebugger                  | FALSE                 | TRUE                    |
| KdpBootedNoDebug                 | FALSE                 | TRUE                    |
| KdEnteredDebugger                | TRUE(Debugging)       | FALSE                   |
| KdPageDebuggerSection            | FALSE(Debugging)      | TRUE                    |
| KdpDebugRoutineSelect            | TRUE(Debugging)       | FALSE                   |
| KdPreviouslyEnabled              | FALSE                 | TRUE(KdDebuggerEnabled) |
| KdpDebuggerStructuresInitialized | TRUE(Debugging)       | FALSE                   |
| KdPortLocked                     | TRUE(Debugging)       | FALSE                   |
| KdDebugDevice                    | TRUE(pointer)         | FALSE                   |
| KdpContext                       | TRUE(xmm)             | FALSE                   |
| KdDebuggerEnteredCount           | TRUE                  | FALSE                   |



## [0x02] Bonus(KdpBreakpointTable)

우선 `ReactOS`에 `BREAKPOINT_ENTRY` 구조체가 정의되어있습니다. 그러나 제가 확인한 것과는 약간 다르기 때문에 직접 확인한 기준으로 설명합니다.

```c
typedef struct _BREAKPOINT_ENTRY
{
    PVOID		BreakPoint;
    ULONG64		DirectoryTableBase;
    DWORD32		InterruptByte_CC;
    DWORD32		UnknownField_0;
    DWORD32		OriginalByte;
    DWORD32		UnknownField_1;
    ULONG64		UnknownField_2;
}BREAKPOINT_ENTRY, *PBREAKPOINT_ENTRY;
```

위와 같이 다르게 정의한 이유는 아래와 같습니다.

```
0: kd> dp KdpBreakpointTable
fffff804`44e323e0  fffff804`450c1b80 ffffc387`6467a200
fffff804`44e323f0  00000000`000000cc 00000000`000000e8
fffff804`44e32400  00000001`00000000 fffff804`450c1b85
fffff804`44e32410  ffffc387`6467a200 00000000`000000cc
fffff804`44e32420  00000000`0000008b 00000001`00000000
fffff804`44e32430  00000000`00000000 00000000`00000000
fffff804`44e32440  00000000`00000000 00000000`00000000
fffff804`44e32450  00000000`00000000 00000000`00000000
```

2개의 BP를 설치했을 때, 테이블을 확인할 수 있습니다. 사이즈를 확인하면 하나의 브레이크 포인트 당 0x28 바이트 크기만큼 할당되어 사용되는 것을 볼 수 있습니다. 해당 구조를 이용하여 디버깅을 방지하는 기법도 만들어 볼 수 있습니다.



## [0x03] Conclusion

커널 디버깅의 원리 챕터의 마무리입니다. 정확하게는 커널 디버깅 시 발생하는 커널의 함수 및 변수라고하는게 맞는 것 같습니다.  다음 챕터에서는 이전에 만들어둔 디버깅 방지 드라이버를 우회하는 방법에 대해 알아보겠습니다.

