---
title: PatchGuard Initialize -2-
keywords: documentation, technique, reversing, kernel, windows
date: 2021-02-23
tags: [Windows, Reversing, Vulnerability, Kernel]
summary: "Windows PG Initialize"
sidebar: windows_sidebar
permalink: windows_pginit2.html
folder: windows
---

## [0x00] Overview

초기화 과정에 대한 내용이 길기 때문에 두개의 파트로 나눴습니다. 첫 번째 파트에서는 패치가드 초기화 루틴이 호출되는 내용에 대해 다뤘으며, 이번 파트에서는 패치가드 초기화 루틴에 대한 전반적인 내용을 서술합니다.

## [0x01] Initialize PatchGuard Context

가장 중요한 핵심 요소인 `PGContext` 에 대해 알아보겠습니다. 과거 많은 보안 연구원 및 해커들은 패치가드에 대해 분석하였고, 패치가드에서 사용되는 핵심 요소인 거대한 구조를 `PG Context` 라고 명명하여 부르기 시작하였습니다.

지금부터는 정말 긴 여정이 될 꺼라 확신합니다.

위에서 설명한 초기화 과정이 중요한 이유는, `KiInitializePatchGuard` 루틴이 바로 이 `PG Context` 를 초기화 하는 루틴이기 때문입니다.

`KiInitializePatchGuard` 루틴을 잘 살펴보면 아래와 유사한 패턴들을 자주 볼 수 있습니다.

```
// KiInitializePatchGuard

0F 31                                   rdtsc
48 C1 E2 20                             shl     rdx, 20h
49 B8 01 20 00 04 80 00 10 70           mov     r8, 7010008004002001h
48 0B C2                                or      rax, rdx
BB 05 00 00 00                          mov     ebx, 5
48 8B C8                                mov     rcx, rax
48 C1 C8 03                             ror     rax, 3
48 33 C8                                xor     rcx, rax
49 8B C0                                mov     rax, r8
48 F7 E1                                mul     rcx
48 8B CA                                mov     rcx, rdx
48 89 94 24 60 05 00 00                 mov     [rsp+2468h+var_1F08], rdx
48 33 C8                                xor     rcx, rax
48 B8 A3 8B 2E BA E8 A2 8B 2E           mov     rax, 2E8BA2E8BA2E8BA3h
48 F7 E1                                mul     rcx
48 D1 EA                                shr     rdx, 1
48 6B C2 0B                             imul    rax, rdx, 0Bh
48 2B C8                                sub     rcx, rax
3B CB                                   cmp     ecx, ebx
0F 87 B7 00 00 00                       ja      loc_1409D3258
0F 84 97 00 00 00                       jz      loc_1409D323E
85 C9                                   test    ecx, ecx
74 79                                   jz      short loc_1409D3224
83 E9 01                                sub     ecx, 1
74 5B                                   jz      short loc_1409D320B
83 E9 01                                sub     ecx, 1
74 3C                                   jz      short loc_1409D31F1
83 F9 01                                cmp     ecx, 1
74 1A                                   jz      short loc_1409D31D4
C7 84 24 0C 01 00 00 94 64 07 67        mov     [rsp+2468h+var_235C], 67076494h
8B BC 24 0C 01 00 00                    mov     edi, [rsp+2468h+var_235C]
C1 C7 04                                rol     edi, 4
E9 97 01 00 00                          jmp     loc_1409D336B
```

`rdtsc` 명령을 이용하여 시드로 사용하여 복잡한 연산을 진행합니다. 해당 패턴은 주로  패치가드에서 사용되는 메모리의 풀 태그를 결정하는데 사용됩니다. 메모리 상에서 내부 데이터 구조를 찾기 어렵게 하기 위한 방법 중 하나입니다.

`KiInitializePatchGuard` 루틴은 매우 복잡하게 이루어져 있습니다. 예로 `KiInitializePatchGuard` 함수에서 `KeBugCheckEx` 를 통해 초기화 실패를 알리는 루틴은 다음과 같습니다.

```c
KeBugCheckEx(__ROR4__(0x4000004F, 222), 0xFui64, BugCheckParameter2[0], 0x140000000ui64, v48);
```

`Rotate` 연산을 통해 버그 코드를 전달할 정도로 신경을 많이 쓴 것을 볼 수 있습니다. 실제로 연산해서 확인하면 `0x13D` 이며, `CRITICAL_INITIALIZATION_FAILURE` 로 BSOD 가 발생하게 될 것으로 보입니다.

```c
//
// MessageId: CRITICAL_INITIALIZATION_FAILURE
//
// MessageText:
//
//  CRITICAL_INITIALIZATION_FAILURE
//
#define CRITICAL_INITIALIZATION_FAILURE  ((ULONG)0x0000013DL)
```

패치가드를 분석하면 꼭 한번씩 보게되는 함수의 이름이 있습니다.

바로 `CmpAppendDllSection`  입니다. 정확히는 이 함수의 바이트 코드는 `PgContext` 를 암호화하는데 사용된다고 알려져 있습니다. 이를 기반으로 참조를 따라가면 아래와 같이 패치가드에서 보호하는 루틴과 전역변수들을 확인할 수 있습니다.(Windows 10, 1909 기준)

```c
...
  *PgContext = *CmpAppendDllSection;
  *(PgContext + 1) = *(CmpAppendDllSection + 1);
  *(PgContext + 2) = *(CmpAppendDllSection + 2);
  *(PgContext + 3) = *(CmpAppendDllSection + 3);
  *(PgContext + 4) = *(CmpAppendDllSection + 4);
  *(PgContext + 5) = *(CmpAppendDllSection + 5);
  *(PgContext + 6) = *(CmpAppendDllSection + 6);
  *(PgContext + 7) = *(CmpAppendDllSection + 7);
  *(PgContext + 8) = *(CmpAppendDllSection + 8);
  *(PgContext + 9) = *(CmpAppendDllSection + 9);
  *(PgContext + 10) = *(CmpAppendDllSection + 10);
  *(PgContext + 11) = *(CmpAppendDllSection + 11);
  *(PgContext + 48) = *(CmpAppendDllSection + 48);
  v323 = v3899;
  *(PgContext + 508) = v3899 + v3883;
  *(PgContext + 506) = v323 + v3882;
  *(PgContext + 507) = v323 + v3884;
  *(PgContext + 509) = v323 + v3887;
  _disable();
...
// anti-debug(infinity loop)
...
  _enable();
  *(PgContext + 29) = ExAcquireResourceSharedLite;
  *(PgContext + 30) = ExAcquireResourceExclusiveLite;
  *(PgContext + 31) = ExAllocatePoolWithTag;
  *(PgContext + 32) = ExFreePoolWithTag;
  *(PgContext + 33) = ExMapHandleToPointer;
  *(PgContext + 34) = ExQueueWorkItem;
  *(PgContext + 35) = ExReleaseResourceLite;
  *(PgContext + 36) = ExUnlockHandleTableEntry;
  *(PgContext + 37) = ExAcquirePushLockExclusiveEx;
  *(PgContext + 38) = ExReleasePushLockExclusiveEx;
  *(PgContext + 39) = ExAcquirePushLockSharedEx;
  *(PgContext + 40) = ExReleasePushLockSharedEx;
  *(PgContext + 41) = KeAcquireInStackQueuedSpinLockAtDpcLevel;
  *(PgContext + 42) = ExAcquireSpinLockSharedAtDpcLevel;
  *(PgContext + 43) = KeBugCheckEx;
  *(PgContext + 44) = KeDelayExecutionThread;
  *(PgContext + 45) = KeEnterCriticalRegionThread;
  *(PgContext + 46) = KeLeaveCriticalRegion;
  *(PgContext + 47) = KeEnterGuardedRegion;
  *(PgContext + 48) = KeLeaveGuardedRegion;
  *(PgContext + 49) = KeReleaseInStackQueuedSpinLockFromDpcLevel;
  *(PgContext + 50) = ExReleaseSpinLockSharedFromDpcLevel;
  *(PgContext + 51) = KeRevertToUserGroupAffinityThread;
  *(PgContext + 52) = KeProcessorGroupAffinity;
  *(PgContext + 53) = KeInitializeEnumerationContext;
  *(PgContext + 54) = KeEnumerateNextProcessor;
  *(PgContext + 55) = KeCountSetBitsAffinityEx;
  *(PgContext + 56) = KeQueryAffinityProcess;
  *(PgContext + 57) = KeQueryAffinityThread;
  *(PgContext + 58) = KeSetSystemGroupAffinityThread;
  *(PgContext + 59) = KeSetCoalescableTimer;
  *(PgContext + 63) = RtlImageNtHeader;
  *(PgContext + 66) = RtlSectionTableFromVirtualAddress;
  *(PgContext + 64) = RtlLookupFunctionTable;
  *(PgContext + 65) = RtlPcToFileHeader;
  *(PgContext + 60) = ObfDereferenceObject;
  *(PgContext + 61) = &ObReferenceObjectByName;
  *(PgContext + 62) = RtlImageDirectoryEntryToData;
  *(PgContext + 67) = DbgPrint;
  *(PgContext + 68) = MmAllocateIndependentPages;
  *(PgContext + 69) = MmFreeIndependentPages;
  *(PgContext + 70) = MmSetPageProtection;
  *(PgContext + 76) = RtlLookupFunctionEntry;
  *(PgContext + 77) = KeAcquireSpinLockRaiseToDpc;
  *(PgContext + 78) = KeReleaseSpinLock;
  *(PgContext + 79) = MmGetSessionById;
  *(PgContext + 80) = MmGetNextSession;
  *(PgContext + 81) = MmQuitNextSession;
  *(PgContext + 82) = MmAttachSession;
  *(PgContext + 83) = MmDetachSession;
  *(PgContext + 84) = MmGetSessionIdEx;
  *(PgContext + 85) = MmIsSessionAddress;
  *(PgContext + 86) = MmIsAddressValid;
  *(PgContext + 87) = MmSessionGetWin32Callouts;
  *(PgContext + 88) = KeInsertQueueApc;
  *(PgContext + 89) = KeWaitForSingleObject;
  *(PgContext + 91) = ExReferenceCallBackBlock;
  *(PgContext + 92) = ExGetCallBackBlockRoutine;
  *(PgContext + 93) = ExDereferenceCallBackBlock;
  *(PgContext + 94) = sub_1401A8A00;
  *(PgContext + 95) = PspEnumerateCallback;
  *(PgContext + 96) = CmpEnumerateCallback;
  *(PgContext + 97) = DbgEnumerateCallback;
  *(PgContext + 98) = ExpEnumerateCallback;
  *(PgContext + 99) = ExpGetNextCallback;
  *(PgContext + 100) = xHalTimerWatchdogStop;
  *(PgContext + 101) = KiSchedulerApcTerminate;
  *(PgContext + 102) = KiSchedulerApc;
  *(PgContext + 103) = xHalTimerWatchdogStop;
  *(PgContext + 104) = sub_1401A9B00;
  *(PgContext + 105) = MmAllocatePagesForMdlEx;
  *(PgContext + 106) = MmAllocateMappingAddress;
  *(PgContext + 107) = MmMapLockedPagesWithReservedMapping;
  *(PgContext + 108) = MmUnmapReservedMapping;
  *(PgContext + 109) = sub_1401B61B0;
  *(PgContext + 110) = sub_1401B6220;
  *(PgContext + 111) = MmAcquireLoadLock;
  *(PgContext + 112) = MmReleaseLoadLock;
  *(PgContext + 113) = KeEnumerateQueueApc;
  *(PgContext + 114) = KeIsApcRunningThread;
  *(PgContext + 115) = sub_1401A99D0;
...
  *(PgContext + 116) = PsAcquireProcessExitSynchronization;
  *(PgContext + 117) = ObDereferenceProcessHandleTable;
  *(PgContext + 118) = PsGetNextProcess;
  *(PgContext + 119) = PsQuitNextProcessThread;
  *(PgContext + 120) = PsGetNextProcessEx;
  *(PgContext + 121) = MmIsSessionLeaderProcess;
  *(PgContext + 122) = PsInvokeWin32Callout;
  *(PgContext + 123) = MmEnumerateAddressSpaceAndReferenceImages;
  *(PgContext + 124) = PsGetProcessProtection;
  *(PgContext + 125) = PsGetProcessSignatureLevel;
  *(PgContext + 126) = PsGetProcessSectionBaseAddress;
  *(PgContext + 127) = SeCompareSigningLevels;
  *(PgContext + 133) = RtlIsMultiSessionSku;
  *(PgContext + 134) = KiEnumerateCallback;
  *(PgContext + 135) = KeStackAttachProcess;
  *(PgContext + 136) = KeUnstackDetachProcess;
  *(PgContext + 137) = KeIpiGenericCall;
  *(PgContext + 138) = sub_1401B6000;
  *(PgContext + 139) = MmGetPhysicalAddress;
  *(PgContext + 140) = MmUnlockPages;
  *(PgContext + 128) = KeComputeSha256;
  *(PgContext + 129) = KeComputeParallelSha256;
  *(PgContext + 130) = KeSetEvent;
  *(PgContext + 141) = VslVerifyPage;
  *(PgContext + 144) = PsLookupProcessByProcessId;
  *(PgContext + 145) = PsGetProcessId;
  *(PgContext + 146) = MmCheckProcessShadow;
  *(PgContext + 147) = MmGetImageRetpolineCodePage;
  *(PgContext + 300) = &qword_14042DBC0;
  if ( v324 )
    *(PgContext + 90) = *(v324 + 8);
  *(PgContext + 131) = RtlpConvertFunctionEntry;
  *(PgContext + 132) = RtlpLookupPrimaryFunctionEntry;
  *(PgContext + 142) = KiGetInterruptObjectAddress;
  _disable();
...
// anti-debug
...
  *(PgContext + 317) = KiDispatchCallout;
  *(PgContext + 318) = xHalTimerWatchdogStop;
```

다음은 전역 변수들 입니다.

```c
 *(PgContext + 152) = &qword_14042A1C0;
  *(PgContext + 153) = &qword_14042DBA8;
  *(PgContext + 154) = &qword_14042DBB0;
  *(PgContext + 155) = &qword_14042DBB8;
  *(PgContext + 156) = PsInitialSystemProcess;
  *(PgContext + 157) = KiWaitAlways;
  *(PgContext + 158) = &KiEntropyTimingRoutine;
  *(PgContext + 159) = &KiProcessListHead;
  *(PgContext + 160) = &KiProcessListLock;
  *(PgContext + 161) = ObpTypeObjectType;
  *(PgContext + 162) = IoDriverObjectType;
  *(PgContext + 163) = PsProcessType;
  *(PgContext + 164) = &PsActiveProcessHead;
  *(PgContext + 165) = &PsInvertedFunctionTable;
  *(PgContext + 166) = &PsLoadedModuleList;
  *(PgContext + 167) = &PsLoadedModuleResource;
  *(PgContext + 168) = &PsLoadedModuleSpinLock;
  *(PgContext + 169) = &PspActiveProcessLock;
  *(PgContext + 170) = &KeNumberProcessorsGroup0[18];
  *(PgContext + 171) = &ExpUuidLock;
  *(PgContext + 172) = &AlpcpPortListLock;
  *(PgContext + 173) = &KeServiceDescriptorTable;
  *(PgContext + 174) = &KeServiceDescriptorTableShadow;
  *(PgContext + 175) = &KeServiceDescriptorTableFilter;
  *(PgContext + 176) = &VfThunksExtended;
  *(PgContext + 177) = &PsWin32CallBack;
  *(PgContext + 178) = &qword_14042DB88;
  *(PgContext + 179) = &KiTableInformation;
  *(PgContext + 180) = &HandleTableListHead;
  *(PgContext + 181) = &HandleTableListLock;
  *(PgContext + 182) = ObpKernelHandleTable;
  *(PgContext + 183) = 0xFFFFF78000000000ui64; // Shared Memory(KUSER_SHARED_DATA)
  *(PgContext + 184) = KiWaitNever;
  *(PgContext + 185) = &SeProtectedMapping;
  *(PgContext + 187) = &KiStackProtectNotifyEvent;
  *(PgContext + 188) = MmPteBase;
  *(PgContext + 189) = PsNtosImageBase;
  *(PgContext + 190) = PsHalImageBase;
  *(PgContext + 191) = &KeNumberProcessors_0;
  v334 = &_ti_a;
  v335 = 2i64;
  *(PgContext + 192) = &::Src;
  *(PgContext + 193) = &qword_140574350;
  *(PgContext + 194) = &RtlpInvertedFunctionTable;
  *(PgContext + 186) = KiInterruptThunk;
```

눈에 띄는 것만 확인해도 위와 같이 매우 많은 것을 볼 수 있습니다.

{% include tip.html content="의사코드의 인덱스를 맞추려하지 마십시오. 의사코드는 말 그대로 의사코드일 뿐입니다. 어셈블리 상 CmpAppendDllSection은 16바이트씩 배열에 복사합니다."%}

위의 팁 내용과 같이 배열이 약간은 다를 수 있지만 틀리진 않았습니다. `CmpAppendDllSection` 의 코드를 복사하는 명령은 `movups` 로 16바이트 만큼 복사합니다.

즉 아래와 같이 이해할 수 있습니다.

```c
  *(PgContext + 16) = *(CmpAppendDllSection + 1);
  *(PgContext + 32) = *(CmpAppendDllSection + 2);
  *(PgContext + 48) = *(CmpAppendDllSection + 3);
  *(PgContext + 64) = *(CmpAppendDllSection + 4);
  *(PgContext + 80) = *(CmpAppendDllSection + 5);
  *(PgContext + 96) = *(CmpAppendDllSection + 6);
  *(PgContext + 112) = *(CmpAppendDllSection + 7);
  *(PgContext + 128) = *(CmpAppendDllSection + 8);
  *(PgContext + 144) = *(CmpAppendDllSection + 9);
  *(PgContext + 160) = *(CmpAppendDllSection + 10);
  *(PgContext + 176) = *(CmpAppendDllSection + 11);
  *(PgContext + 192) = *(CmpAppendDllSection + 48); // 4 bytes
```

보호 함수의 경우, 8바이트 주소 값으로 정렬되어 있으므로 8바이트 씩 저장됩니다.

```c
  *(PgContext + 232) = ExAcquireResourceSharedLite;
  *(PgContext + 240) = ExAcquireResourceExclusiveLite;
  *(PgContext + 248) = ExAllocatePoolWithTag;
  *(PgContext + 256) = ExFreePoolWithTag;
  *(PgContext + 264) = ExMapHandleToPointer;
  *(PgContext + 272) = ExQueueWorkItem;
  *(PgContext + 280) = ExReleaseResourceLite;
  *(PgContext + 288) = ExUnlockHandleTableEntry;
  *(PgContext + 296) = ExAcquirePushLockExclusiveEx;
```

위와 같이 이해할 수 있습니다.

간단히 `PgContext` 는 아래와 같다고 정의할 수 있습니다. 진행하며 천천히 채워보겠습니다.

```c
typedef struct _PG_CONTEXT{
	BYTE CmpAppendDllSection[0xC4]; // 0x0000 - 0x00C4
	BYTE UnknownData[0x24]; // 0x00C4 - 0x00E8
  PVOID ExAcquireResourceSharedLite;
	PVOID ExAcquireResourceExclusiveLite;
	PVOID ExAllocatePoolWithTag;
	PVOID ExFreePoolWithTag;
	PVOID ExMapHandleToPointer;
	....
}PG_CONTEXT, *PPG_CONTEXT;
```

다시 돌아와서 `PgContext` 초기화 부분에서 특정 상수 값을 찾을 수 있습니다.

```c
PgContext = v194 + v193;                      // First PgContext
  v3989 = v194;
  v3891 = v194 + v203;
  if ( !(v194 + v203) )
    return 0;
  v213 = v172 + 0x80000;
  v3896 = v172 + 0x80000;
  memset(PgContext, 0, (v172 + 0x80000));
  _disable();
  if ( !KdDebuggerNotPresent )
  {
    while ( 1 )
      ;
  }
  _enable();
...
  if ( !v169 )
  {
    v216 = PgContext + 0xAA0;                   // Context Size??
    qword_140426210[0] = off_140428D28;
    v4365[4] = (PgContext + 0xAA0);
```

최근 연구된 패치가드 문서에서 `PgContext`의 사이즈를 `0xAA0` 이라 정의한 부분을 확인했습니다.  개인적인 의견으로는 `PgContext` 의 `Tail` 부분이 아닐까 생각합니다. 어떤 데이터 구조에서 `HEAD`와 `TAIL` 부분은 있으니 충분히 가능성 있다고 봅니다.

## [0x02] Parameters

`Windows 8.1 Kernel Patch Protection Analysis` 문서에 의하면 `KiInitializePatchGuard` 에 다섯개의 파라미터를 전달한다고 되어 있습니다.

해당 부분을 확인하기 위해 `KiInitializePatchGuardStub` 부터 디버깅하였습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/pginit2_00.png?raw=true">

위의 그림을 확인하면 전달되는 파라미터 값을 아래와 같이 확인할 수 있습니다.

```
rcx = 0x09
rdx = 0x03
r8  = 0x02
r9  = 0x00
[rsp+20h] = 0x01
```

### [-] 1st Parameter

먼저 첫 번째 파라미터(`rcx`) 는 `PGContext`를 확인하기 위해 생성되는 `DPC` 루틴의 인덱스를 의미한다고 되어있습니다. 이 의미는 `Windows` 에서 사용 가능한 `DPC Routines` 를 의미합니다.

```
// 예외 핸들러를 이용한 호출 방식
ExpTimerDpcRoutine
IopTimerDispatch
IopIrpStackProfilerTimer
PopThermalZoneDpc
CmpEnableLazyFlushDpcRoutine
CmpLazyFlushDpcRoutine
KiBalanceSetManagerDeferredRoutine
ExpTimeRefreshDpcRoutine
ExpTimeZoneDpcRoutine
ExpCenturyDpcRoutine

// 예외 핸들러를 이용하지 않는 방식
KiTimerDispatch(임의의 풀에 할당)
KiDpcDispatch(PGContext 내에 할당)
```

예외 핸들러를 이용하는 10 개의 DPC 루틴은 일반적인 시스템 DPC 루틴이지만, 비정규 주소(`Non-Canonical Address`)를 가진 `DeferredContext(DPC Routine에 사용되는 파라미터)`를 전달 받으면 해당하는 `KiCustomAccessRoutine` 함수를 호출합니다. `Windows 10, 1909` 기준으로 10개의 `KiCustomAccessRoutine` 이 존재합니다.

아래는 해당하는 `KiCustomAccessRoutine` 입니다.

```
ExpTimerDpcRoutine
- KiCustomAccessRoutine0 (+ FsRtlTruncateSmallMcb)

IopTimerDispatch
- KiCustomAccessRoutine1

IopIrpStackProfilerTimer
- KiCustomAccessRoutine2

PopThermalZoneDpc
- KiCustomAccessRoutine3

CmpEnableLazyFlushDpcRoutine
- KiCustomAccessRoutine4

CmpLazyFlushDpcRoutine
- KiCustomAccessRoutine5

KiBalanceSetManagerDeferredRoutine
- KiCustomAccessRoutine6

ExpTimeRefreshDpcRoutine
- KiCustomAccessRoutine7

ExpTimeZoneDpcRoutine
- KiCustomAccessRoutine8

ExpCenturyDpcRoutine
- KiCustomAccessRoutine9
```

### [-] 2nd Parameter

두 번째 파라미터는 `KiInitializePatchGuard` 내에서 생성된 DPC 오브젝트를 실행하는데 사용되는 방식을 의미하는 열거된 형태의 값입니다.

```
KeSetCoalescableTimer = 0,
Prcb.AcpiReserved = 1,
Prcb.HalReserved = 2,
PsCreateSystemThread = 3,
KeInsertQueueApc = 4,
KiBalanceSetManagerPeriodicDpc = 5
```

문서 내 해당 메소드 별 내용이 존재하지만 현재는 내가 이해하지 못했으므로 작성하지 않았습니다.

### [-] 3rd Parameter

알 수 없는 값으로 1 또는 2를 가집니다. 다만 해당 파라미터를  `idiv` 명령으로 어떤 의미있는 데이터로 변환합니다.

### [-] 4th Parameter

`KI_FILTER_FIBER_PARAM` 구조체를 의미합니다. 해당 구조체는 `KiFilterFiberContext` 을 호출하는 다양한 방법 중 `ExpLicenseWatchInitWorker` 에 의해 호출될 때 전달되는 작은 구조체 입니다.

### [-] 5th Parameter

NT 커널 함수 체크섬을 다시 계산해야 하는가에 대한 여부를 나타내는 `Boolean` 형 값입니다.

두 번째 파라미터에서 해당하는 메소드를 설명하지 않는 이유는 아래와 같습니다.

현재 디버깅 중인 내용을 봤을 때, 메소드는 `PsCreateSystemThread` 를 사용하게 됩니다. 문서를 확인했을 때 해당하는 메소드는 반드시 `KI_FILTER_FIBER_PARAM` 구조를 전달받아야 한다고 되어 있지만, 실제 디버깅 중인 4번째 파라미터는 0의 값을 가지고 있기 때문입니다.

다른 메소드가 추가되었을 수 있기 때문에 불확실한 정보는 전달하지 않겠습니다.

먼저 디버깅 시 확인한 파라미터에서 DPC 루틴의 인덱스를 의미한다는 첫 번째 파라미터가 `9`로 확인되었습니다.

```
MEMORY:FFFFF8030B9E92B3 mov     eax, [rsp+2470h]                ; Get first param
MEMORY:FFFFF8030B9E92BA mov     edx, 5
MEMORY:FFFFF8030B9E92BF cmp     eax, edx
MEMORY:FFFFF8030B9E92C1 jbe     loc_FFFFF8030B9E998F
MEMORY:FFFFF8030B9E92C7 lea     rdi, KiTimerDispatch
MEMORY:FFFFF8030B9E92CE
MEMORY:FFFFF8030B9E92CE loc_FFFFF8030B9E92CE:                   ; CODE XREF: KiInitializePatchGuard+16AD3↓j
MEMORY:FFFFF8030B9E92CE cmp     eax, 6
MEMORY:FFFFF8030B9E92D1 jz      loc_FFFFF8030B9E9D65
MEMORY:FFFFF8030B9E92D7 cmp     eax, 7
MEMORY:FFFFF8030B9E92DA jz      loc_FFFFF8030B9E9D57
MEMORY:FFFFF8030B9E92E0 cmp     eax, 8
MEMORY:FFFFF8030B9E92E3 jz      loc_FFFFF8030B9E9D49
MEMORY:FFFFF8030B9E92E9 cmp     eax, 9
MEMORY:FFFFF8030B9E92EC jz      loc_FFFFF8030B9E9D3B    ; <= this

loc_FFFFF8030B9E998F:
MEMORY:FFFFF8030B9E998F jz      loc_FFFFF8030B9E9DA6
MEMORY:FFFFF8030B9E9995 test    eax, eax
MEMORY:FFFFF8030B9E9997 jz      loc_FFFFF8030B9E9D98
MEMORY:FFFFF8030B9E999D sub     eax, 1
MEMORY:FFFFF8030B9E99A0 jz      loc_FFFFF8030B9E9D8A
MEMORY:FFFFF8030B9E99A6 sub     eax, 1
MEMORY:FFFFF8030B9E99A9 jz      loc_FFFFF8030B9E9D7C
MEMORY:FFFFF8030B9E99AF cmp     eax, 1
MEMORY:FFFFF8030B9E99B2 jz      loc_FFFFF8030B9E9D6E
MEMORY:FFFFF8030B9E99B8 lea     rcx, ExpCenturyDpcRoutine
MEMORY:FFFFF8030B9E99BF mov     eax, offset unk_FB006943
MEMORY:FFFFF8030B9E99C4 jmp     loc_FFFFF8030B9E9DB2

loc_FFFFF8030B9E9D3B:                ; <= this  
MEMORY:FFFFF8030B9E9D3B lea     rcx, PopThermalZoneDpc
MEMORY:FFFFF8030B9E9D42 mov     eax, offset unk_80007078
MEMORY:FFFFF8030B9E9D47 jmp     short loc_FFFFF8030B9E9DB2
```

먼저 첫 번째 파라미터를 가져와 5보다 작은 경우 `sub` 명령을 이용해 비교하여 특정 루틴들로 이동하여 해당하는 루틴을 가져옵니다.

현재에 해당하는 `9` 의 경우 `PopThermalZoneDpc` 루틴을 이용하는 걸로 확인됩니다. 해당 코드를 토대로 인덱스는 다음과 같습니다.

```
CmpEnableLazyFlushDpcRoutine = 0
CmpLazyFlushDpcRoutine = 1
ExpTimeRefreshDpcRoutine = 2
ExpTimeZoneDpcRoutine = 3 
ExpCenturyDpcRoutine = 4
ExpTimerDpcRoutine = 5
IopTimerDispatch = 6
IopIrpStackProfilerTimer = 7
KiBalanceSetManagerDeferredRoutine = 8
PopThermalZoneDpc = 9
```

(작성 중)