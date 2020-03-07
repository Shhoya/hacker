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

- **KdPitchDebugger**

  `KdInitSystem` 함수에서 부팅 옵션에 따라 값이 설정됩니다. `/NODEBUG` 옵션의 경우 TRUE로 설정되고, 이 때 `KdEnableDebugger` 함수를 호출하면 디버그 모드가 아니므로 디버거 비활성화 오류 메시지를 반환합니다.

- **KdBlockEnable**

  마찬가지로 디버깅이 허용되어 있는지에 대한 확인을 하는 변수입니다. `KdChangeOption` 또는 `NtSystemDebugControl` 함수에 의해 설정이 가능하며, 이 값이 TRUE 인 경우 디버깅이 차단되어 있음을 의미하므로 접근 거부 오류를 반환하게 됩니다.

```c
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
```

`KdDisableCount` 변수의 값을 확인합니다. 디버그 모드에서 `KdDisableDebugger` 함수를 이용해 비활성화 시 값이 증가하는 스위치 플래그와 같은 기능을 합니다.

즉 디버그 모드에서 `KdDisableDebugger`를 통해 비활성화 하고, 다시 `KdEnableDebugger`로 활성화 시키면 동작하는 로직입니다. 

먼저 `KdDisableCount`를 `v4` 임시변수에 복사합니다. 값이 존재하는 경우 변수의 값을 감소시키고, `KdPreviouslyEnabed` 변수에 값이 존재하는지 확인합니다. `KdPreviouslyEnabled` 변수는 `KdDisableDebugger` 함수 호출 시, 기존의 `KdDebuggerEnabled` 변수의 값을 백업합니다. `Lock` 의 유무에 따라 특정 변수들의 값을 설정하거나 `KdInitSystem` 함수를 호출하는 것을 확인할 수 있습니다.

여기서 `Lock` 이 설정된 경우, `KdpDebugRoutineSelect`, `KdDebuggerEnabled`, `0xFFFFF780000002D4` 변수의 값이 1로 설정되는 것을 볼 수 있습니다.

이 때 `0xFFFFF780000002D4`  변수에 대한 설명은 아래와 같습니다.

### [-] KUSER_SHARED_DATA

`KUSER_SHARED_DATA` 구조체는 커널이 유저모드 소프트웨어와 공유하기 위해 미리 고정된 주소에 배치됩니다. 본래의 의도는 유저모드에서 커널 모드를 호출 할 때 오버헤드를 줄이기 위해 필요한 전역 변수나 시간 등을 확보하기 위한 것으로 보입니다.

고정된 주소는 x86의 경우 `0xFFDF0000`, x64의 경우 `0xFFFFF78000000000`  입니다. 구조체 정보는 아래와 같습니다.

```
3: kd> dt_KUSER_SHARED_DATA
ntdll!_KUSER_SHARED_DATA
   +0x000 TickCountLowDeprecated : Uint4B
   +0x004 TickCountMultiplier : Uint4B
   +0x008 InterruptTime    : _KSYSTEM_TIME
   +0x014 SystemTime       : _KSYSTEM_TIME
   +0x020 TimeZoneBias     : _KSYSTEM_TIME
   +0x02c ImageNumberLow   : Uint2B
   +0x02e ImageNumberHigh  : Uint2B
   +0x030 NtSystemRoot     : [260] Wchar
   +0x238 MaxStackTraceDepth : Uint4B
   +0x23c CryptoExponent   : Uint4B
   +0x240 TimeZoneId       : Uint4B
   +0x244 LargePageMinimum : Uint4B
   +0x248 AitSamplingValue : Uint4B
   +0x24c AppCompatFlag    : Uint4B
   +0x250 RNGSeedVersion   : Uint8B
   +0x258 GlobalValidationRunlevel : Uint4B
   +0x25c TimeZoneBiasStamp : Int4B
   +0x260 NtBuildNumber    : Uint4B
   +0x264 NtProductType    : _NT_PRODUCT_TYPE
   +0x268 ProductTypeIsValid : UChar
   +0x269 Reserved0        : [1] UChar
   +0x26a NativeProcessorArchitecture : Uint2B
   +0x26c NtMajorVersion   : Uint4B
   +0x270 NtMinorVersion   : Uint4B
   +0x274 ProcessorFeatures : [64] UChar
   +0x2b4 Reserved1        : Uint4B
   +0x2b8 Reserved3        : Uint4B
   +0x2bc TimeSlip         : Uint4B
   +0x2c0 AlternativeArchitecture : _ALTERNATIVE_ARCHITECTURE_TYPE
   +0x2c4 BootId           : Uint4B
   +0x2c8 SystemExpirationDate : _LARGE_INTEGER
   +0x2d0 SuiteMask        : Uint4B
   +0x2d4 KdDebuggerEnabled : UChar
   +0x2d5 MitigationPolicies : UChar
   +0x2d5 NXSupportPolicy  : Pos 0, 2 Bits
   +0x2d5 SEHValidationPolicy : Pos 2, 2 Bits
   +0x2d5 CurDirDevicesSkippedForDlls : Pos 4, 2 Bits
   +0x2d5 Reserved         : Pos 6, 2 Bits
   +0x2d6 Reserved6        : [2] UChar
   +0x2d8 ActiveConsoleId  : Uint4B
   +0x2dc DismountCount    : Uint4B
   +0x2e0 ComPlusPackage   : Uint4B
   +0x2e4 LastSystemRITEventTickCount : Uint4B
   +0x2e8 NumberOfPhysicalPages : Uint4B
   +0x2ec SafeBootMode     : UChar
   +0x2ed VirtualizationFlags : UChar
   +0x2ee Reserved12       : [2] UChar
   +0x2f0 SharedDataFlags  : Uint4B
   +0x2f0 DbgErrorPortPresent : Pos 0, 1 Bit
   +0x2f0 DbgElevationEnabled : Pos 1, 1 Bit
   +0x2f0 DbgVirtEnabled   : Pos 2, 1 Bit
   +0x2f0 DbgInstallerDetectEnabled : Pos 3, 1 Bit
   +0x2f0 DbgLkgEnabled    : Pos 4, 1 Bit
   +0x2f0 DbgDynProcessorEnabled : Pos 5, 1 Bit
   +0x2f0 DbgConsoleBrokerEnabled : Pos 6, 1 Bit
   +0x2f0 DbgSecureBootEnabled : Pos 7, 1 Bit
   +0x2f0 DbgMultiSessionSku : Pos 8, 1 Bit
   +0x2f0 DbgMultiUsersInSessionSku : Pos 9, 1 Bit
   +0x2f0 DbgStateSeparationEnabled : Pos 10, 1 Bit
   +0x2f0 SpareBits        : Pos 11, 21 Bits
   +0x2f4 DataFlagsPad     : [1] Uint4B
   +0x2f8 TestRetInstruction : Uint8B
   +0x300 QpcFrequency     : Int8B
   +0x308 SystemCall       : Uint4B
   +0x30c SystemCallPad0   : Uint4B
   +0x310 SystemCallPad    : [2] Uint8B
   +0x320 TickCount        : _KSYSTEM_TIME
   +0x320 TickCountQuad    : Uint8B
   +0x320 ReservedTickCountOverlay : [3] Uint4B
   +0x32c TickCountPad     : [1] Uint4B
   +0x330 Cookie           : Uint4B
   +0x334 CookiePad        : [1] Uint4B
   +0x338 ConsoleSessionForegroundProcessId : Int8B
   +0x340 TimeUpdateLock   : Uint8B
   +0x348 BaselineSystemTimeQpc : Uint8B
   +0x350 BaselineInterruptTimeQpc : Uint8B
   +0x358 QpcSystemTimeIncrement : Uint8B
   +0x360 QpcInterruptTimeIncrement : Uint8B
   +0x368 QpcSystemTimeIncrementShift : UChar
   +0x369 QpcInterruptTimeIncrementShift : UChar
   +0x36a UnparkedProcessorCount : Uint2B
   +0x36c EnclaveFeatureMask : [4] Uint4B
   +0x37c TelemetryCoverageRound : Uint4B
   +0x380 UserModeGlobalLogger : [16] Uint2B
   +0x3a0 ImageFileExecutionOptions : Uint4B
   +0x3a4 LangGenerationCount : Uint4B
   +0x3a8 Reserved4        : Uint8B
   +0x3b0 InterruptTimeBias : Uint8B
   +0x3b8 QpcBias          : Uint8B
   +0x3c0 ActiveProcessorCount : Uint4B
   +0x3c4 ActiveGroupCount : UChar
   +0x3c5 Reserved9        : UChar
   +0x3c6 QpcData          : Uint2B
   +0x3c6 QpcBypassEnabled : UChar
   +0x3c7 QpcShift         : UChar
   +0x3c8 TimeZoneBiasEffectiveStart : _LARGE_INTEGER
   +0x3d0 TimeZoneBiasEffectiveEnd : _LARGE_INTEGER
   +0x3d8 XState           : _XSTATE_CONFIGURATION
```



## [0x02] Conclusion

이번에는 `KdEnableDebugger(KdEnableDebuggerWithLock)` 함수에 대해 알아봤습니다. 전역변수들은 `WKE`와 같은 커널 드라이버 도구를 이용하여 조작을 해볼 수 있습니다. 하지만 블루 스크린을 각오하셔야 합니다. 마지막 챕터에서는 최대한 안전하게 운영체제를 속이는 방법에 대해 알 수 있습니다.



