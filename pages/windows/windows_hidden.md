---
title: Find Hidden Process
keywords: documentation, technique, reversing, kernel, windows
date: 2021-02-03
tags: [Windows, Reversing, Vulnerability, Kernel]
summary: "Find Hidden Process "
sidebar: windows_sidebar
permalink: windows_hidden.html
folder: windows
---

## [0x00] Overview

최근에 `ActiveProcessLinks` 의 링크를 변조하는 것 보다 더 골치아픈 프로세스 숨기기 기법을 확인했습니다. 아주 어려운 기법도 아니였습니다. 다만 `EPROCESS`의 `ImageFileName` 을 변조하고, `PEB` 내 커맨드라인과 경로를 모두 바꿔버리는 경우입니다.

나는 이를 자동으로 탐지하고, 확인하고 싶었기에 프로세스 오브젝트를 이용하여 정확한 프로세스 정보를 가져오는 방법에 대해 연구했습니다.

RootKit 의 하나인 `HideToolz` 를 통해 프로세스 은닉 탐지에 대한 내용입니다.

{% include warning.html content="hidetoolz 샘플은 제공되지 않습니다. "%}

## [0x01] Environment

실행 환경은 다음과 같습니다.

```
Guest OS : Windows 7, 6.1(7601 Service pack 1)
```

다음과 같은 전제 조건이 존재합니다.

```
1. 부트 레벨에서 동작하지 않는다.
2. 프로세스는 이미 은닉되어 있거나 속이고 있다.
(즉, 각종 프로세스 모니터 도구에서 출력되는 정보를 신뢰할 수 없습니다.)
```

## [0x02] Analysis(HideToolz)

먼저 제작한 정적 분석 도구를 통해 해당 `hidetoolz` 바이너리를 열어보면 숨겨져 있는 이미지가 존재하는 것을 확인할 수 있습니다.(해당 도구가 아니라도 `HxD` 와 같은 바이너리 편집 도구로 확인 가능합니다.)

[<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/hidden_00.png?raw=true">

분석 대상 드라이버는 숨겨진 파일 중 가장 큰(320kb) 파일로 정보는 아래와 같습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/hidden_01.png?raw=true">

마찬가지로 파일이 숨겨져있지만, 해당 파일은 87kb의 같은 파일입니다.

파일명을 `HideToolz.sys` 로 변경하여 분석을 진행하겠습니다.

### [-] DriverEntry

VMP로 패킹되어 있지만, `IRP_MJ_DEVICE_CONTROL` 루틴을 제외하고는 분석이 쉽게 가능합니다. 다음은 `IDA` 를 이용하여 헥스레이 사용 후 네이밍 한 의사 코드입니다.

```cpp
NTSTATUS __stdcall DriverEntry(_DRIVER_OBJECT *DriverObject, PUNICODE_STRING RegistryPath)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  DriverObject->DriverUnload = DriverUnload;
  if ( KdDebuggerEnabled )                      // Anti Kernel Debugging
    KdDisableDebugger();
  result = GetTargetVersion();
  if ( result >= 0 )
  {
    result = CreateSymbolicLink(L"\\\\??\\\\HideToolz");
    if ( result < 0 )
    {
      P = sub_140002E9C(RegistryPath);
      if ( P && (Driver = DriverObject, CreateDevice(DriverObject) >= 0) )
      {
        if ( DriverObject->DeviceObject )
        {
          DriverObject->MajorFunction[0] = Dummy;// IRP_MJ_CREATE
          DriverObject->MajorFunction[14] = DeviceControl;// IRP_MJ_DEVICE_CONTROL
          DriverObject->MajorFunction[2] = Dummy;// IRP_MJ_CLOSE
        }
        sub_1400093B4();
        RxInitializeTopLevelIrpPackage();
        *(DriverObject->DriverSection + 0x1A) |= 0x20u;
        IoRegisterDriverReinitialization(DriverObject, DriverReinitializationRoutine, 0i64);
        result = 0;
      }
      else
      {
        result = -1073741823;
      }
    }
  }
  return result;
}
```

`KdDebuggerEnabled` 를 이용하여 커널 디버깅 여부를 확인하고, `KdDisableDebugger` 를 호출하여 디버깅이 불가능하도록 합니다. 물론 이 부분은 [Anti Kernel Debugging](<https://shhoya.github.io/antikernel_ctrldebugger.html>)에서 다룬 내용입니다. 간단히 우회하여 디버깅할 수 있습니다.

```cpp
DriverObject->MajorFunction[0] = Dummy;// IRP_MJ_CREATE
DriverObject->MajorFunction[14] = DeviceControl;// IRP_MJ_DEVICE_CONTROL
DriverObject->MajorFunction[2] = Dummy;// IRP_MJ_CLOSE
```

위의 내용으로 유저모드 애플리케이션과 통신할 함수를 바로 확인하면 좋겠지만, 해당 함수는 가상화가 적용되어 분석이 어렵습니다.

그렇기에 나는 해당 루틴을 분석하기 위해 `GetTargetVersion(pseudo)` 을 확인하기로 했습니다.

### [-] GetTargetVersion

```cpp
NTSTATUS __stdcall GetTargetVersion()
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  MajorVersion = 0;
  MinorVersion = 0;
  BuildNumber = 0;
  PsGetVersion(&MajorVersion, &MinorVersion, &BuildNumber, 0i64);
  if ( MajorVersion == 6 )
  {
    switch ( MinorVersion )
    {
      case 1u:
        if ( BuildNumber == 7601 )
        {
          dwTargetVersion = 0x3AE62A4;
          return 0;
        }
        v0 = BuildNumber == 7600;
        v1 = 0x1814;
        v2 = 0x3AE6240;
        goto LABEL_6;
      case 2u:
        v0 = BuildNumber == 9200;
        v1 = 0x1878;
        v2 = 0x3C01580;
        goto LABEL_6;
      case 3u:
        v0 = BuildNumber == 9600;
        v1 = 6364;
        v2 = 63960064;
LABEL_6:
        if ( v0 )
          v1 = v2;
        goto LABEL_25;
    }
  }
  else if ( MajorVersion == 10 && !MinorVersion )
  {
    switch ( BuildNumber )
    {
      case 10240u:
        dwTargetVersion = 0x3BAA6A40;
        return 0;
      case 10586u:
        dwTargetVersion = 0x3BAAF168;
        return 0;
      case 14393u:
        dwTargetVersion = 0x3BB0C084;
        return 0;
      case 15063u:
        dwTargetVersion = 0x3BB1C63C;
        return 0;
    }
    v1 = 10064;
    if ( BuildNumber == 16299 )
      v1 = 1001629964;
LABEL_25:
    dwTargetVersion = v1;
    return 0;
  }
  dwTargetVersion = BuildNumber;
  return 0xC0000001;
```

정확히 `Windows 10 RS3(16299)` 까지 지원하는 것으로 보입니다. 각 빌드 버전에 따라 `dwTargetVersion` 변수에 특정 값을 저장하는 것을 확인할 수 있습니다.

해당 변수는 전역변수로 사용되며 이를 통해 특정 행위에 대한 분기가 일어날 것이라 짐작할 수 있습니다.

다음은 해당 전역변수(`dwTargetVersion`)가 참조되는 주소들 입니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/hidden_02.png?raw=true">

네이밍 되어 있지 않은 세 개의 함수(`sub_1400093B4`, `sub_1400097B8`, `sub_14000AA5C`)에서 참조되는 것을 확인할 수 있습니다.

### [-] sub_1400093B4(GetSeAuditInfoOffset)

함수가 굉장히 크지만 중요한 부분만 확인해보겠습니다.

```cpp
__int64 sub_1400093B4()
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  RtlInitUnicodeString(&DestinationString, L"ObGetFilterVersion");
  OsGetFilterVersion = MmGetSystemRoutineAddress(&DestinationString);
  RtlInitUnicodeString(&DestinationString, L"ObRegisterCallbacks");
  *ObRegisterCallbacks = MmGetSystemRoutineAddress(&DestinationString);
  RtlInitUnicodeString(&DestinationString, L"ObUnRegisterCallbacks");
  *ObUnRegisterCallbacks = MmGetSystemRoutineAddress(&DestinationString);
  RtlInitUnicodeString(&DestinationString, L"PsReferenceProcessFilePointer");
  PsReferenceProcessFilePointer = MmGetSystemRoutineAddress(&DestinationString);
//...
//생략
//...
  result = dwTargetVersion;
  if ( dwTargetVersion <= 0x3C01580 )
  {
    if ( dwTargetVersion != 0x3C01580 )
    {
      result = (dwTargetVersion - 0x1814);
      if ( dwTargetVersion == 0x1814 )
      {
LABEL_21:
        qword_140031C80 = 0x390i64;
        return result;
      }
      result = (dwTargetVersion - 0x1878);
      if ( dwTargetVersion != 0x1878 )
      {
        result = (dwTargetVersion - 0x18DC);
        if ( dwTargetVersion != 0x18DC )
        {
          result = (dwTargetVersion - 0x2750);
          if ( dwTargetVersion != 0x2750 )
          {
            result = (dwTargetVersion - 0x3AE6240);
            if ( dwTargetVersion == 0x3AE6240 || dwTargetVersion == 0x3AE62A4 )
              goto LABEL_21;
            return result;
          }
LABEL_28:
          qword_140031C80 = 0x468i64;
          qword_140031C88 = 0x448i64;
          return result;
        }
      }
    }
LABEL_30:
    qword_140031C80 = 0x450i64;
    return result;
  }
  switch ( dwTargetVersion )
  {
    case 0x3CFF400:
      goto LABEL_30;
    case 0x3BAA6A40:
      qword_140031C80 = 0x460i64;
      return result;
    case 0x3BAAF168:
    case 0x3BB0C084:
    case 0x3BB1C63C:
    case 0x3BB3A90C:
      goto LABEL_28;
  }
  return result;
}
```

보통 커널 드라이버에서 OS build 버전을 확인하는 경우, 오프셋을 설정하기 위함이 주 목적이 될 때가 많습니다. 이 경우도 마찬가지입니다.

우리는 `Windows 7, 6.1(7601)` 으로, `dwTargetVersion` 은 `0x3AE62A4` 입니다. `qword_140031C80` 전역 변수에 `0x390` 값을 저장하는 것을 확인할 수 있습니다.

현재 루틴에서 `qword_140031C80` 변수에는 다음과 같이 값을 저장하고 있습니다.

```cpp
qword_140031C80 = 0x390i64;
qword_140031C80 = 0x468i64;
qword_140031C88 = 0x448i64;
qword_140031C80 = 0x460i64;
```

[Geoff Chappell](<https://www.geoffchappell.com/studies/windows/km/ntoskrnl/inc/ntos/ps/eprocess/index.htm>) 내 `EPROCESS` 오프셋 정보를 확인하면 해당 오프셋이 버전별 `EPROCESS.SeAuditProcessCreationInfo` 를 가리키고 있음을 확인할 수 있습니다.

```cpp
kd> dt nt!_EPROCESS fffffa80313b3880 Se*
   +0x1e0 SessionProcessLinks : _LIST_ENTRY [ 0xfffffa80`31658ce0 - 0xfffffa80`330face0 ]
   +0x268 SectionObject : 0xfffff8a0`0264c060 Void
   +0x270 SectionBaseAddress : 0x00000000`ffd10000 Void
   +0x2d8 Session : 0xfffff880`04b9a000 Void
   +0x318 SecurityPort : (null) 
   +0x390 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO
   +0x440 SetTimerResolution : 0y0
   +0x440 SetTimerResolutionLink : 0y0
   +0x4d0 SequenceNumber : 0x49
   +0x4e8 SecurityDomain : 0x00000001`00000025

kd> dt nt!_EPROCESS fffffa80313b3880 SeAuditProcessCreationInfo
   +0x390 SeAuditProcessCreationInfo : _SE_AUDIT_PROCESS_CREATION_INFO

kd> dx -id 0,0,fffffa8030f28040 -r1 (*((ntkrnlmp!_SE_AUDIT_PROCESS_CREATION_INFO *)0xfffffa80313b3c10))
(*((ntkrnlmp!_SE_AUDIT_PROCESS_CREATION_INFO *)0xfffffa80313b3c10))                 [Type: _SE_AUDIT_PROCESS_CREATION_INFO]
    [+0x000] ImageFileName    : 0xfffffa8031581d30 [Type: _OBJECT_NAME_INFORMATION *]

kd> dx -r1 ((ntkrnlmp!_OBJECT_NAME_INFORMATION *)0xfffffa8031581d30)
((ntkrnlmp!_OBJECT_NAME_INFORMATION *)0xfffffa8031581d30)                 : 0xfffffa8031581d30 [Type: _OBJECT_NAME_INFORMATION *]
    [+0x000] Name             : "\\Device\\HarddiskVolume2\\Windows\\System32\\notepad.exe" [Type: _UNICODE_STRING]
```

해당 함수명을 `GetSeAuditInfoOffset` 으로 명명하였습니다.

### [-] sub_1400097B8(GetActiveLinkOffset)

```cpp
__int64 GetActiveLinkOffset()
{
  __int64 v0; // rcx

  v0 = 0i64;
  if ( dwTargetVersion > 0x3CFF400 )
  {
    if ( dwTargetVersion == 0x3BAA6A40 || dwTargetVersion == 0x3BAAF168 || dwTargetVersion == 0x3BB0C084 )
      return 0x2F0i64;
    if ( dwTargetVersion != 0x3BB1C63C && dwTargetVersion != 0x3BB3A90C )
      return v0;
    return 0x2E8i64;
  }
  switch ( dwTargetVersion )
  {
    case 0x3CFF400:
      return 0x2E8i64;
    case 0x1814:
      return 0x188i64;
    case 0x18DC:
      return 0x2E8i64;
    case 0x2750:
      return 0x2F0i64;
    case 0x3AE6240:
    case 0x3AE62A4:
      return 0x188i64;
  }
  return v0;
}
```

짧은 코드입니다. 이 부분은 `EPROCESS` 구조체를 자주 본 사람이라면 쉽게 알 수 있습니다. 바로 `EPROCESS.ActiveProcessLinks` 의 오프셋을 의미합니다. `HideToolz` 는 프로세스 은닉 기능이 존재합니다. 아마 이 루틴을 참조하는 부분이 `DKOM` 을 수행하는 루틴 중 하나일 것입니다.

### [-] sub_14000AA5C(UnlinkProcess)

```cpp
__int64 __fastcall UnlinkProcess(HANDLE ProcessId)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

  Process = 0i64;
  offset = dwActiveLinkOffset;
  pid = ProcessId;
  if ( !dwActiveLinkOffset )
  {
    offset = GetActiveLinkOffset();
    dwActiveLinkOffset = offset;
  }
  if ( pid <= 4 || !offset || dwTargetVersion != 0x1814 && dwTargetVersion != 0x3AE6240 && dwTargetVersion != 0x3AE62A4 )
    return 0xC0000001i64;
  result = sub_1400038A4();
  if ( result >= 0 )
  {
    status = PsLookupProcessByProcessId(pid, &Process);
    if ( status < 0 )
    {
      status = 0xC0000001;
    }
    else
    {
      obProcess = Process;
      if ( Process != PsInitialSystemProcess )
      {
        ProcessLink = (Process + dwActiveLinkOffset);
        bakIrql = KeGetCurrentIrql();
        __writecr8(2ui64);
        Flink = ProcessLink->Flink;
        Blink = ProcessLink->Blink;
        if ( ProcessLink->Flink->Blink != ProcessLink || Blink->Flink != ProcessLink )
          __fastfail(3u);
        Blink->Flink = Flink;
        Flink->Blink = Blink;
        ProcessLink->Blink = ProcessLink;
        ProcessLink->Flink = ProcessLink;
        __writecr8(bakIrql);
        obProcess = Process;
      }
      ObfDereferenceObject(obProcess);
    }
    result = status;
  }
  return result;
}
```

`DKOM` 기법 이용하여, 프로세스 연결 리스트를 변조하는 것을 확인할 수 있습니다.

## [0x03] Behavior Analysis

실제로 동작하는 내용을 확인하면서 특이한 점이 있었습니다. 또한 이 때문에 꽤 피곤했습니다.

먼저 문제가 된 부분은 다음과 같습니다.

```cpp
if ( !dwActiveLinkOffset )
  {
    offset = GetActiveLinkOffset();
    dwActiveLinkOffset = offset;
  }
if ( pid <= 4 || !offset || dwTargetVersion != 0x1814 && dwTargetVersion != 0x3AE6240 && dwTargetVersion != 0x3AE62A4 )
    return 0xC0000001i64;
```

`ActiveProcessLinks` 오프셋을 구하지 못하는 경우 다른 방식으로 프로세스를 은닉합니다. 은닉이라기 보단 속임수에 가까웠습니다.

### [-] Normal

먼저 `HideToolz` 의 프로세스 은닉 기능을 사용하기 전 프로세스의 링크 상태 입니다.

```
kd> dt_EPROCESS fffffa8032de8b00 ActiveProcessLinks
nt!_EPROCESS
   +0x188 ActiveProcessLinks : _LIST_ENTRY [ 0xfffff800`0306f940 - 0xfffffa80`3129e9f8 ]

kd> dx -id 0,0,fffffa8030f2a040 -r1 (*((ntkrnlmp!_LIST_ENTRY *)0xfffffa8032de8c88))
(*((ntkrnlmp!_LIST_ENTRY *)0xfffffa8032de8c88))                 [Type: _LIST_ENTRY]
    [+0x000] Flink            : 0xfffff8000306f940 [Type: _LIST_ENTRY *]
    [+0x008] Blink            : 0xfffffa803129e9f8 [Type: _LIST_ENTRY *]
```

은닉 시도 후 아래와 같이 프로세스를 찾을 수 없게 된 것을 확인할 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/hidden_03.png?raw=true">

당연히 다음과 같이 프로세스 연결 리스트가 모두 자기 자신을 가리키도록 변조된 것도 확인 가능합니다.

```
kd> dx -id 0,0,fffffa8030f2a040 -r1 (*((ntkrnlmp!_LIST_ENTRY *)0xfffffa8032de8c88))
(*((ntkrnlmp!_LIST_ENTRY *)0xfffffa8032de8c88))                 [Type: _LIST_ENTRY]
    [+0x000] Flink            : 0xfffffa8032de8c88 [Type: _LIST_ENTRY *]
    [+0x008] Blink            : 0xfffffa8032de8c88 [Type: _LIST_ENTRY *]
```

### [-] Abnormal

해당 부분은 아무런 문제가 되지 않습니다. 잘 알려진 기법인 만큼 탐지할 수 있는 방법도 많이 알려져 있습니다. 다만 다음의 상황은 조금 달랐습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/hidden_04.png?raw=true">

위의 그림을 설명하자면, `ActiveProcessLinks` 의 오프셋을 찾지 못하는 경우 프로세스 은닉의 대안으로 프로세스의 이름을 부모 프로세스인 `explorer.exe` 변경하였습니다.

더욱 재밌는 점은 꽤나 깊은 파일 명을 변조한다는 것 입니다.

확인한 내용은 아래와 같습니다.

```
EPROCESS.ImageFileName
EPROCESS.SeAuditProcessCreationInfo
Peb.CommandLine
Peb.ImagePathName
```

{% include note.html content="물론 백신과 같은 동작들은 쉽게 파악할 수 있습니다. 다만 안티-치트와 같이 게임이라는 한정적인 동작에서도 쉽게 찾을 것이라 보장할 수 없습니다."%}

## [0x04] How to find the real process name

`HideToolz` 라는 루트킷을 대상으로 프로세스 은닉 및 속임수를 탐지하는 방법에 대해 연구하였습니다.  중국의 사자성어에는 이이제이 라는 말이 있습니다. 영어권에서 비슷하게 Divide and rule 이란 말이 있다고 합니다.

이 말을 한 이유는, 최근까지도 꾸준히 업데이트 하고 있는 `WKE(Windows Kernel Explorer)` 에서 힌트를 얻었기 때문입니다.

파일 이름을 얻는 방법은 여러가지가 있습니다. `FILE_OBJECT` 를 이용하여 `IoQueryNameString` 과 같은 심볼 함수를 이용하는 방법, `NtQueryInformationProcess` 등이 있지만 변조의 위험이 있으며, `HideToolz` 에서는 이를 허용하지 않습니다.

먼저 `HideToolz` 의 `DKOM` 에 의한 은닉된 프로세스를 탐지하는 방법을 확인해보겠습니다.

### [-] How WKE Find Process

아래와 같이 `WKE` 에서 프로세스 목록을 확인할 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/hidden_05.png?raw=true">

현재 보이지 않지만, `HideToolz` 가 두 가지 방식(DKOM, Fake) 모두 탐지하고 있습니다.

이에 대해 어떻게 탐지하는지 직접 `WKE` 드라이버를 분석하였고 중요한 정보를 얻었습니다.

다음은 분석 중 프로세스 정보를 가져오는 루틴 중 일부입니다.

```c
_FILE_OBJECT *__fastcall InternalFileName(_FILE_OBJECT *pFilePointer)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]
  v9 = 0;
  v10 = 0;
  v8 = 8;
  v12 = 0i64;
  v11 = 0i64;
  v3 = 0i64;
  ObjAttr.Length = 0;
  memset(&ObjAttr.RootDirectory, 0, 0x28ui64);
  *v5 = 0i64;
  *&v5[8] = 0;
  *&v5[12] = 0;
  IoBlock.Information = 0i64;
  v4 = 0;
  IoBlock.Pointer = 0i64;
  if ( IoQueryFileInformation(pFilePointer, FileInternalInformation, 8u, &v9, &v8) >= 0
    && ObOpenObjectByPointer(pFilePointer->DeviceObject, 0x200u, 0i64, 0, 0i64, 0, &v12) >= 0 )
  {
    *&v5[6] = &v9;
    ObjAttr.RootDirectory = v12;
    ObjAttr.ObjectName = &v4;
    v4 = 8;
    *v5 = 8;
    ObjAttr.Length = 0x30;
    ObjAttr.Attributes = 0x200;
    ObjAttr.SecurityDescriptor = 0i64;
    ObjAttr.SecurityQualityOfService = 0i64;
    if ( IoCreateFile(
           &v11,
           0x80000000,
           &ObjAttr,
           &IoBlock,
           0i64,
           0x80u,
           7u,
           1u,
           0x2040u,
           0i64,
           0,
           CreateFileTypeNone,
           0i64,
           0x100u) >= 0 )
    {
      if ( ObReferenceObjectByHandle(v11, 0x81u, *IoFileObjectType, 0, &v3, 0i64) >= 0 )
        pFilePointer = v3;
      ZwClose(v11);
    }
    ZwClose(v12);
  }
  return pFilePointer;
```

`IoQueryFileInformation` 존재에 대해 알게되었고, 이 때 전달하는 `FileInterInformation` 클래스는 파일 오브젝트의 파일시스템 인덱스 번호를 질의합니다.

이에 대해 조사하다가 `Sysinternals` 의 `FindLinks` 가 떠올랐습니다. `NTFS` 에서 파일 인덱스와 링크 개수와 링킹 파일을 나열해주는 툴입니다.

그리고 찾았습니다.

```powershell
PS C:\\Users\\hunho\\Desktop\\Shh0ya\\02_Tools\\02_reversing\\SysinternalsSuite> .\\FindLinks.exe c:\\windows\\system32\\notepad.exe

Findlinks v1.1 - Locate file hard links
Copyright (C) 2011-2016 Mark Russinovich
Sysinternals - www.sysinternals.com

c:\\windows\\system32\\notepad.exe
        Index:  0x00120688
        Links:  2

Linking files:
c:\\Windows\\WinSxS\\amd64_microsoft-windows-notepad_31bf3856ad364e35_10.0.19041.746_none_4d13d847cecf0038\\notepad.exe
c:\\Windows\\notepad.exe
```

`WKE` 에서 프로세스 경로를 확인하면 `WinSxS` 가 존재하는 것을 알 수 있습니다. `Windows Side By Side` 로 발음되며 업데이트 시 호환성을 위해 이전 버전으로 복원해야 하는 경우를 위해 보관됩니다.

즉 `WKE` 는 확실한 프로세스의 경로 및 이름을 얻기 위해 파일 시스템의 인덱스를 이용하여 링크 이름을 가져오는 것을 알 수 있었습니다.

### [-] Find Hidden Process

아래는 직접 개발한 `Detective` 의 일부 소스코드 입니다.

{% include note.html content="HideToolz 의 프로세스 은닉 기법을 탐지하기 위한 커널 드라이버 입니다. 알고리즘은 마지막에 다루겠습니다."%}

```c
VOID FindDkomProcess(PFUNCTION_POINTER pFunction, ULONG Count)
{
	ULONG LinkOffset = GetProcessLinkOffset();
	PLIST_ENTRY ActiveLinks = { 0, };
	if (!LinkOffset)
	{
		ErrLog("Not found ActiveProcessLinks\\n");
		return;
	}
	for (int i = 0; i < Count; i++)
	{
		if (!pFunction->PsGetProcessExitProcessCalled(pDetectData[i].Process))
		{
			ActiveLinks = *(PHANDLE)((PCHAR)pDetectData[i].Process + LinkOffset);
			if (ActiveLinks->Flink == ActiveLinks->Blink)
			{
				Log("[DETECTIVE] Detect hidden process : %d(%s)\\n", pDetectData[i].ProcessId,pFunction->PsGetProcessImageFileName(pDetectData[i].Process));
			}
		}
	}
}
```

`DKOM` 기법에 대해서는 많이 알려져 있으므로 자세한 설명은 생략하겠습니다.

### [-] Find Fake Process

약간 긴 소스지만 이해하는데 문제가 없을꺼라 생각합니다.

```c
VOID FindFakeProcess(PFUNCTION_POINTER pFunction, ULONG Count)
{
	PFILE_OBJECT				        pFilePointer = NULL;
	FILE_INTERNAL_INFORMATION	  FileIdInfo = { 0, };
	FILE_LINKS_INFORMATION		  FileLinkInfo = { 0, };
	RDEF_FILE_NAME_INFORMATION	FileNameInfo = { 0, };
	ULONG ReturnLength = 0;
	HANDLE hDevice = NULL;

	for (int i = 0; i < Count; i++)
	{
		if (pFunction->PsGetProcessExitProcessCalled(pDetectData[i].Process))
		{
			ErrLog("Terminate Process : %s\\n", pFunction->PsGetProcessImageFileName(pDetectData[i].Process));
			continue;
		}
		else
		{
			if (NT_SUCCESS(pFunction->PsReferenceProcessFilePointer(pDetectData[i].Process, &pFilePointer)))
			{
				if (NT_SUCCESS(IoQueryFileInformation(pFilePointer, FileInternalInformation, sizeof(FileIdInfo), &FileIdInfo, &ReturnLength)) &&
					NT_SUCCESS(ObOpenObjectByPointer(pFilePointer->DeviceObject, OBJ_KERNEL_HANDLE, NULL, 0, NULL, KernelMode, &hDevice)))
				{
					HANDLE hFile = NULL;
					OBJECT_ATTRIBUTES ObjAttr = { 0, };
					OBJECT_NAME_INFORMATION ObjName = { 0, };
					IO_STATUS_BLOCK ioOpenFile = { 0, };
					ObjName.Name.MaximumLength = ObjName.Name.Length = 8;
					ObjName.Name.Buffer = (PWSTR)&FileIdInfo.IndexNumber;
					InitializeObjectAttributes(&ObjAttr, &ObjName, OBJ_KERNEL_HANDLE, hDevice, NULL);

					if (NT_SUCCESS(ZwOpenFile(&hFile, GENERIC_READ, &ObjAttr, &ioOpenFile, FILE_SHARE_READ, FILE_OPEN_BY_FILE_ID | FILE_NON_DIRECTORY_FILE)))
					{
						IO_STATUS_BLOCK ioQueryFile = { 0, };

						NTSTATUS result = NtQueryInformationFile(hFile, &ioQueryFile, &FileLinkInfo, sizeof(RDEF_FILE_LINKS_INFORMATION), FileHardLinkInformation);
						if (NT_SUCCESS(result))
						{
							if (CompareFileName(pFunction, pDetectData[i].Process, FileLinkInfo.Entry.FileName))
							{
								memset(&FileNameInfo, 0, sizeof(RDEF_FILE_NAME_INFORMATION));
								result = NtQueryInformationFile(hFile, &ioQueryFile, &FileNameInfo, sizeof(RDEF_FILE_NAME_INFORMATION), FileNameInformation);
								if (NT_SUCCESS(result))
								{
									Log("[DETECTIVE] [%d] Original Path : C:%ws\\n", pDetectData[i].ProcessId, FileNameInfo.FileName);
								}
							}
						}
						ZwClose(hFile);
					}
					ZwClose(hDevice);
				}
				ObDereferenceObject(pFilePointer);
			}
			else
			{
				if (pDetectData[i].ProcessId == 4)
				{

				}
				else
				{
					ErrLog("Not Found File Object : %s\\n", pFunction->PsGetProcessImageFileName(pDetectData[i].Process));
				}
			}
		}
	}
}
```

위의 과정이 긴 이유는 `EPROCESS` 오브젝트만을 이용하여, 해당 오브젝트와 연결된 파일 오브젝트, 파일 핸들, 파일 인덱스(파일시스템), 파일 경로를 얻기 위함입니다.

## [0x05] PoC

다음은 `HideToolz` 를 이용하여 프로세스명 속임수와 프로세스 은닉을 탐지하는 내용입니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/hidden_06.gif?raw=true">

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/hidden_07.png?raw=true">

## [0x06] Conclusion

해당 탐지 알고리즘은 간략히 다음과 같습니다.

```
1. 모든 핸들 나열(Handle Table 이용)
2. 프로세스 핸들을 이용하여 프로세스 ID 획득
3. 프로세스 ID를 이용하여 프로세스 오브젝트(EPROCESS) 획득
4. 프로세스 오브젝트를 이용하여 파일 오브젝트 획득(PsReferenceProcessFilePointer)
5. 파일 오브젝트를 이용하여 파일 시스템 인덱스 획득(IoQueryFileInformation)
6. 파일 오브젝트를 이용하여 디바이스 핸들(DEVICE_OBJECT) 획득(ObOpenObjectByPointer)
7. OBJECT_ATTRIBUTE 초기화(Object Name = 파일 인덱스)
8. 파일 인덱스를 이용하여 파일 핸들 획득(ZwOpenFile)
9. 파일 핸들을 이용하여 파일 경로 및 하드 링크 정보 획득
```

이 외에도 수 많은 프로세스 은닉 기법 및 탐지 기법이 존재합니다.

다만 이러한 파일 시스템의 정보로 탐지하는 방법을 알게 되어 공유하게 되었습니다.

