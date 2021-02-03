---
title: Windows Handle Table & Object
keywords: documentation, technique, reversing, kernel, windows
date: 2021-02-04
tags: [Windows, Reversing, Vulnerability, Kernel]
summary: "Windows Handle Table & Object"
sidebar: windows_sidebar
permalink: windows_hwndobject.html
folder: windows
---

## [0x00] Overview

기본적으로 핸들에 대한 개념은 [위키](https://ko.wikipedia.org/wiki/핸들_(컴퓨팅)) 내 잘 서술되어 있습니다.

Windows 커널에서 핸들 테이블과 핸들, 오브젝트의 연관성 및 알고리즘에 대한 내용입니다.

`Windows 10, 20H2(19042.572)` 에서 테스트 되었습니다.

## [0x01] Windows Kernel Handle Table

`EPROCESS` 구조 내 `ObjectTable` 이라는 필드가 존재합니다. 이는 `HANDLE_TABLE` 구조로 이루어져 있습니다.

```
3: kd> !process 4 0 
Searching for Process with Cid == 4
PROCESS ffffd78d98c8f040
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001ad002  ObjectTable: ffff840e0ec8be00  HandleCount: 2342.
    Image: System

3: kd> dt_EPROCESS ffffd78d98c8f040 ObjectTable
ntdll!_EPROCESS
   +0x570 ObjectTable : 0xffff840e`0ec8be00 _HANDLE_TABLE

3: kd> dx -id 0,0,ffffd78d98c8f040 -r1 ((ntdll!_HANDLE_TABLE *)0xffff840e0ec8be00)
((ntdll!_HANDLE_TABLE *)0xffff840e0ec8be00)                 : 0xffff840e0ec8be00 [Type: _HANDLE_TABLE *]
    [+0x000] NextHandleNeedingPool : 0x3000 [Type: unsigned long]
    [+0x004] ExtraInfoPages   : 0 [Type: long]
    [+0x008] TableCode        : 0xffff840e120d7001 [Type: unsigned __int64]
    [+0x010] QuotaProcess     : 0x0 [Type: _EPROCESS *]
    [+0x018] HandleTableList  [Type: _LIST_ENTRY]
    [+0x028] UniqueProcessId  : 0x4 [Type: unsigned long]
    [+0x02c] Flags            : 0x0 [Type: unsigned long]
    [+0x02c ( 0: 0)] StrictFIFO       : 0x0 [Type: unsigned char]
    [+0x02c ( 1: 1)] EnableHandleExceptions : 0x0 [Type: unsigned char]
    [+0x02c ( 2: 2)] Rundown          : 0x0 [Type: unsigned char]
    [+0x02c ( 3: 3)] Duplicated       : 0x0 [Type: unsigned char]
    [+0x02c ( 4: 4)] RaiseUMExceptionOnInvalidHandleClose : 0x0 [Type: unsigned char]
    [+0x030] HandleContentionEvent [Type: _EX_PUSH_LOCK]
    [+0x038] HandleTableLock  [Type: _EX_PUSH_LOCK]
    [+0x040] FreeLists        [Type: _HANDLE_TABLE_FREE_LIST [1]]
    [+0x040] ActualEntry      [Type: unsigned char [32]]
    [+0x060] DebugInfo        : 0x0 [Type: _HANDLE_TRACE_DEBUG_INFO *]
```

간략히 `System` 프로세스를 대상으로 확인하였습니다. 그 이유는 익스포트 되지 않는 전역변수 `ObpKernelHandleTable` 때문입니다. `ObpKernelHandleTable` 은 바로 이 `System` 프로세스의 `ObjectTable`을 의미합니다.

```
0: kd> dt nt!_HANDLE_TABLE poi(ObpKernelHandleTable)
   +0x000 NextHandleNeedingPool : 0x3000
   +0x004 ExtraInfoPages   : 0n0
   +0x008 TableCode        : 0xffff840e`120d7001
   +0x010 QuotaProcess     : (null) 
   +0x018 HandleTableList  : _LIST_ENTRY [ 0xffff840e`0ec88dd8 - 0xfffff805`17f2db78 ]
   +0x028 UniqueProcessId  : 4
   +0x02c Flags            : 0
   +0x02c StrictFIFO       : 0y0
   +0x02c EnableHandleExceptions : 0y0
   +0x02c Rundown          : 0y0
   +0x02c Duplicated       : 0y0
   +0x02c RaiseUMExceptionOnInvalidHandleClose : 0y0
   +0x030 HandleContentionEvent : _EX_PUSH_LOCK
   +0x038 HandleTableLock  : _EX_PUSH_LOCK
   +0x040 FreeLists        : [1] _HANDLE_TABLE_FREE_LIST
   +0x040 ActualEntry      : [32]  ""
   +0x060 DebugInfo        : (null)
```

`ObpKernelHandleTable` 의 살펴보면 `ObInitSystem` 루틴에서 `ExCreateHandleTable` 을 통해 초기화 됩니다.

<img src="https://s3.us-west-2.amazonaws.com/secure.notion-static.com/c60f2908-718a-4e02-a665-4d2db534179c/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAT73L2G45O3KS52Y5%2F20210203%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20210203T174719Z&X-Amz-Expires=86400&X-Amz-Signature=8ffe8da03aa1fbceabff5b6facbbba7a15965c92729aa41246f829828848e725&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22">

즉, 커널 핸들 테이블의 기준이 `System` 프로세스의 `ObjectTable` 으로 이해할 수 있습니다. 또한 특이한 점은, `ObpKernelHandleTable`의 경우 `QuotaProcess` 가 비어있습니다. 그 외에는 모두 존재합니다.

해당 기준을 이용하여 `HandleTableList` 멤버를 통해 리스트 순회가 가능합니다.

```
0: kd> dx -r1 (*((ntdll!_LIST_ENTRY *)0xffff840e0ec8be18))
(*((ntdll!_LIST_ENTRY *)0xffff840e0ec8be18))                 [Type: _LIST_ENTRY]
    [+0x000] Flink            : 0xffff840e0ec88dd8 [Type: _LIST_ENTRY *]
    [+0x008] Blink            : 0xfffff80517f2db78 [Type: _LIST_ENTRY *]

0: kd> dt_HANDLE_TABLE 0xffff840e0ec88dd8-0x18
ntdll!_HANDLE_TABLE
   +0x000 NextHandleNeedingPool : 0x400
   +0x004 ExtraInfoPages   : 0n0
   +0x008 TableCode        : 0xffff840e`0ecb2000
   +0x010 QuotaProcess     : 0xffffd78d`98cb6080 _EPROCESS
   +0x018 HandleTableList  : _LIST_ENTRY [ 0xffff840e`0ffacd18 - 0xffff840e`0ec8be18 ]
   +0x028 UniqueProcessId  : 0x6c
   +0x02c Flags            : 0x10
   +0x02c StrictFIFO       : 0y0
   +0x02c EnableHandleExceptions : 0y0
   +0x02c Rundown          : 0y0
   +0x02c Duplicated       : 0y0
   +0x02c RaiseUMExceptionOnInvalidHandleClose : 0y1
   +0x030 HandleContentionEvent : _EX_PUSH_LOCK
   +0x038 HandleTableLock  : _EX_PUSH_LOCK
   +0x040 FreeLists        : [1] _HANDLE_TABLE_FREE_LIST
   +0x040 ActualEntry      : [32]  ""
   +0x060 DebugInfo        : (null) 

0: kd> dt_EPROCESS 0xffffd78d`98cb6080 ImageFileName
ntdll!_EPROCESS
   +0x5a8 ImageFileName : [15]  "Registry"
```

### [-] HANDLE_TABLE_ENTRY

`HANDLE_TABLE_ENTRY` 의 경우 시간이 걸렸습니다. 기존 인터넷 상에 존재하는 정보들은 모두 x86 기준이거나 최신 윈도우의 정보와 조금 다릅니다.

HANDLE_TABLE 내 `TableCode`는 `HANDLE_TABLE_ENTRY` 포인터입니다. 이 `TableCode` 를 아래와 같은 과정을 통해 연산하면 해당하는 핸들의 오브젝트를 구할 수 있습니다.

```
2: kd> !handle 4

PROCESS ffffb986186a7040
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001ad002  ObjectTable: ffff9d8573a8be00  HandleCount: 2378.
    Image: System

Kernel handle table at ffff9d8573a8be00 with 2378 entries in use

0004: Object: ffffb986186a7040  GrantedAccess: 001fffff (Protected) Entry: ffff9d8573a9e010
Object: ffffb986186a7040  Type: (ffffb986186c4e80) Process
    ObjectHeader: ffffb986186a7010 (new version)
        HandleCount: 6  PointerCount: 212365

2: kd> dt_HANDLE_TABLE ffff9d8573a8be00
ntdll!_HANDLE_TABLE
   +0x000 NextHandleNeedingPool : 0x3800
   +0x004 ExtraInfoPages   : 0n0
   +0x008 TableCode        : 0xffff9d85`73e61001
   +0x010 QuotaProcess     : (null) 
   +0x018 HandleTableList  : _LIST_ENTRY [ 0xffff9d85`73a88dd8 - 0xfffff805`0ff2db78 ]
   +0x028 UniqueProcessId  : 4
   +0x02c Flags            : 0
   +0x02c StrictFIFO       : 0y0
   +0x02c EnableHandleExceptions : 0y0
   +0x02c Rundown          : 0y0
   +0x02c Duplicated       : 0y0
   +0x02c RaiseUMExceptionOnInvalidHandleClose : 0y0
   +0x030 HandleContentionEvent : _EX_PUSH_LOCK
   +0x038 HandleTableLock  : _EX_PUSH_LOCK
   +0x040 FreeLists        : [1] _HANDLE_TABLE_FREE_LIST
   +0x040 ActualEntry      : [32]  ""
   +0x060 DebugInfo        : (null)

2: kd> dp poi(0xffff9d85`73e61001&0xfffffffffffffffc)
ffff9d85`73a9e000  00000000`00000000 00000000`00000000
ffff9d85`73a9e010  b986186a`7010ff4d 00000000`001fffff
ffff9d85`73a9e020  b986187c`b110fff5 00000000`001fffff
ffff9d85`73a9e030  9d857534`3de0fff3 00000000`000f0001
ffff9d85`73a9e040  b986186a`2890fe6f 00000000`001f0001
ffff9d85`73a9e050  9d8573a0`fad0fff3 00000000`000f000f
ffff9d85`73a9e060  9d8573a8`9880fd99 00000000`000f000f
ffff9d85`73a9e070  b9861869`c310fff3 00000000`001f0003

2: kd> dt_HANDLE_TABLE_ENTRY ffff9d85`73a9e010
ntdll!_HANDLE_TABLE_ENTRY
   +0x000 VolatileLowValue : 0n-5078344684387893427
   +0x000 LowValue         : 0n-5078344684387893427
   +0x000 InfoTable        : 0xb986186a`7010ff4d _HANDLE_TABLE_ENTRY_INFO
   +0x008 HighValue        : 0n2097151
   +0x008 NextFreeHandleEntry : 0x00000000`001fffff _HANDLE_TABLE_ENTRY
   +0x008 LeafHandleValue  : _EXHANDLE
   +0x000 RefCountField    : 0n-5078344684387893427
   +0x000 Unlocked         : 0y1
   +0x000 RefCnt           : 0y0111111110100110 (0x7fa6)
   +0x000 Attributes       : 0y000
   +0x000 ObjectPointerBits : 0y10111001100001100001100001101010011100000001 (0xb986186a701)
   +0x008 GrantedAccessBits : 0y0000111111111111111111111 (0x1fffff)
   +0x008 NoRightsUpgrade  : 0y0
   +0x008 Spare1           : 0y000000 (0)
   +0x00c Spare2           : 0

2: kd> ? (b986186a`7010ff4d>>>10)&fffffffffffffff0
Evaluate expression: -77489390325744 = ffffb986`186a7010

2: kd> dt_OBJECT_HEADER ffffb986`186a7010
nt!_OBJECT_HEADER
   +0x000 PointerCount     : 0n212365
   +0x008 HandleCount      : 0n6
   +0x008 NextToFree       : 0x00000000`00000006 Void
   +0x010 Lock             : _EX_PUSH_LOCK
   +0x018 TypeIndex        : 0x70 'p'
   +0x019 TraceFlags       : 0 ''
   +0x019 DbgRefTrace      : 0y0
   +0x019 DbgTracePermanent : 0y0
   +0x01a InfoMask         : 0 ''
   +0x01b Flags            : 0x2 ''
   +0x01b NewObject        : 0y0
   +0x01b KernelObject     : 0y1
   +0x01b KernelOnlyAccess : 0y0
   +0x01b ExclusiveObject  : 0y0
   +0x01b PermanentObject  : 0y0
   +0x01b DefaultSecurityQuota : 0y0
   +0x01b SingleHandleEntry : 0y0
   +0x01b DeletedInline    : 0y0
   +0x01c Reserved         : 0
   +0x020 ObjectCreateInfo : 0xfffff805`0fe53900 _OBJECT_CREATE_INFORMATION
   +0x020 QuotaBlockCharged : 0xfffff805`0fe53900 Void
   +0x028 SecurityDescriptor : 0xffff9d85`73a3ee61 Void
   +0x030 Body             : _QUAD

2: kd> !object ffffb986`186a7010+30
Object: ffffb986186a7040  Type: (ffffb986186c4e80) Process
    ObjectHeader: ffffb986186a7010 (new version)
    HandleCount: 6  PointerCount: 212365
```

단계별로 설명하겠습니다.

먼저 `ObjectTable(HANDLE_TABLE)` 을 확인합니다. 해당 `ObjectTable` 에는 `TableCode` 필드가 존재합니다. `0xffffffff'fffffffc` 로 AND 연산을 하는 이유는 최하위 2비트를 지우기 위함입니다.

이를 통해 `HANDLE_TABLE_ENTRY` 의 시작 주소를 얻을 수 있습니다.

<img src="https://s3.us-west-2.amazonaws.com/secure.notion-static.com/a3e0aba9-710d-40c4-bf8d-1ec4b8fb0b24/Untitled.png?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIAT73L2G45O3KS52Y5%2F20210203%2Fus-west-2%2Fs3%2Faws4_request&X-Amz-Date=20210203T174648Z&X-Amz-Expires=86400&X-Amz-Signature=e72f2501412485a3e52fa7c851b1a94fcc6a5cd8a3a4124482a2a7f0b9c68d37&X-Amz-SignedHeaders=host&response-content-disposition=filename%20%3D%22Untitled.png%22">

물론 시작 주소이기 때문에 확인해보면 `0x10` 만큼 떨어진 위치부터 엔트리가 시작됩니다.

좀더 정확한 핸들의 `HANDLE_TABLE_ENTRY` 를 얻기 위해서 `ExpLookupHandleTableEntry` 함수를 확인합니다.

```c
_HANDLE_TABLE_ENTRY *__fastcall ExpLookupHandleTableEntry(_HANDLE_TABLE *HandleTable, _EXHANDLE ExHandle)
{
  unsigned __int64 Handle; // rdx
  volatile unsigned __int64 TableCode; // r8

  Handle = ExHandle.Value & 0xFFFFFFFFFFFFFFFCui64;
  if ( Handle >= HandleTable->NextHandleNeedingPool )
    return 0i64;
  TableCode = HandleTable->TableCode;
  if ( (TableCode & 3) == 1 )
    return (*(TableCode + 8 * (Handle >> 0xA) - 1) + 4 * (Handle & 0x3FF));
  if ( (TableCode & 3) != 0 )
    return (*(*(TableCode + 8 * (Handle >> 0x13) - 2) + 8 * ((Handle >> 10) & 0x1FF)) + 4 * (Handle & 0x3FF));
  return (TableCode + 4 * Handle);
}
```

핸들 값도 마찬가지로 4의 배수인데 하위 2비트를 지우는건 어떤 상황인지 궁금합니다.

어쨋든, 위의 내용을 토대로 볼 때 `HANDLE_TABLE` 의 `TableCode` 를 3으로 AND 연산하여 1인 경우와 1보다 큰 경우, 0인 경우로 리턴하는 값이 다른 것을 확인할 수 있습니다.

위의 내용을 토대로 간단히 실습을 해보면 아래와 같이 정확한 `HANDLE_TABLE_ENTRY` 주소를 얻을 수 있습니다.

```
3: kd> !process 0n3248 0
Searching for Process with Cid == cb0
PROCESS ffffb9861e7b0080
    SessionId: 1  Cid: 0cb0    Peb: 33c2165000  ParentCid: 10d4
    DirBase: 5af68002  ObjectTable: ffff9d857ce7f180  HandleCount: 256.
    Image: notepad.exe

3: kd> .process ffffb9861e7b0080
Implicit process is now ffffb986`1e7b0080

3: kd> !handle 0

PROCESS ffffb9861e7b0080
    SessionId: 1  Cid: 0cb0    Peb: 33c2165000  ParentCid: 10d4
    DirBase: 5af68002  ObjectTable: ffff9d857ce7f180  HandleCount: 256.
    Image: notepad.exe

Handle table at ffff9d857ce7f180 with 256 entries in use

0004: Object: ffffb9861f7d4960  GrantedAccess: 001f0003 (Protected) (Inherit) Entry: ffff9d857a5f9010
Object: ffffb9861f7d4960  Type: (ffffb986186c5820) Event
    ObjectHeader: ffffb9861f7d4930 (new version)
        HandleCount: 1  PointerCount: 32768

...
생략
...

0010: Object: ffffb9861f214bc0  GrantedAccess: 001f0003 (Protected) Entry: ffff9d857a5f9040
Object: ffffb9861f214bc0  Type: (ffffb986186e0da0) IoCompletion
    ObjectHeader: ffffb9861f214b90 (new version)
        HandleCount: 1  PointerCount: 32762
```

위와 같은 구조로 되어 있을 때, `notepad` 프로세스의 0x10 핸들의 `HANDLE_TABLE_ENTRY` 를 구해보겠습니다.

위의 정보에서 `Entry` 가 `HANDLE_TABLE_ENTRY` 이며, 계산으로 정확한 엔트리를 구할 수 있는지 확인합니다.

먼저 `notepad` 의 `ObjectTable` 을 확인합니다.

```
3: kd> dt_HANDLE_TABLE ffff9d857ce7f180
ntdll!_HANDLE_TABLE
   +0x000 NextHandleNeedingPool : 0x800
   +0x004 ExtraInfoPages   : 0n0
   +0x008 TableCode        : 0xffff9d85`7a619001
   +0x010 QuotaProcess     : 0xffffb986`1e7b0080 _EPROCESS
   +0x018 HandleTableList  : _LIST_ENTRY [ 0xffff9d85`7ce7e998 - 0xffff9d85`7ce7e698 ]
   +0x028 UniqueProcessId  : 0xcb0
   +0x02c Flags            : 0
   +0x02c StrictFIFO       : 0y0
   +0x02c EnableHandleExceptions : 0y0
   +0x02c Rundown          : 0y0
   +0x02c Duplicated       : 0y0
   +0x02c RaiseUMExceptionOnInvalidHandleClose : 0y0
   +0x030 HandleContentionEvent : _EX_PUSH_LOCK
   +0x038 HandleTableLock  : _EX_PUSH_LOCK
   +0x040 FreeLists        : [1] _HANDLE_TABLE_FREE_LIST
   +0x040 ActualEntry      : [32]  ""
   +0x060 DebugInfo        : (null)
```

`TableCode` 필드의 값이 `0xffff9d85'7a619001` 으로 확인됩니다.

```
3: kd> ? 0xffff9d85`7a619001&3
Evaluate expression: 1 = 00000000`00000001
```

AND 3 의 연산 결과가 1이므로 아래와 같은 계산식을 세울 수 있습니다.

```
poi(0xffff9d85`7a619001+8*(10>>a)-1)+4*(10&0x3ff)
//*(TableCode+8*(Handle>>0xA)-1)+4*(Handle&0x3FF)

2: kd> ? poi(0xffff9d85`7a619001 + 8 *(10>>a)-1) + 4 *(10&3ff)
Evaluate expression: -108278367416256 = ffff9d85`7a5f9040

==

0010: Object: ffffb9861f214bc0  GrantedAccess: 001f0003 (Protected) Entry: ffff9d857a5f9040
Object: ffffb9861f214bc0  Type: (ffffb986186e0da0) IoCompletion
    ObjectHeader: ffffb9861f214b90 (new version)
        HandleCount: 1  PointerCount: 32762
```

계산한 값과 `Entry` 의 값이 일치하는 것을 확인할 수 있습니다.

그럼 좀 더 정확하게 오브젝트를 확인해보겠습니다.

```
2: kd> dt_HANDLE_TABLE_ENTRY ffff9d85`7a5f9040
nt!_HANDLE_TABLE_ENTRY
   +0x000 VolatileLowValue : 0n-5078337301951479837
   +0x000 LowValue         : 0n-5078337301951479837
   +0x000 InfoTable        : 0xb9861f21`4b90ffe3 _HANDLE_TABLE_ENTRY_INFO
   +0x008 HighValue        : 0n2031619
   +0x008 NextFreeHandleEntry : 0x00000000`001f0003 _HANDLE_TABLE_ENTRY
   +0x008 LeafHandleValue  : _EXHANDLE
   +0x000 RefCountField    : 0n-5078337301951479837
   +0x000 Unlocked         : 0y1
   +0x000 RefCnt           : 0y0111111111110001 (0x7ff1)
   +0x000 Attributes       : 0y000
   +0x000 ObjectPointerBits : 0y10111001100001100001111100100001010010111001 (0xb9861f214b9)
   +0x008 GrantedAccessBits : 0y0000111110000000000000011 (0x1f0003)
   +0x008 NoRightsUpgrade  : 0y0
   +0x008 Spare1           : 0y000000 (0)
   +0x00c Spare2           : 0
```

`GrantedAccessBits` 를 제외하고는 이게 맞는 값인가 싶습니다.

### [-] Object

하지만 다음과 같은 계산을 통해 해당 핸들의 오브젝트를 구할 수 있습니다.

```
ObjectHeader = (HandleTableEntry.VolatileLowValue >> 0x10) & 0xFFFFFFFF`FFFFFFF0

2: kd> dt_OBJECT_HEADER
nt!_OBJECT_HEADER
   +0x000 PointerCount     : Int8B
   +0x008 HandleCount      : Int8B
   +0x008 NextToFree       : Ptr64 Void
   +0x010 Lock             : _EX_PUSH_LOCK
   +0x018 TypeIndex        : UChar
   +0x019 TraceFlags       : UChar
   +0x019 DbgRefTrace      : Pos 0, 1 Bit
   +0x019 DbgTracePermanent : Pos 1, 1 Bit
   +0x01a InfoMask         : UChar
   +0x01b Flags            : UChar
   +0x01b NewObject        : Pos 0, 1 Bit
   +0x01b KernelObject     : Pos 1, 1 Bit
   +0x01b KernelOnlyAccess : Pos 2, 1 Bit
   +0x01b ExclusiveObject  : Pos 3, 1 Bit
   +0x01b PermanentObject  : Pos 4, 1 Bit
   +0x01b DefaultSecurityQuota : Pos 5, 1 Bit
   +0x01b SingleHandleEntry : Pos 6, 1 Bit
   +0x01b DeletedInline    : Pos 7, 1 Bit
   +0x01c Reserved         : Uint4B
   +0x020 ObjectCreateInfo : Ptr64 _OBJECT_CREATE_INFORMATION
   +0x020 QuotaBlockCharged : Ptr64 Void
   +0x028 SecurityDescriptor : Ptr64 Void
   +0x030 Body             : _QUAD

Object = (HandleTableEntry.VolatileLowValue >> 0x10) & 0xFFFFFFFF`FFFFFFF0 + 0x30
```

위의 공식을 토대로 `notepad` 의 핸들 값 0x10 을 가지는 오브젝트는 아래와 같습니다.

```
2: kd> ? ((0xb9861f21`4b90ffe3 >>> 0x10) & 0xFFFFFFFFFFFFFFF0) + 0x30
Evaluate expression: -77489277678656 = ffffb986`1f214bc0

2: kd> !object ffffb986`1f214bc0
Object: ffffb9861f214bc0  Type: (ffffb986186e0da0) IoCompletion
    ObjectHeader: ffffb9861f214b90 (new version)
    HandleCount: 1  PointerCount: 32762

=== result of !handle command
0010: Object: ffffb9861f214bc0  GrantedAccess: 001f0003 (Protected) Entry: ffff9d857a5f9040
Object: ffffb9861f214bc0  Type: (ffffb986186e0da0) IoCompletion
    ObjectHeader: ffffb9861f214b90 (new version)
        HandleCount: 1  PointerCount: 32762
```

정확히 일치하는 것을 볼 수 있습니다.

해당 공식은 `ExQueryProcessHandleInformation` 에서 찾을 수 있습니다.

```c
_int64 __fastcall ExQueryProcessHandleInformation(__int64 HandleTable, _QWORD *a2, int a3, int *a4)
{
  // [COLLAPSED LOCAL DECLARATIONS. PRESS KEYPAD CTRL-"+" TO EXPAND]

...

  while ( 1 )
  {
    v10 = ExpGetNextHandleTableEntry(HandleTable, v9, v25);
    HandleTableEntry = v10;
    ...
		...
    else if ( ExLockHandleTableEntry(v28, &v10->LowValue) )
    {
      ObjectHeader = ((HandleTableEntry->LowValue >> 0x10) & 0xFFFFFFFFFFFFFFF0ui64);
      v14 = HandleTableEntry->LeafHandleValue.0;
      v15 = (HandleTableEntry->LowValue >> 0x11) & 7 | 8;
      if ( (*&v14 & 0x2000000) == 0 )
        LOBYTE(v15) = (HandleTableEntry->LowValue >> 0x11) & 7;
      v16 = v15 & 7;
      v30 = v16;
      v17 = *(ObTypeIndexTable[ObHeaderCookie ^ *(((HandleTableEntry->LowValue >> 0x10) & 0xFFFFFFFFFFFFFFF0ui64) + 0x18) ^ ((WORD1(HandleTableEntry->LowValue) & 0xFFF0) >> 8)]
            + 0x28);
```

Windows 커널 오브젝트의 위치는 항상 헤더의 다음입니다. 그렇기 때문에 위의 공식을 이용하여 오브젝트를 구할 수 있습니다.

### [-] Object Type

특정 오브젝트가 프로세스라는 가정하에 오브젝트 유형을 찾는 방법에 대해 알아보겠습니다.

```
2: kd> dt_OBJECT_TYPE
nt!_OBJECT_TYPE
   +0x000 TypeList         : _LIST_ENTRY
   +0x010 Name             : _UNICODE_STRING
   +0x020 DefaultObject    : Ptr64 Void
   +0x028 Index            : UChar
   +0x02c TotalNumberOfObjects : Uint4B
   +0x030 TotalNumberOfHandles : Uint4B
   +0x034 HighWaterNumberOfObjects : Uint4B
   +0x038 HighWaterNumberOfHandles : Uint4B
   +0x040 TypeInfo         : _OBJECT_TYPE_INITIALIZER
   +0x0b8 TypeLock         : _EX_PUSH_LOCK
   +0x0c0 Key              : Uint4B
   +0x0c8 CallbackList     : _LIST_ENTRY
```

위에서 말한 것과 같이 특정 오브젝트 앞에는 OBJECT_HEADER가 존재합니다.

System 프로세스의 EPROCESS 오브젝트를 이용해보겠습니다.

```
0: kd> !process 4 0
Searching for Process with Cid == 4
PROCESS ffffb986186a7040
    SessionId: none  Cid: 0004    Peb: 00000000  ParentCid: 0000
    DirBase: 001ad002  ObjectTable: ffff9d8573a8be00  HandleCount: 2320.
    Image: System

0: kd> dt_OBJECT_HEADER ffffb986186a7040-30
nt!_OBJECT_HEADER
   +0x000 PointerCount     : 0n179132
   +0x008 HandleCount      : 0n5
   +0x008 NextToFree       : 0x00000000`00000005 Void
   +0x010 Lock             : _EX_PUSH_LOCK
   +0x018 TypeIndex        : 0x70 'p'
   +0x019 TraceFlags       : 0 ''
   +0x019 DbgRefTrace      : 0y0
   +0x019 DbgTracePermanent : 0y0
   +0x01a InfoMask         : 0 ''
   +0x01b Flags            : 0x2 ''
   +0x01b NewObject        : 0y0
   +0x01b KernelObject     : 0y1
   +0x01b KernelOnlyAccess : 0y0
   +0x01b ExclusiveObject  : 0y0
   +0x01b PermanentObject  : 0y0
   +0x01b DefaultSecurityQuota : 0y0
   +0x01b SingleHandleEntry : 0y0
   +0x01b DeletedInline    : 0y0
   +0x01c Reserved         : 0
   +0x020 ObjectCreateInfo : 0xfffff805`0fe53900 _OBJECT_CREATE_INFORMATION
   +0x020 QuotaBlockCharged : 0xfffff805`0fe53900 Void
   +0x028 SecurityDescriptor : 0xffff9d85`73a3ee63 Void
   +0x030 Body             : _QUAD
```

헤더에서 TypeIndex를 확인합니다. 0x70로 되어 있습니다.

오브젝트 유형을 알아내기 위한 루틴으로 `ObGetObjectType` 이라는 Export 함수가 존재합니다.

```c
__int64 __fastcall ObGetObjectType(__int64 Object)
{
  return ObTypeIndexTable[ObHeaderCookie ^ *(Object - 0x18) ^ ((Object - 0x30) >> 8)];
}
```

```PAGE:0000000140682110                         ObGetObjectType proc near               ; DATA XREF: .pdata:0000000140101AB4↑o
PAGE:0000000140682110 48 8D 41 D0                             lea     rax, [rcx-30h]
PAGE:0000000140682114 0F B6 49 E8                             movzx   ecx, byte ptr [rcx-18h]
PAGE:0000000140682118 48 C1 E8 08                             shr     rax, 8
PAGE:000000014068211C 0F B6 C0                                movzx   eax, al
PAGE:000000014068211F 48 33 C1                                xor     rax, rcx
PAGE:0000000140682122 0F B6 0D F3 A5 67 00                    movzx   ecx, byte ptr cs:ObHeaderCookie
PAGE:0000000140682129 48 33 C1                                xor     rax, rcx
PAGE:000000014068212C 48 8D 0D DD AC 67 00                    lea     rcx, ObTypeIndexTable
PAGE:0000000140682133 48 8B 04 C1                             mov     rax, [rcx+rax*8]
PAGE:0000000140682137 C3                                      retn
```

이제 `nt!ObGetObjectType` 의 연산을 참조하여 오브젝트 유형을 구해보도록 하겠습니다.

먼저 오브젝트 헤더(`ffffb986186a7010`) 의 하위 1바이트를 제거하고, 마지막 1바이트 값과 `OBJECT_HEADER.TypeIndex` 값을 XOR 연산합니다.

```
1. (ffffb986186a7010 >> 8)
2. ffffb986186a70 => 0x70
3. TypeIndex = 0x70
```

다음으로 `ObHeaderCookie` 의 1바이트 값과 XOR 연산을 진행합니다.

```
0: kd> db ObHeaderCookie l1
fffff805`0fefc71c  07
```

즉 아래와 같은 공식이 성립됩니다.

```
0x70(&ObjectHeader>>8 의 하위 1바이트)
XOR
0x70(ObjectHeader 의 TypeIndex)
XOR
0x07(ObHeaderCookie)
0: kd> dt_OBJECT_TYPE poi(ObTypeIndexTable+(7*8))
nt!_OBJECT_TYPE
   +0x000 TypeList         : _LIST_ENTRY [ 0xffffb986`186c4e80 - 0xffffb986`186c4e80 ]
   +0x010 Name             : _UNICODE_STRING "Process"
   +0x020 DefaultObject    : (null) 
   +0x028 Index            : 0x7 ''
   +0x02c TotalNumberOfObjects : 0x74
   +0x030 TotalNumberOfHandles : 0x42a
   +0x034 HighWaterNumberOfObjects : 0x98
   +0x038 HighWaterNumberOfHandles : 0x523
   +0x040 TypeInfo         : _OBJECT_TYPE_INITIALIZER
   +0x0b8 TypeLock         : _EX_PUSH_LOCK
   +0x0c0 Key              : 0x636f7250
   +0x0c8 CallbackList     : _LIST_ENTRY [ 0xffff9d85`73e9fd40 - 0xffff9d85`73e9fd40 ]
```

## [0x02] Reference

1. [Reversing Windows Internals](https://rayanfam.com/topics/reversing-windows-internals-part1/)
2. [ReactOS](https://doxygen.reactos.org/index.html)