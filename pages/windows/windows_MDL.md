---
title: Memory Descriptor List
keywords: documentation, technique, reversing, kernel, windows
date: 2020-12-08
tags: [Windows, Reversing, Vulnerability, Kernel]
summary: "MDL(Memory Descriptor List)"
sidebar: windows_sidebar
permalink: windows_MDL.html
folder: windows

---

## [0x00] Overview

MDL을 학습하는 이유는 `Read Only`, 즉 `CR0` 내 `WP(Write Protect)`를 비활성화 하기 위해서 입니다.
커널 내 네이티브 함수에 인라인 후킹을 하기 위해 꼭 필요한 과정이었습니다.
CR0 내 WP 비트를 비활성화하는 방법도 있지만 MDL을 이용해보기로 하여 학습하였습니다.

## [0x01] Memory Descriptor List

먼저 `MDL`은 MSDN에서 아래와 같이 설명합니다.

```
가상 메모리의 연속적인 주소가 실제 물리 메모리 공간에서 연속적일 필요가 없기 때문에, 연속성을 보장하지 않습니다.
이에 OS는 MDL(Memory Descriptor List) 를 이용하여 가상 메모리의 물리 페이지 레이아웃을 설명합니다.
```

즉 `MDL`는 가상 메모리와 관련된 물리적 페이지를 추적합니다. 이러한 내용에서 Direct I/O의 개념을 빼놓을 수가 없습니다.(해당 내용에는 없으며 DMA, Direct I/O 등을 검색하세요)

```
0: kd> dt nt!_MDL
   +0x000 Next             : Ptr64 _MDL
   +0x008 Size             : Int2B
   +0x00a MdlFlags         : Int2B
   +0x00c AllocationProcessorNumber : Uint2B
   +0x00e Reserved         : Uint2B
   +0x010 Process          : Ptr64 _EPROCESS
   +0x018 MappedSystemVa   : Ptr64 Void
   +0x020 StartVa          : Ptr64 Void
   +0x028 ByteCount        : Uint4B
   +0x02c ByteOffset       : Uint4B
```

`MDL` 은 위와 같은 구조를 지녔습니다.

`StartVa`의 경우 고정된 사이즈로 페이징된 가상 메모리의 시작 주소를 의미합니다. 즉 이로부터 `ByteOffset` 만큼 더한 값이 `IoAllocateMdl` 을 호출할 때 전달한 `VA` 값입니다.

MSDN에는 `MDL`의 구조가 반 투명적인 구조라고 설명합니다. 때문에 `Next`, `MdlFlags` 외의 멤버에는 직접 접근을 하지 말 것을 권고하고 있습니다. 이에 따라 주요 값들을 얻기 위해 다음과 같은 매크로를 이용하라고 권고하고 있습니다.

- `MmGetMdlVirtualAddress`     : Return Virtual Address
- `MmGetMdlByteCount`              : Return Byte Count
- `MmGetMdlByteOffset`            : Return Byte Offset

 `MmGetMdlVirtualAddress`의 경우 단순히 오프셋과 더하여 실제 `MDL` 할당 시 사용한 `VA` 값을 리턴합니다.

```c++
#define MmGetMdlVirtualAddress(Mdl)                   \
  ((PVOID) ((PCHAR) ((Mdl)->StartVa) + (Mdl)->ByteOffset))
```

페이징 가능한(Pageable) 메모리의 경우, 가상 메모리와 물리적 메모리가 대응되는 것은 일시적입니다. 때문에 MDL 구조의 데이터 배열들은 특정 상황에서만 유효할 수 있습니다. 이러한 특성때문에 `**MmProbeAndLockPages**`를 이용하여 페이징 가능한 메모리를 고정하고 현재 레이아웃의 데이터로 배열을 초기화합니다. 이는 `**MmUnlockPages**` 가 호출될 때까지 페이지 아웃되지 않습니다.

본인은 여기서 의문을 가졌습니다. 그래서 **결론적으로 물리적 메모리의 정보는 어디있습니까?**
해당 부분을 찾는데 그리 오랜 시간이 걸리지 않았습니다. `MDL` 구조의 끝에 저장되어 있습니다.

간단히 확인해보겠습니다.

```
0: kd> dt_MDL ffffca0ce4418b80
nt!_MDL
   +0x000 Next             : (null) 
   +0x008 Size             : 0n56
   +0x00a MdlFlags         : 0n10
   +0x00c AllocationProcessorNumber : 0
   +0x00e Reserved         : 0
   +0x010 Process          : (null) 
   +0x018 MappedSystemVa   : 0xffffca0c`e154a018 Void
   +0x020 StartVa          : 0xfffff805`3096f000 Void
   +0x028 ByteCount        : 0x10
   +0x02c ByteOffset       : 0x10

0: kd> dp ffffca0ce4418b80+30h          ; End of MDL
ffffca0c`e4418bb0  00000000`00002b6f 00000000`0011de1a
ffffca0c`e4418bc0  00000000`0012521b 00000000`0012341c
ffffca0c`e4418bd0  00000000`0011dd1d 00000000`0011bf1e
ffffca0c`e4418be0  00000000`0011be1f 00000000`0011b520
ffffca0c`e4418bf0  ffffca0c`e5a42760 00000000`00000000
ffffca0c`e4418c00  0000023b`6052c768 0000023b`6052c5e0
ffffca0c`e4418c10  00000000`00000000 00000000`00000000
ffffca0c`e4418c20  ffffca0c`e5a42760 00000000`00000000

0: kd> !db 2b6f*1000+10               ; MDL+30h * 1000h + 10h(MDL.ByteOffset)
# 2b6f010 48 89 5c 24 08 48 89 6c-24 10 48 89 74 24 18 57 H.\$.H.l$.H.t$.W
# 2b6f020 41 56 41 57 48 83 ec 30-65 48 8b 04 25 20 00 00 AVAWH..0eH..% ..
# 2b6f030 00 33 db 44 0f b7 3d c5-3f 20 00 41 8b e8 48 8b .3.D..=.? .A..H.
# 2b6f040 f2 89 5c 24 68 8b f9 4c-8b 88 c0 00 00 00 45 0f ..\$h..L......E.
# 2b6f050 b7 b1 92 00 00 00 41 8b-c6 44 8b c8 89 5c 24 20 ......A..D...\$ 
# 2b6f060 44 8b c5 48 8b d6 8b cf-e8 53 36 cc ff 48 85 c0 D..H.....S6..H..
# 2b6f070 0f 84 38 00 00 00 48 8b-d8 48 8b 6c 24 58 48 8b ..8...H..H.l$XH.
# 2b6f080 c3 48 8b 5c 24 50 48 8b-74 24 60 48 83 c4 30 41 .H.\$PH.t$`H..0A

0: kd> db ExAllocatePoolWithTag
fffff805`3096f010  48 89 5c 24 08 48 89 6c-24 10 48 89 74 24 18 57  H.\$.H.l$.H.t$.W
fffff805`3096f020  41 56 41 57 48 83 ec 30-65 48 8b 04 25 20 00 00  AVAWH..0eH..% ..
fffff805`3096f030  00 33 db 44 0f b7 3d c5-3f 20 00 41 8b e8 48 8b  .3.D..=.? .A..H.
fffff805`3096f040  f2 89 5c 24 68 8b f9 4c-8b 88 c0 00 00 00 45 0f  ..\$h..L......E.
fffff805`3096f050  b7 b1 92 00 00 00 41 8b-c6 44 8b c8 89 5c 24 20  ......A..D...\$ 
fffff805`3096f060  44 8b c5 48 8b d6 8b cf-e8 53 36 cc ff 48 85 c0  D..H.....S6..H..
fffff805`3096f070  0f 84 38 00 00 00 48 8b-d8 48 8b 6c 24 58 48 8b  ..8...H..H.l$XH.

fffff805`3096f080  c3 48 8b 5c 24 50 48 8b-74 24 60 48 83 c4 30 41  .H.\$PH.t$`H..0A
```

## [0x02] PoC

```c++
NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
	NTSTATUS Status = STATUS_SUCCESS;
	pDriver->DriverUnload = DriverUnload;

	Log("Driver Loaded\n");
	PMDL pMDL = NULL;
	pMDL = IoAllocateMdl(ExAllocatePoolWithTag, 0x10, FALSE, FALSE, NULL);
	__try
	{
		MmProbeAndLockPages(pMDL, KernelMode, IoReadAccess);
	}
	__except (EXCEPTION_EXECUTE_HANDLER)
	{
		IoFreeMdl(pMDL);
		Log("Invalid V.A(MDL)\n");
		return;
	}

	PVOID MappingData = MmMapLockedPagesSpecifyCache(pMDL, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	if (MappingData)
	{
		MmUnmapLockedPages(MappingData, pMDL);
	}

	MmUnlockPages(pMDL);
	IoFreeMdl(pMDL);
	return Status;
}
```

직접 디버깅을 진행하며 각 `MDL` 함수 호출 후의 상태들을 확인하였습니다. 먼저 `IoAllocateMdl` 을 통해 반환된 `MDL`의 데이터입니다.

```
// IoAllocateMdl(ExAllocatePoolWithTag, 0x10, FALSE, FALSE, NULL);

1: kd> dt_MDL ffff9f814b466340
DevKernelDriver!_MDL
   +0x000 Next             : (null) 
   +0x008 Size             : 0n56
   +0x00a MdlFlags         : 0n8	// MDL_ALLOCATED_FIXED_SIZE
   +0x010 Process          : (null) 
   +0x018 MappedSystemVa   : 0xffffb680`afc22000 Void	// Not yet valid
   +0x020 StartVa          : 0xfffff805`11db1000 Void
   +0x028 ByteCount        : 0x10
   +0x02c ByteOffset       : 0x30
```

`MdlFlags` 값이 `MDL_ALLOCATED_FIXED_SIZE` 인 이유는 `MDL` 할당 시 전달한 두 번째 파라미터(Size)의 영향입니다. `MappedSystemVa`의 경우 아직 매핑하지 않았기 때문에 유효하지 않습니다. 다음은 `MmProbeAndLockPages` 호출 후의 데이터 입니다.

```
1: kd> dt_MDL ffff9f814b466340
DevKernelDriver!_MDL
   +0x000 Next             : (null) 
   +0x008 Size             : 0n56
   +0x00a MdlFlags         : 0n10	// MDL_ALLOCATED_FIXED_SIZE | MDL_PAGES_LOCKED
   +0x010 Process          : (null) 
   +0x018 MappedSystemVa   : 0xffffb680`afc22000 Void
   +0x020 StartVa          : 0xfffff805`11db1000 Void
   +0x028 ByteCount        : 0x10
   +0x02c ByteOffset       : 0x30
```

`MdlFlags` 값이 `MDL_ALLOCATED_FIXED_SIZE | MDL_PAGES_LOCKED` 가 되었습니다. 해당 페이지를 고정했음을 의미합니다.
마지막으로 `MmMapLockedPageSpecifyCache` 를 이용하여 매핑을 한 후의 데이터 입니다.

```
1: kd> dt_MDL ffff9f814b466340
DevKernelDriver!_MDL
   +0x000 Next             : (null) 
   +0x008 Size             : 0n56
   +0x00a MdlFlags         : 0n11	// MDL_ALLOCATED_FIXED_SIZE | MDL_PAGES_LOCKED | MDL_MAPPED_TO_SYSTEM_VA
   +0x010 Process          : (null) 
   +0x018 MappedSystemVa   : 0xffffb680`afc2d030 Void	// Valid
   +0x020 StartVa          : 0xfffff805`11db1000 Void
   +0x028 ByteCount        : 0x10
   +0x02c ByteOffset       : 0x30
```

 매핑되어 `MdlFlags`에 `MDL_MAPPED_TO_SYSTEM_VA` 값이 추가 된 것을 확인할 수 있습니다. 더불어 `MappedSystemVa`의 값이 변하였고 해당 주소를 확인하면 정확히 원하던 메모리 값이 매핑되어 있는 것을 확인할 수 있습니다.

```
1: kd> db 0xffffb680`afc2d030 // (MappedSystemVa)
ffffb680`afc2d030  48 89 5c 24 08 48 89 6c-24 10 48 89 74 24 18 57  H.\$.H.l$.H.t$.W
ffffb680`afc2d040  41 56 41 57 48 83 ec 30-65 48 8b 04 25 20 00 00  AVAWH..0eH..% ..
ffffb680`afc2d050  00 45 8b f0 44 0f b7 3d-a4 9f 34 00 48 8b ea 8b  .E..D..=..4.H...
ffffb680`afc2d060  f1 4c 8b 88 c0 00 00 00-41 0f b7 b9 92 00 00 00  .L......A.......
ffffb680`afc2d070  0f ba ef 1f 0f ba f7 1f-33 db 8b c7 89 5c 24 68  ........3....\$h
ffffb680`afc2d080  44 8b c8 89 5c 24 20 45-8b c6 48 8b d5 8b ce e8  D...\$ E..H.....
ffffb680`afc2d090  2c 97 91 ff 48 85 c0 0f-84 4f 01 00 00 48 8b d8  ,...H....O...H..
ffffb680`afc2d0a0  48 8b 6c 24 58 48 8b c3-48 8b 5c 24 50 48 8b 74  H.l$XH..H.\$PH.t
```

본인은 맨 처음 말한 것과 같이 후킹을 하기 위해 해당 내용을 학습했습니다.
`ExAllocatePoolWithTag` 를 후킹한다는 가정하에 다음과 같은 로직을 그려볼 수 있습니다.

- `ExAllocatePoolWithTag` 의 `VA`와 `PA`를 `MmMapLockedPagesSpecifyCache`를 이용하여 `MappedSystemVA`에 매핑
  - `MmMapLockedPagesSpecifyCache`은 매핑된 가상 주소를 반환합니다.
- `MappedSystemVA` 의 메모리 수정은 각 `VA`, `PA` 에 동일하게 적용된다.(공유 메모리 같은 원리)
- `MappedSystemVA`의 메모리 보호 비트를 `Write` 가능하도록 변경 후 수정

아래는 위의 내용을 토대로 그려본 그림입니다. 틀린 부분이 있다면 피드백 주시길 바랍니다.

[<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/mdl.png?raw=true">](https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/mdl.png?raw=true)

## [0x03] Shh0ya Kernel Hook

위의 내용을 토대로 인라인 후킹 드라이버를 제작해봤습니다.
Github : [https://github.com/Shhoya/Shh0yaKernelHook](https://github.com/Shhoya/Shh0yaKernelHook)

## [0x04] Reference

1. [Using MDLs](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/using-mdls)
2. [Understanding MDLs](http://bsodtutorials.blogspot.com/2013/12/understanding-mdls-memory-descriptor.html)
3. [MDLs are Lists that Describe Memory(OSR)](http://www.osronline.com/article.cfm%5Eid=423.htm)

