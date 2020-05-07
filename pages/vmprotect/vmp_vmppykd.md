---
title: VMP kernel driver analysis using pykd
keywords: documentation, technique, debugging
date: 2020-05-06
tags: [Windows, Reversing, Dev]
summary: "pykd를 이용한 패킹 드라이버 분석"
sidebar: vmp_sidebar
permalink: vmp_vmppykd.html
folder: vmprotect
---

## [0x00] Overview

악성코드, 게임 치트, 안티 치트 솔루션 등 커널 드라이버를 사용하는 제품이나 도구가 많이 있습니다. 트레이싱을 하기 위해서는 간결하고 적절한 해결책이 필요합니다. 저는 이를 해결하기 위해 windbg 플러그인 중 pykd 를 이용하였습니다. windbg와 파이썬을 함께 사용할 수 있는 매우 유용한 플러그인입니다.

## [0x01] Requirements

먼저 [여기](https://shhoya.github.io/vmp_vmpanalysis.html) 에서 선행학습을 통해 간략한 코드 가상화의 내용을 숙지해야 합니다. 아래와 같이 정의한 용어들을 확인하십시오.

- `vmmacro` : 여러 개의 매크로 함수가 존재, 특정 패턴으로 이루어져 있음
- `vmmacro_handler` : vmmacro를 호출하는 `push` 와 `call`명령어 세트
- `vmtable` : vmmacro의 집합

### [-] Virtual Machine

가상머신에 대한 정보와 해당 머신에서 사용하는 도구 목록입니다.

- Guest OS : Windows 10, 1903(OS Build 18362.30)



### [-] Host Machine

실습을 진행하는 호스트 OS의 정보 및 도구 목록입니다.

- Host OS : Windows 10 x64, 1909(OS Build 18363.720)
- Tools
  - Debugger & Disassembler : Windbg, IDA Pro
  - Visual Studio 2019 Community

{% include note.html content="추가 도구를 사용할 수 있습니다." %}



## [0x02] Windbg plugins

우선 실제 실습을 진행하기 앞서 windbg 에서 사용 가능한 플러그인 `dbgkit`와 `pykd`를 설치하는 과정과 사용 방법에 대해 설명하겠습니다.

### [-] DbgKit

- [http://www.andreybazhan.com/dbgkit.html](http://www.andreybazhan.com/dbgkit.html) 다운로드
-  압축 파일 내 모듈 존재
- windbg 설치 경로 내 아키텍쳐별 winext에 저장
- `.load dbgkit.dll`
- `!dbgkit.help` 로 각 명령어 확인 가능

해당 모듈은 일단 커널 모드에서만 가능한 것으로 알려져 있습니다. 매우 유용한 이유는 원하는 프로세스를 찾거나 디바이스 드라이버를 확인할 때 GUI 형태로 깔끔하고 신속하게 찾을 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/vmp/vmp_00.png?raw=true">



### [-] PyKd

- [https://githomelab.ru/pykd](https://githomelab.ru/pykd) 공식 홈페이지
- `pykd` 내 `Wiki` 에서 다운로드 가능
- pip로 설치 가능(python2.7 설치 경로 내에서 `pykd.pyd` 파일을 찾아 위와 마찬가지로 `winext` 경로에 복사)
- `.load pykd.pyd`
- `!pykd.help`

```
3: kd> .load pykd.pyd
3: kd> !py
Python 2.7.15 (v2.7.15:ca079a3ea3, Apr 30 2018, 16:30:26) [MSC v.1500 64 bit (AMD64)] on win32
Type "help", "copyright", "credits" or "license" for more information.
(InteractiveConsole)
>>> print "hello"
hello
>>> 
```

위와 같이 파이썬 스크립트를 이용할 수 있습니다. 뿐만 아니라 스크립트를 작성하여 분석에 대해 자동화할 수 있습니다.



## [0x03] Prepare for analysis

먼저 목표한 바와 같이 VMP로 드라이버를 패킹해야합니다. 코드 가상화에 대한 분석이 목적입니다. 또한 드라이버의 경우 실행압축을 제대로 하지 못하는 이슈가 존재합니다. 아마 드라이버 진입점 자체가 `.INIT` 섹션에 존재해야 하는데 실행압축을 하면 이를 인지하지 못하고 드라이버가 로드되지 못하는 것 같습니다.(이건 저의 단순한 추측입니다.)

### [-] VmpDriver(Dummy)

먼저 아래와 같이 간략한 드라이버 코드를 작성합니다.

```c
#include <ntifs.h>

typedef PPEB(*PsGetProcessPeb_t)(
	PEPROCESS Process
	);

PVOID GetRoutineAddress(PCWSTR Routine)
{
	UNICODE_STRING RoutineName = { 0, };
	RtlInitUnicodeString(&RoutineName, Routine);
	return MmGetSystemRoutineAddress(&RoutineName);
}

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);
	
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	
	pDriver->DriverUnload = DriverUnload;
	PVOID pAllocated = ExAllocatePoolWithTag(NonPagedPool, 0x1000, 'SHHO');
	ExFreePoolWithTag(pAllocated, 'SHHO');

	PEPROCESS Process = PsGetCurrentProcess();

	HANDLE PID = PsGetProcessId(Process);
	PsGetProcessPeb_t PsGetProcessPeb = (PsGetProcessPeb_t)GetRoutineAddress(L"PsGetProcessPeb");
	if (!PsGetProcessPeb)
	{
		return STATUS_ACCESS_DENIED;
	}

	KAPC_STATE ApcState = { 0, };
	KeStackAttachProcess(Process, &ApcState);
	PPEB Peb = PsGetProcessPeb(Process);
	KeUnstackDetachProcess(&ApcState);

	UNREFERENCED_PARAMETER(Peb);
	UNREFERENCED_PARAMETER(PID);

	return STATUS_SUCCESS;
}
```

별 동작은 없습니다. 드라이버 키트에서 제공하는 함수들을 몇 가지 호출할뿐입니다.

### [-] A difference between Vmp Driver and Normal  Driver

먼저 분석에 앞서 패킹된 드라이버와 정상 드라이버 간의 몇 가지 알아둬야 할 차이점이 있습니다.

1. 디버깅 방지 기능이 적용되어 있다.(소프트웨어 브레이크 포인트 탐지 & 커널 디버깅 탐지)
2. 드라이버 진입점을 찾을 수 없다.(`sxe ld`와 같은 명령으로 드라이버 로드 시 정확히 탐지할 수 없습니다.)

위의 두 가지 기능 때문에 드라이버가 로드된 커널의 메모리 덤프를 이용하여 분석하는 경우가 많습니다. 동적 분석은 많은 내용과 분석의 질을 향상시키며 난이도도 그만큼 낮추는 효과가 있습니다.

위와 같은 문제점을 해결할 수 있는 방법이 무엇일지 생각해봤습니다. 먼저 디버깅 방지 기능의 경우 제가 만든 `ControlDebugger`를 이용하여 우회할 수 있습니다. 또한 드라이버 진입점의 경우 수동으로 드라이버가 로드되는 시점을 확인하고 해당 경로의 이름을 구분하여 드라이버 진입점을 확인할 수 있습니다.

위의 두 가지 해결책은 각각 [Control Debugger](https://shhoya.github.io/antikernel_ctrldebugger.html) 와 [Manually Find DriverEntry](https://shhoya.github.io/driverentry.html) 에서 원리를 확인할 수 있습니다.

패킹한 드라이버는 여기서 다운로드 할 수 있습니다. IDA로 열어두면 아주 오랜시간 코드를 정리합니다.

**작성중**

