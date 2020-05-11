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

**예제로 필요한 VMP Driver와 스크립트는 [여기](https://github.com/Shhoya/Examples/tree/master/0x01_VMPDriver)에서 다운로드 가능합니다.**

{% include warning.html content="본 저자는 VMP로 보호된 프로그램 해제에 대한 막연한 질문 또는 의뢰를 받지 않습니다." %}

## [0x01] Requirements

먼저 [여기](https://shhoya.github.io/vmp_vmpanalysis.html) 에서 선행학습을 통해 간략한 코드 가상화의 내용을 숙지해야 합니다. 아래와 같이 정의한 용어들을 확인하십시오.

- `vmmacro` : 여러 개의 매크로 함수가 존재, 특정 패턴으로 이루어져 있음
- `vmmacro_handler` : vmmacro를 호출하는 `push` 와 `call`명령어 세트
- `vmtable` : vmmacro_handler 의 집합

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

먼저 목표한 바와 같이 VMP로 드라이버를 패킹해야합니다. 코드 가상화에 대한 분석이 목적입니다. 또한 드라이버의 경우 실행압축을 제대로 하지 못하는 이슈가 존재합니다.

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

위의 두 가지 해결책은 각각 [Control Debugger](https://shhoya.github.io/antikernel_ctrldebugger.html) 와 [Manually Find DriverEntry](https://shhoya.github.io/driverentry.html) 에서 원리를 확인할 수 있으며, 이 두 가지 방법을 통해 아래와 같이 패킹 된 드라이버의 드라이버 진입점에서의 실행 흐름을 가져올 수 있습니다.

1. 디버그 모드 탐지 우회

   <img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/vmp/vmp_01.gif?raw=true">

2. 드라이버 진입점

   <img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/vmp/vmp_02.gif?raw=true">

{% include note.html content="그림이 잘 보이지 않는 경우 브라우저를 확대하여 볼 수 있습니다." %}

코드 가상화(Code Virtualization)와 코드 변형(Mutation)이 함께 적용되어 있는 경우, 분석이 매우 어려워지며 쓰레기 코드가 굉장히 많이 존재합니다. 최대한 분석 시간을 단축하고자 한다면 몇 가지 특성을 기억해야 합니다.

1. `.vmp1` 섹션은 초기화 코드(`VmpEntryPoint`)가 존재합니다.
2. `.vmp0` 섹션은 원본 코드를 실행할 수 있는 가상 CPU 명령들이 존재합니다.

우리는 `vmpmacro_hanlder` 를 통해 `vmpmacro`를 호출하고 리턴 명령을 통해 원본 코드를 호출하는 것을 알고 있습니다. 이러한 여러가지 알고있는 특성을 토대로 자동으로 각 명령들을 실행하며 분석하고 로그로 남기는 스크립트를 `pykd`를 이용하여 작성해보겠습니다.

## [0x04] PYKD Script

스크립트가 조금 긴 관계로 **[여기](https://github.com/Shhoya/Examples/tree/master/0x01_VMPDriver)**에서 확인하길 바랍니다.
간략하게 주요 기능에 대해서만 설명하겠습니다.

### [-] InitTracer

```python
def InitTracer():
    global DriverObject
    global ImageBase
    global NtImageEnd

    NtModule    = pykd.module("nt")
    NtImageBase = NtModule.begin()
    NtImageEnd  = NtModule.end()
    pykd.dbgCommand("ba e1 IopLoadDriver+4bd")
    pykd.dbgCommand("ba e1 IopLoadDriver+4c2")
    pykd.go()

    while(1):
        regPath = pykd.dbgCommand("du /c40 @rdx+10")
        if "VmpDriver.vmp" in regPath:
            print "[*] Find VMP Driver"
            DriverObject = pykd.reg("rcx")
            print "\t[-] Driver Object : 0x{:X}".format(DriverObject)
            ImageBase =pykd.ptrPtr(DriverObject+0x18)    # DriverObject.DriverStart
            print "\t[-] ImageBase Address : 0x{:X}".format(ImageBase)
            VMPTracingSub.GetSectionInfo(ImageBase)
            EntryPoint = ImageBase + VMPTracingSub.EntryPoint_Off
            strEntryPoint = hex(EntryPoint).rstrip("L")
            pykd.dbgCommand("ba e1 "+strEntryPoint)
            pykd.go()
            pykd.dbgCommand("bc 2")
            return
        pykd.go()

```

`DriverEntry`로 전달되는 파라미터 중 `RegistryPath`를 이용하여 타겟 드라이버를 식별합니다. 타겟 파일을 파싱하여 `VMPEntryPoint`에 하드웨어 브레이크 포인트를 설치하고 실행합니다.

### [-] Tracer

```python
def Tracer():
    global ImageBase
    EndIopLoadDriver = pykd.getBp(1).getOffset()
    pykd.dbgCommand("eb KdDebuggerEnabled 0")
    count = 0
    while(1):
        ReturnLogPath = PathInform(LogPath[0])
        JumpLogPath = PathInform(LogPath[1])
        JumpRLogPath = PathInform(LogPath[2])
        CallLogPath = PathInform(LogPath[3])

        Disassem = pykd.disasm()
        Instruction = Disassem.instruction()
        CurrentOffset = pykd.reg("rip") - ImageBase
        CurrentInstruction = pykd.reg("rip")
        pCallStack = pykd.reg("rsp")

        # IopLoadDriver+4c2, End driver load
        if CurrentInstruction == EndIopLoadDriver:
            break

        # Another module
        CurrentSection = VMPTracingSub.GetSectionName(CurrentInstruction)
        if CurrentSection == "Not Found Section":
            print "[*] Check Log.."
            pykd.dbgCommand("pt")
            continue

        if "call" in Instruction:
            CallLog = open(CallLogPath,'a+')
            CurrentSection = VMPTracingSub.GetSectionName(CurrentInstruction)

            # Call register
            if "call    r" in Instruction:
                ...
                continue
            # Call address
            else:
                ...
                continue

        if "ret" in Instruction:
            ReturnLog = open(ReturnLogPath,'a+')
            ...
            continue

        pykd.dbgCommand("th")
        count+=1

    return
```

트레이싱 로그를 남기기 위한 코드입니다. windbg의 `th` 명령을 이용하여 각 분기하는 부분에서 실행을 멈추도록 유도합니다. 그리고 해당 분기에 대한 명령어를 가져와 `call`, `ret` 등으로 분류하여 로그를 작성합니다.

분명 여러분은 더 나은 코드를 작성할 수 있으며 원하는 조건을 작성하여 간추려 작성할 수 있습니다.



## [0x05] Analysis

먼저 위의 스크립트로 작성된 로그입니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/vmp/vmp_03.png?raw=true">

섹션의 이름과 해당 명령의 오프셋 등이 존재합니다. 해당 부분까지 로그를 출력하는데 굉장히 긴 시간이 필요합니다. 이러한 시간을 줄이기 위해서는 어느정도의 정적 분석이 동반되어야 합니다.

예를 들어 위의 그림에서 마지막 `Call Instruction` 로그를 확인하면 아래와 같습니다.

```
[*] Call Instruction
	[*] Current Section : .shh0ya1
	[*] Current Instruction Offset : 2C6151
	[-] Count : 30530

[*] Current Instruction :fffff800`52816151 e85e7d0500      call    fffff800`5286deb4

rax=fffff80051600000 rbx=ffffd90150f02590 rcx=ffff9780886e0180
rdx=0000000000000000 rsi=ffffd9015768ee30 rdi=00000000c0000183
rip=fffff80052816151 rsp=fffff88051547738 rbp=fffff88051547780
 r8=0000000000000000  r9=ffffd90150f00260 r10=ffffd90151000160
r11=0000000000000000 r12=ffffffff80003228 r13=fffff80052550000
r14=0000000000000000 r15=fffff80052550000
iopl=0         nv up ei ng nz na pe nc
cs=0010  ss=0018  ds=002b  es=002b  fs=0053  gs=002b             efl=00040282
fffff800`52816151 e85e7d0500      call    fffff800`5286deb4


[*] Current Disassembly

fffff800`52816151 e85e7d0500      call    fffff800`5286deb4
fffff800`52816156 ac              lods    byte ptr [rsi]
fffff800`52816157 52              push    rdx
fffff800`52816158 68c5e2cf5a      push    5ACFE2C5h
fffff800`5281615d e872a00200      call    fffff800`528401d4
```

본인은 어느정도의 경험을 통해 이 로그를 제외한 상단의 로그는 VMP의 초기화 코드임을 알 수 있습니다. 자 그럼 현재 위의 로그에서 opcode를 확인하면 해당 부분이 `vmtable` 임을 예상할 수 있습니다. 실제 해당 오프셋을 IDA로 확인해보면 아래와 같습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/vmp/vmp_04.png?raw=true">

VMP로 인해 IDA는 위와 같이 명령을 해석하지 못합니다. 해당 부분을 아래와 같이 수정하여 코드를 정렬합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/vmp/vmp_05.gif?raw=true">

위의 로그를 통해 하나의 `vmtable`을 찾았습니다. 해당 코드를 재정렬하여 본인이 만든 정적인 `vmtable`은 아래와 같습니다. 

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/vmp/vmp_06.png?raw=true">

각 `vmpmacro`는 `Instruction Handler`를 통해 가상화가 적용되지 않은 함수나 또 다른 `vmptable`로 이동합니다. 시간은 걸리지만 정확하고 조건에 맞는 분석이 가능합니다!

위와 같이 로그를 확인하면 아래와 같은 정의도 가능합니다.(물론 VMP 초기화 코드가 있기 때문에 `NtQuerySystemInformation`, `ExAllocatePool` 등을 제외하고..)

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/vmp/vmp_07.png?raw=true">

경험으로 미루어 볼 때, 첫 `vmtable_00`의 경우 `NtQuerySystemInformation`이 다수 호출될 것으로 보입니다. 현재 스크립트에는 `call` 명령과 `ret` 명령의 로그만 작성되고 있습니다. VMP 초기화 코드에서 `Instruction Handler`는 `call <register>` 또는 `jmp <register>` 로 이루어진 경우가 많습니다.

이러한 과정을 거치고 어느 순간 로그에 `.text` 섹션의 코드가 작성될 것 입니다. 해당 내용까지 읽어주셔서 감사합니다. 여기까지 다 읽어주셨다면 이러한 스크립트를 좀 더 활용할 수 있도록 팁을 알려드리겠습니다.

`DriverEntry`는 `GsDriverEntry`에서 호출됩니다. 그리고 `GsDriverEntry`는 `INIT` 섹션에 존재하며 VMP로 패킹된 드라이버의 경우 `INIT` 섹션에는 `__security_init_cookie` 외 하나의 함수가 존재합니다. 바로 해당 함수가 `GsDriverEntry` 입니다. 

즉 `VmpEntryPoint`의 불필요한 코드를 넘기고 `DriverEntry` 또는 타겟 함수의 `vmtable`에서 스크립트를 실행하는 것이 더욱 효율적입니다.

{% include tip.html content="본인은 이러한 특징을 찾아내기 위해 스크립트를 매우 긴 시간 실행해봤습니다. 한번쯤은 도전해보는 것도 나쁘지 않다고 생각합니다. " %}



## [0x06] Conclusion

꽤 긴 내용의 글입니다. `pykd` 플러그인은 이러한 작업 외에도 매우 유용합니다. 예제로 있는 스크립트를 수정하여 사용하십시오. 코드의 난이도가 낮으므로 직접 맞는 조건에 맞춰 사용하고, `pykd`의 공식 문서를 참조하여 API를 활용하시길 바랍니다.

긴 글 읽어주셔서 감사합니다.

