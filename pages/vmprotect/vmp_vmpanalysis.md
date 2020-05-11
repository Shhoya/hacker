---
title: VMP analysis
keywords: documentation, technique, debugging
date: 2020-03-10
tags: [Windows, Reversing, Dev]
summary: "VMP 동적 및 정적분석"
sidebar: vmp_sidebar
permalink: vmp_vmpanalysis.html
folder: vmprotect
---

## [0x00] Overview

VMP나 Themida로 패킹된 파일을 분석할 때 중요한 것은 운입니다. 적용할 때 단순히 패킹만 했다면 아주 감사하게 분석을 할 수 있고, Mutation과 Virtualization 을 적절하게 사용했다면 그야말로 지옥을 볼 수 밖에 없습니다.(적어도 저는 그렇습니다.)

그래서 분석하면서 느끼고 그나마 분석을 할 수 있는 패턴에 대한 내용을 준비해봤습니다.

{% include warning.html content="본 저자는 VMP로 보호된 프로그램 해제에 대한 막연한 질문 또는 의뢰를 받지 않습니다." %}

## [0x01] Analysis

먼저 `Mutation` 과 `Virtualization` 은 다른 의미를 지닙니다. `Mutation`은 말 그대로 돌연변이를 일으킵니다. 어셈블리를 복잡하게 만들어주는 역할을 합니다. 그에 비해 `Virtualization`은 내부에 특수한 가상 CPU(명령어 해석)를 두고, 가상 CPU에서 복잡한 명령어들을 통해 코드를 실행합니다.

저는 코드 가상화 부분을 분석해봤습니다. 많은 내용들을 보았지만 사실 이해가 되지 않았습니다. 다만 분석하면서 몇 가지 패턴을 찾는데는 성공하여 동적 분석을 하며 특정 VM Macro가 어떤 함수를 호출하는지에 대해 분석할 수 있었습니다.

저는 몇 가지 용어를 정의했습니다.

- `vmmacro` : 여러 개의 매크로 함수가 존재, 특정 패턴으로 이루어져 있음
- `vmmacro_handler` : vmmacro를 호출하는 `push` 와 `call`명령어 세트
- `vmtable` : vmmacro의 집합

정확한 용어를 알지 못하므로 위와 같이 정의했습니다. 그럼 이전 챕터에서 만든 패킹 된 예제를 가지고 분석을 진행해보겠습니다.

### [-] EntryPoint

패킹을 거치고나면 EntryPoint가 `.vmp1` 섹션에 위치하게 되며 아래의 그림과 같이 구성되어 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_00.png?raw=true">

내부에는 알 수없는 명령어들로 가득합니다. EP는 vmp에서 실행 압축을 해제하고, 옵션에 따라 안티 디버깅 및 안티 VM 등의 기능을 수행합니다. 실제 분석해야 할 곳은 실행 압축이 해제되는 `.text` 섹션입니다. 아래와 같이 비어있는 `.text` 섹션에 하드웨어 브레이크 포인트를 설치하고 실행합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_01.png?raw=true">

실행 후에 특정 위치에서 실행이 멈추게 됩니다. 확인해보면 실행 압축을 해제하며 `.text` 섹션에 코드를 복사합니다. 해당 위치에서 `CTRL+F9(Execute till Return)`을 입력하면 리턴 명령을 만날때까지 실행하게 됩니다. 실행 압축이 해제되는 것을 직접 확인할 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_02.png?raw=true">

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_03.gif?raw=true">



### [-] vmtable & vmmacro_handler pattern

본격적으로 `.text` 섹션 위치에서 가상화 코드들을 확인해봅니다. 위에서 코드가 모두 풀리면 `ret` 명령에서 동작을 멈춥니다. `Step Over` 명령을 통해 다음 명령을 확인하면 확실하게 `vmmacro_handler` 를 만날 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_04.png?raw=true">

여기서 `vmmcaro_handler` 패턴에 대해 발견했습니다. `68 ?? ?? ?? ?? E8 ?? ?? ?? ?? <??>` 패턴을 가지고 있으며 `<>` 안에 값은 더미 값입니다(물론 의미있는 값이 간혹 있지만 아래 그림을 보면 이해가 될 것 입니다.). 이 패턴을 토대로 현재 명령에서 명령을 다시 어셈블하면 아래와 같은 형태를 갖추게 됩니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_05.png?raw=true">

이 패턴을 기억하며 스크롤을 위로 올려 더미 바이트를 nop으로 변환하고 아래와 같이 정렬합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_06.gif?raw=true">

이러한 `vmmacro_handler`의 집합을 저는 `vmtable`로 정의하였습니다. 



### [-] Sections

이제 위의 `vmtable`과 `vmmacro_handler` 패턴, 스택을 이용해 섹션 분석을 진행해보도록 하겠습니다. 우선 실행 압축이 해제되었습니다. `.vmp0` 섹션에도 `.text` 섹션과 같이 실행압축을 해제해줘야 합니다. 이를 토대로 제가 세운 가설은 아래와 같습니다.

1. `.vmp1` 섹션은 VMProtect가 사용하는 초기화 코드(안티 디버깅, 실행 압축 해제 등)가 저장된다.
2. `.text` 섹션에는 기존의 코드가 존재하며 적용되어 있는 구간이나 기능에 따라 다르다.
3. `.vmp0` 섹션에는 `.text` 섹션의 원래 코드를 계산하여 실행할 수 있도록 가상 CPU 명령들이 존재한다.

즉 가상 CPU로 명령을 해석하는 `vmmacro`는 `.vmp0` 섹션과 `.vmp1` 섹션 모두에 존재합니다. 다만 실제 원본 코드와 관련된 섹션은 `.vmp0` 섹션으로 보입니다.



### [-] Destroy Functions

또 한가지 확인할 수 있는 패턴이 존재하는데, 덤프를 생성하여 `IDA`를 통해 열어보면 아래와 같은 형태를 띄게 됩니다.
바로 함수를 분리하여 분석을 어렵게 만들어놨습니다. `jmp`명령을 통해 함수의 에필로그 부분을 실행하는 것을 볼 수 있습니다. 함수의 프롤로그와 에필로그 사이에 더미 명령(0xCC)를 넣어 디버깅 시 혼란을 주기 위함으로 보입니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_08.png?raw=true">



### [-] Analysis

`Virtualizaiton` 에서 대부분 원래의 로직을 실행할 때 가상 CPU에서 연산을하여 스택에 저장하고 `ret` 명령을 통해 실행한다는 것입니다. 디버거에는 `Execute till return` 기능이 존재하고 이를 유용하게 사용할 수 있습니다. `windbg`의 경우에는 분기문을 만나면 멈추는 기능까지 존재합니다.

{% include note.html content="물론 조건분기와 같은 내용의 경우 가상 CPU 내에서 난독화 등을 통해 직접 연산하기도 합니다. " %}

먼저 해당 프로젝트에서 만든 예제를 통해 실행하여 입력 값을 받는 부분을 간략하게 분석해보겠습니다. `scanf`를 사용하였으므로 `NtReadFile` 함수에 하드웨어 브레이크 포인트를 설치하고 입력 값을 입력합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_07.png?raw=true">

`Execute till Return` 기능을 이용해 콜 스택을 따라가다보면 `ucrtbase.__stdio_common_vfscanf` 함수 위치로 돌아오게됩니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_09.png?raw=true">

리턴 명령을 통해 복귀하면 `.text` 섹션의 특정 위치임을 볼 수 있습니다. 아래 그림에서 `scanf` 함수를 호출한 함수를 확인해보면 `.vmp0` 섹션에 위치한 것을 확인할 수 있습니다. `vmmacro`가 존재하지 않는 것으로 보아 `mutation` 된 것으로 보입니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_10.png?raw=true">

계속해서 분석을 진행해보겠습니다. 위의 위치에서 두번의 리턴을 거치면 아래와 같이 `vmmacro`를 호출하는 명령을 볼 수 있습니다. 위에서 확인한대로 바이트를 `NOP` 명령으로 패치하며 정렬합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_11.png?raw=true">

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_12.png?raw=true">

해당 `vmmacro`로 진입하여 `Execute till Return` 기능을 사용하면 `.text` 섹션으로 돌아옵니다. 위에서 말한 것과 같이 가상 CPU에서 복잡한 연산을 거친 후 스택에 넣어 `ret` 명령을 통해 실제 함수를 실행하는 것입니다. 이렇게 코드 가상화가 적용되어 있는 경우 어느정도 분석이 가능합니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_13.gif?raw=true">

이러한 내용들을 토대로 `windbg` 의 `pykd` 모듈을 이용하여 로깅을 할 수 있습니다. 

1. 분석하기 위한 함수의 위치의 시작과 로깅을 종료될 시점을 설정
2. `pe` 모듈을 이용하여 각 섹션 영역을 확인
3. `windbg` 내 트레이싱 명령들(`th`, `ph`, `pct` 등) 을 이용하여 가상 CPU 진입 시 컨트롤 및 로깅
4. 가상 CPU 내에서 `call` 또는 `ret`, `jmp <register>` 명령들에 대해 다음 실행될 섹션이 `.text` 섹션인 경우 로깅

저는 실제 위와 같은 로직의 스크립트를 제작하여 아래와 같이 분석하였습니다. 매우 유용한 분석 방법이라고 생각됩니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/antikernel/vmp_14.png?raw=true">



## [0x02] NtProtectVirtualMemory

약간 부록의 느낌의 주제입니다. VMP 기능 중 `Memory Protection` 이라는 기능을 사용하면 일반적인 후킹이 불가능한 것을 알 수 있습니다. 해당 이유는 `NtProtectVirtualMemory` 함수를 VMP에서 후킹해놓기 때문입니다.

후킹을 하기 위해 거의 필수적으로 사용되는 함수가 `VirtualProtect` 함수입니다. 메모리 보호 기능이 적용된 vmp 프로그램에 후킹하기 위한 두 가지 방법을 소개합니다.

### [-] Restore Bytes

간단하게 원래의 바이트 코드로 복구해줍니다. `MinHook` 과 같은 후킹 라이브러리를 이용하는 경우에는 해당 방법말고는 찾지 못했습니다. `MinHook`을 예로 들면 라이브러리 내 `VirtualProtect` 함수를 사용하기 때문에 라이브러리를 고치지 않는 이상 아래와 같은 방법으로 복구를 해줘야 잘 동작했습니다.

```cpp
{
		BYTE unHooked[5] = { 0x4C,0x8B,0xD1,0xB8,0x50 };
		HMODULE hModule = GetModuleHandleA("ntdll.dll");
		FARPROC pNtVirtualProtect = GetProcAddress(hModule, "NtProtectVirtualMemory");
		WriteProcessMemory(GetCurrentProcess(), pNtVirtualProtect, unHooked, 5, NULL);
}
```



### [-] Make NtProtectVirtualMemory

바로 `syscall` 명령을 이용하여 직접 호출하는 방법입니다. 현재 커널의 경우 `0x50` 이 `NtProtectVirtualMemory` 함수의 `syscall` 번호입니다. 

```
mov r10,rcx
mov eax,50
test byte ptr ds:[7FFE0308],1
jne ntdll.7FF98A63CAC5
syscall 
ret 
int 2E
ret 
```

재배치가 필요없기 때문에 위의 바이트를 그대로 가상 메모리에 할당하고 실행하면 잘 동작하는 것을 볼 수 있습니다.

```c++
#include <stdio.h>
#include <Windows.h>
#include <ntstatus.h>

typedef NTSTATUS(NTAPI *PFNTPROTECTVIRTUALMEMORY)(
	IN HANDLE               ProcessHandle,
	IN OUT PVOID            *BaseAddress,
	IN OUT PULONG           NumberOfBytesToProtect,
	IN ULONG                NewAccessProtection,
	OUT PULONG              OldAccessProtection
	);

BYTE bNtProtect[11] = {
					 0x4C,0x8B,0xD1,
					 0xB8,0x50,0x00,0x00,0x00,
					 0x0F,0x05,
					 0xC3 };


void testFunction()
{
	MessageBoxA(NULL, "Hello", "Shh0ya", MB_OK);
}

int main()
{
	BYTE cc[1] = { 0xCC };
	DWORD dwProtect = 0;
	FARPROC pMem = (PROC)testFunction;
	MEMORY_BASIC_INFORMATION info;
	ZeroMemory(&info, sizeof(info));
	VirtualQuery(pMem, &info, sizeof(MEMORY_BASIC_INFORMATION));
	fprintf(stdout,"BaseAddress : %IX\nAllocProtect : %X\nProtect : %X\nState : %X\n", info.BaseAddress,info.AllocationProtect,info.Protect,info.State);
	
	//========================================================//
	//===============  NtProtectVirtualMemory  ===============//
	//========================================================//
	LPVOID NtProtectVirtualMemory_ = VirtualAlloc(NULL, 100, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);;
	ULONG size = 10;
	memcpy(NtProtectVirtualMemory_, bNtProtect, 11);
	ULONG uProtect = 0;
	PULONG pSize = &size;

	NTSTATUS Flag = ((PFNTPROTECTVIRTUALMEMORY)NtProtectVirtualMemory_)(GetCurrentProcess(), (PVOID*)&pMem, pSize, PAGE_EXECUTE_READWRITE, &uProtect);
	if (Flag != STATUS_SUCCESS)
	{
		fprintf(stderr, "[+] Syscall Error");
		return -1;
	}

	else
	{
		fprintf(stdout,"================================================================\n");
		VirtualQuery(pMem, &info, sizeof(MEMORY_BASIC_INFORMATION));
		fprintf(stdout,"BaseAddress : %IX\nAllocProtect : %X\nProtect : %X\nState : %X\n", info.BaseAddress, info.AllocationProtect, info.Protect, info.State);
		return 0;
	}
}
```



## [0x03] Conclusion

VMProtect에 대한 분석 방법론을 좀 더 쉽고 획기적이게 작성해보고 싶었으나, 아직 멀었습니다. 해당 프로젝트는 추후에 더 업데이트해서 고급스러운(?) 내용으로 돌아오겠습니다.