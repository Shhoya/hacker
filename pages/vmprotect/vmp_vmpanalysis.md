---
title: VMP analysis
keywords: documentation, technique, debugging
date: 2020-03-10
tags: [Windows, Reversing, Dev]
summary: "VMP 동적 및 정적분석"
sidebar: vmp_sidebar
permalink: vmp_vmpanalysis.html
folder: vmprotct
---

## [0x00] Overview

VMP나 Themida로 패킹된 파일을 분석할 때 중요한 것은 운입니다. 적용할 때 단순히 패킹만 했다면 아주 감사하게 분석을 할 수 있고, Mutation과 Virtualization 을 적절하게 사용했다면 그야말로 지옥을 볼 수 밖에 없습니다.(적어도 저는 그렇습니다.)

그래서 분석하면서 느끼고 그나마 분석을 할 수 있는 패턴에 대한 내용을 준비해봤습니다.



## [0x01] VMP Packing

우선 예제 소스코드는 아래와 같습니다. 패킹 하기 전에 vmp 마커를 통해 가상화 구간을 지정했습니다. 또한 유저모드 안티 디버깅도 적용하여 패킹했습니다.

```c
#include <stdio.h>
#include <Windows.h>
#include <VMProtectSDK.h>
#pragma warning(disable:4996)
#pragma comment(lib,"VMProtectSDK64.lib")

BOOLEAN ValidationCheck()
{
	int input = 0;
	int valid = 13579;
	VMProtectBegin("testvmp");
	printf("[+] Input Key : ");
	scanf("%d", &input);

	if (input == valid)
	{
		printf("[+] Correct!\n");
		return TRUE;
	}

	else
	{
		printf("[!] Incorrect!\n");
		return FALSE;
	}
	VMProtectEnd();
}

int main()
{
	printf("Ok, VMP Test\n");
	VMProtectBeginVirtualization("Virtual");
	
	if (ValidationCheck())
	{
		for (int i = 0; i < 10; i++)
		{
			printf("w0w..\n");
		}
	}
	else
	{
		exit(1);
	}
	VMProtectEnd();
}
```



## [0x02] VMP Anti Debugging

처음에 플러그인에 존재를 몰랐기 때문에 직접 디버깅하며 찾았었습니다.(매우 어리석은 짓이지만 큰 도움이 됐었습니다.) VMP에 적용되어 있는 유저모드 안티 디버깅 기법과 이에 대한 우회방법에 대해 설명하겠습니다. 제가 사용하는 VMP 패커에서는 정확히 아래에 기법 순서대로 동작합니다.

{% include note.html content="어떠한 안티 디버깅 기법이 적용이 되어있는가에 대한 내용입니다. 기법에 대한 상세 내용은 존재하지 않습니다. 워낙 잘 알려진 기법들이기 때문입니다." %}



### [-] PEB.BeingDebugged

`IsDebuggerPresent` 함수로 더 잘 알려진 값입니다. 프로세스의 `PEB` 에 존재하는 멤버로써 디버깅 중인 경우 1로 설정됩니다. 간단하게 이 값을 0으로 설정하면 프로세스가 다시 실행되지 않는 한 바뀌지 않습니다.

x64 기준 `gs:[60h]`에 프로세스의 `PEB`가 존재하고  `gs:[60h] + 2` 위치에 `BeingDebugged` 멤버가 존재합니다.



### [-] PEB.NtGlobalFlag

마찬가지로 `PEB`에 존재하는 값입니다. 문서화 되어있으며 `GFLAGS.exe` 도구를 이용해 확인할 수 있습니다. 해당 플래그 값을 통해 디버깅 여부를 판단할 수 있습니다. 

x64 기준 `gs:[60h] + 0xbc` 위치에 해당 멤버가 존재하며 0x70인 경우 디버깅 중임을 의미합니다. 마찬가지로 0으로 설정해주면 우회가 가능합니다.



### [-] NtQueryInformationProcess

```cpp
__kernel_entry NTSTATUS NtQueryInformationProcess(
  IN HANDLE           ProcessHandle,
  IN PROCESSINFOCLASS ProcessInformationClass,
  OUT PVOID           ProcessInformation,
  IN ULONG            ProcessInformationLength,
  OUT PULONG          ReturnLength
);
```

`PROCESSINFOCLASS` 내 열거되어 있는 클래스 식별 값을 전달하여 이에 해당하는 프로세스 정보를 획득합니다. 열거되어 있는 클래스 중 `ProcessDebugPort(0x7)`, `ProcessDebugObjectHandle(0x1E)`, `ProcessDebugFlags(0x1F)`를 이용하여 디버깅 중인지 판별할 수 있습니다. 

VMP 에서는 `ProcessDebugPort`와 `ProcessDebugObjectHandle` 클래스를 이용하여 디버깅 여부를 판별합니다. 유저모드에서 syscall 을 호출하기 전에 클래스를 0으로 교체해주면 우회가 가능합니다.



### [-] NtSetInformationThread

```cpp
__kernel_entry NTSYSCALLAPI NTSTATUS NtSetInformationThread(
  HANDLE          ThreadHandle,
  THREADINFOCLASS ThreadInformationClass,
  PVOID           ThreadInformation,
  ULONG           ThreadInformationLength
);
```

`THREADINFOCLASS` 내 열거되어 있는 클래스 식별 값을 전달하여 이에  해당하는 값으로 스레드 상태를 설정합니다. 대표적으로 `ThreadHideFromDebugger(0x11)` 을 이용합니다. 말 그대로 디버거로 부터 스레드를 숨기기 때문에 디버깅이 불가능한 상태가 되며, 이미 어태치 된 디버거도 무용지물이 됩니다.

마찬가지로 호출하기 전에 클래스를 0으로 교체해주면 우회가 가능합니다.



### [-] NtClose

```cpp
__kernel_entry NTSYSCALLAPI NTSTATUS NtClose(
  HANDLE Handle
);
```

오브젝트 핸들을 닫는 루틴을 가지고 있습니다. 디버깅 중일 때 예외를 디버거에서 처리해야 된다는 점을 이용하여 `0xDEADC0DE` 라는 잘못된 핸들 값을 넘겨 디버깅이 불가능하도록 방지합니다.

마찬가지로 0으로 교체해주면 우회가 가능합니다.



## [0x03] Plugins

개인적으로 ScyllaHide 내 HookLibrary 코드를 보는 것을 추천드립니다.

- ScyllaHide : 안티 디버깅 관련된 여러가지 기법들을 선택적으로 우회할 수 있도록 만들어진 플러그인입니다.

  - https://github.com/x64dbg/ScyllaHide

- SharpOD : 마찬가지로 선택이 가능합니다. 커널 단에서 사용 가능한 몇 가지 기법이 적용되어 강력합니다.

  - https://github.com/A-new/x64dbg_plugin/tree/master/x32

  



## [0x02] Feedback

수정해야 할 내용이나 잘못된 내용이 있다면 상단에 `Feedback`을 이용하여 메일 주시면 감사하겠습니다.