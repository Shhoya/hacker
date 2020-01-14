---
layout: article
title: "[Rev]Side Effects of Kernel Debugging[0x02]"
key: 20200114
tags:
  - Windows
  - Reversing
  - Kernel
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] How to fix KdDebuggerNotPresent

<!--more-->

## [0x01] Introduction

`KdDebuggerEnabled` 변수의 경우, 별도의 방법이 없어도 간단하게 변경이 가능하다. 그러나 `KdDebuggerNotPresent` 변수의 경우에는 디버거가 활성화 되어있는 경우 `0`으로 세트 된다. 그렇기 때문에 이를 이용하여 커널 디버깅 여부를 판단하는 경우가 많다. 

해당 포스트는 이를 변경하여 고정하는 방법에 대한 방법론이다.

## [0x02] Environment

```
# OS : Windows 10 Pro (build 17763.914)
# Kernel : 1809
# Boot Option : Testing Mode + Debug Mode (via VirtualKD)
# VirtualMachine : TRUE

# Tools
- Windbg
- CFF Explorer
- OSRLoader
- DbgView
- WKE64
```



## [0x03] How to detect kernel debugging

간단한 예제를 통해 디버거를 탐지하는 커널 드라이버를 만들어 본다. 실제로는 더 정교한 방법으로 디버거를 탐지하여 분석을 어렵게 해야 한다. (`Common.h`에는 단순히 `DriverEntry`와 `Unload` 루틴을 만들어 놓았다.)

```c
#include "Common.h"

NTSTATUS CheckDebugger()
{
	if (!KD_DEBUGGER_NOT_PRESENT)
	{
		DbgPrint("[!] Debugging\n");
		return STATUS_FAILED_DRIVER_ENTRY;
	}
	return STATUS_SUCCESS;
}

VOID ImportFunction()
{
	DbgPrint("[#] No Debugging\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);
	DriverObject->DriverUnload = DriverUnload;

	DbgPrint("[#] Driver Load\n");
	NTSTATUS status = CheckDebugger();
	if (NT_SUCCESS(status))
	{
		ImportFunction();
		return status;
	}

	else
	{
		return status;
	}
}
```

드라이버가 로드되면 `CheckDebugger` 함수를 통해 `KdDebuggerNotPresent` 변수의 값을 확인한다. 이 때 값이 0이면 디버깅 중이므로 `STATUS_FAILED_DRIVER_ENTRY` 오류를 반환한다. 

해당 예제를 테스트 환경에서 `OSRLoader`를 이용하여 로드하려고 하면 `초기화를 호출하지 못했기 때문에 드라이버가 로드되지 않았습니다.` 라는 에러가 발생한다.

이렇게 간단한 코드라면 당연히 우회가 쉽게 가능하다. 다만 다수의 루틴에서 지속적으로 탐지하는 상황이나 좀 더 복잡하고 난독화가 극심한 경우 일일이 이 로직을 찾아내기란 쉽지 않다.

그럼 위의 예제에서 사용하는 `KdDebuggerNotPresent` 변수를 고정하는 방법을 알아본다.

## [0x04] Why can't KdDebuggerNotPresent be changed

`windbg`를 이용하여 아래의 명령들을 입력해본다.

```
// Try fix to KdDebuggerNotPresent
1: kd> db KdDebuggerNotPresent l1
fffff801`538dd393  00                                               
1: kd> eb KdDebuggerNotPresent 0x1
1: kd> db KdDebuggerNotPresent l1
fffff801`538dd393  00            

// Try fix to KdDebuggerEnabled
1: kd> db KdDebuggerEnabled l1
fffff801`538dd392  01                                               
1: kd> eb KdDebuggerEnabled 0x0
1: kd> db KdDebuggerEnabled l1
fffff801`538dd392  00      
```

확인해보면 알 수 있듯이, `KdDebuggerNotPresent`의 값은 변하지 않는다. 아래 `KdDebuggerEnabled`는 정상적으로 변경이 되었다. 

하드웨어 브레이크 포인트를 설치하면 해당 이유를 알 수 있다.

```
1: kd> ba w1 KdDebuggerNotPresent
1: kd> g
Breakpoint 1 hit
fffff801`54001863 f6c304          test    bl,4

3: kd> u @rip
kdcom!KdReceivePacket+0x4a3:
fffff801`54001863 f6c304          test    bl,4
fffff801`54001866 740f            je      kdcom!KdReceivePacket+0x4b7 (fffff801`54001877)
fffff801`54001868 c1eb08          shr     ebx,8
fffff801`5400186b 0fb6c3          movzx   eax,bl
fffff801`5400186e a2d402000080f7ffff mov   byte ptr [FFFFF780000002D4h],al
fffff801`54001877 488d4db7        lea     rcx,[rbp-49h]
fffff801`5400187b e8cc1a0000      call    kdcom!KdReceivePacket+0x1f8c (fffff801`5400334c)
fffff801`54001880 f0ff0dbd3b0200  lock dec dword ptr [kdcom!KdReceivePacket+0x24084 (fffff801`54025444)]
```

`kdcom!KdReceivePacket` 함수에서 `KdDebuggerNotPresent` 변수에 값을 쓰는 것을 확인할 수 있다.
여기에서 중요하게 확인해야 할 부분이 있다.

```
3: kd> lmDvm kdcom
Browse full module list
start             end                 module name
fffff801`54000000 fffff801`5402a000   kdcom      (export symbols)       kdbazis.dll
    Loaded symbol image file: kdbazis.dll
    Image path: kdbazis.dll
    Image name: kdbazis.dll
    Browse all global symbols  functions  data
    Timestamp:        Wed Sep 30 11:51:39 2015 (560B4E3B)
    CheckSum:         00006F45
    ImageSize:        0002A000
    Translations:     0000.04b0 0000.04e4 0409.04b0 0409.04e4
    Information from resource tables:
```

원래는 `kdcom.dll` 이어야하지만 `kdbazis.dll` 이라는 이름으로 되어있다. 이는 `VirtualKD`를 사용하는 경우 해당 모듈에 후킹을 해서 사용하기 때문인 것으로 추정된다.

그렇기 때문에 해당 부분을 패치하여 항상 `KdDebuggerNotPresent` 변수를 1로 고정시켜야 한다.

## [0x05] How to fix KdDebuggerNotPresent

나는 삽질을 했기 때문에 미리 이야기를 하겠다. 단순히 `windbg`에서 해당 위치의 코드를 패치하게 되면 OS가 바보가 되는 것을 경험할 수 있다.

때문에 직접 드라이버를 만들거나, `WKE` 툴을 이용하여야 한다. 먼저 어떻게 코드를 바꾸면 될지 해당 코드를 분석해보자.

```
48 8B 0D BD 27 00 00                    mov     rcx, cs:KdDebuggerNotPresent
C7 45 C7 FF FF FF FF                    mov     dword ptr [rbp-39h], 0FFFFFFFFh
80 E2 01                                and     dl, 1
44 89 7D D7                             mov     [rbp-29h], r15d
88 11                                   mov     [rcx], dl	; Write
F6 C3 04                                test    bl, 4
74 0F                                   jz      short loc_180001877
C1 EB 08                                shr     ebx, 8
0F B6 C3                                movzx   eax, bl
A2 D4 02 00 00 80 F7 FF+                mov     ds:0FFFFF780000002D4h, al
```

`kdbazis.dll`을 디스어셈블러로 확인하면 위와 같이 되어있다. `KdDebuggerNotPresent` 변수를 `rcx` 레지스터에 넣고, 주석으로 표시해둔 `mov [rcx], dl` 을 통해 값을 저장한다.

어떠한 결과를 초래할지 모르지만 나는 과감하게 5바이트를 패치했다.

```
88 11                                   mov     [rcx], dl	; Write
F6 C3 04                                test    bl, 4
=========================================================================
C6 01 01                                mov     [rcx], 0x1	; Write
90                                      nop
90                                      nop
```

위와 같이 패치하게 되면 `KdDebuggerNotPresent`에는 1이 고정되게 된다.
`WKE`의 `Memory Editor` 기능을 이용하여 위와 같이 코드패치를 하면 변수의 값이 고정되는 것을 확인할 수 있다.

## [0x06] Fixed KdDebuggerNotPresent via Driver

`kdcom.dll(kdbazis.dll)` 은 `System` 프로세스에 모듈로 로드된다. 때문에 `Universal Driver`로 만들기 위해서는 노력하고 있지만 조금 힘들다. 일단 커널에서의 `GetProcAddress` API를 구현하고 싶었으나 아직 그러지 못했다. 다만 `GetModuleHandle`은 어느정도 구현이 되었다. 해당 함수는 유저모드 애플리케이션에서 `DeviceIoControl`을 통해 드라이버에 특정 코드를 전달하면 호출된다. 

 ```c
NTSTATUS GetModuleInformation(const char* szModuleName)
{
	BOOLEAN tmpSwitch = FALSE;
	ULONG infoLen = 0;
	UNICODE_STRING ZwQueryString = { 0, };
	PSYSTEM_MODULE_INFORMATION pMod = { 0, };
	RtlInitUnicodeString(&ZwQueryString, L"ZwQuerySystemInformation");
	NtQuerySystemInformation_t ZwQuerySystemInformation = MmGetSystemRoutineAddress(&ZwQueryString);

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &infoLen, 0, &infoLen);
	pMod = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, infoLen, 'Sh0y');
	RtlZeroMemory(pMod, infoLen);
	status = ZwQuerySystemInformation(SystemModuleInformation, pMod, infoLen, &infoLen);
	PSYSTEM_MODULE_ENTRY pModEntry = pMod->Module;
	for (int i = 0; i < pMod->Count; i++)
	{
		if (!strcmp(pModEntry[i].FullPathName, szModuleName))
		{
			DbgPrint("[+] Find Module %s\n", pModEntry[i].FullPathName);
			TargetModule = pModEntry[i];	// Global Variable
			tmpSwitch = TRUE;
			break;
		}
	}
	ExFreePoolWithTag(pMod, 'Sh0y');
	if (!tmpSwitch)
	{
		return STATUS_NOT_FOUND;
	}
	return status;
}
 ```

아래는 `IRP Dispatch Routine` 을 통해 전달받은 `ControlCode`가 `INFINITY_EDIT` 인 경우 `KdDebuggerNotPresent` 변수를 고정하도록 코드를 패치하게 된다.

```c
	case INFINITY_EDIT:
		Status = GetModuleInformation("\\SystemRoot\\system32\\kdcom.dll");
		if (Status != STATUS_SUCCESS)
		{
			DbgPrint("[!] Not Found Module %IX\n", Status);
		}
		else
		{
			KdReceivePacket = (DWORD64)TargetModule.ImageBase + 0x1861;	// KdReceivePacket+4a1 ( Write KdDebuggerNotPresent )
			memcpy(KdReceivePacket, bWrite, 5);
			DbgPrint("[+] Patch Complete\n");
		}
	}
```

실제 어떻게 동작하는지 아래 영상을 통해 확인 가능하다.

# [+] PoC

[![KdDebuggerNot](http://img.youtube.com/vi/RjDLa2IEmnc/mq1.jpg)](https://youtu.be/RjDLa2IEmnc?t=0s) 

