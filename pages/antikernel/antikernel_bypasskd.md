---
title: KdDebuggerEnabled Bypass
keywords: documentation, technique, debugging
tags: [Windows, Reversing, Dev]
summary: "안티 커널 디버깅 우회(1)"
sidebar: antikernel_sidebar
permalink: antikernel_bypasskd.html
folder: antikernel
---

## [0x00] Overview

기존에 두 가지 전역변수를 이용하여 안티 커널 디버깅을 구현하였습니다. 이번에 우회 기법을 소개하기 앞서 실제 이 전역변수들의 역할을 알아보고, 간단한 소스코드를 통해 확인해보겠습니다.

- <a href="https://shhoya.github.io/Examples">예제 소스코드</a>



## [0x01] Anti Kernel Debugging Bypass

이제 `ObRegisterCallbacks` 우회와 커널 디버깅 방지 로직을 우회하는 코드를 구현해보겠습니다.



### [-] callbacks.h

```c
#pragma once
#include <ntifs.h>

typedef struct _CALLBACK_ENTRY 
{
	INT16							Version;
	unsigned char					unknown[6];
	POB_OPERATION_REGISTRATION		RegistrationContext;
	UNICODE_STRING					Altitude;
} CALLBACK_ENTRY, *PCALLBACK_ENTRY;

typedef struct _CALLBACK_ENTRY_ITEM 
{
	LIST_ENTRY						EntryItemList;
	OB_OPERATION					Operations1;
	OB_OPERATION					Operations2;
	PCALLBACK_ENTRY					CallbackEntry;
	POBJECT_TYPE					ObjectType;
	POB_PRE_OPERATION_CALLBACK		PreOperation;
	POB_POST_OPERATION_CALLBACK		PostOperation;
} CALLBACK_ENTRY_ITEM, *PCALLBACK_ENTRY_ITEM;

typedef struct _OBJECT_TYPE
{
	LIST_ENTRY                 TypeList;
	UNICODE_STRING             Name;
	PVOID                      DefaultObject;
	ULONG                      Index;
	ULONG                      TotalNumberOfObjects;
	ULONG                      TotalNumberOfHandles;
	ULONG                      HighWaterNumberOfObjects;
	ULONG                      HighWaterNumberOfHandles;
	unsigned char			   TypeInfo[0x78];
	EX_PUSH_LOCK               TypeLock;
	ULONG                      Key;
	LIST_ENTRY                 CallbackList;
} OBJECT_TYPE, * POBJECT_TYPE;

PVOID RegistrationHandle = NULL;
```



### [-] common.h

```c
#pragma once
#include "callbacks.h"

//============================================//
//======= DriverEntry & Unload Routine =======//
//============================================//

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath);
VOID UnloadDriver(IN PDRIVER_OBJECT pDriver);
```



### [-] main.c

단순히 현재 `KdDebuggerEnabled` 변수의 값이 존재하면 `KdDisableDebugger`, 반대의 경우 `KdEnableDebugger`를 이용하여 다시 활성화 시켜줍니다.  이 소스코드로 이전에 만든 보호 드라이버는 우회가 가능합니다.

```c
#include "common.h"

VOID Dummy()
{
	
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	pDriver->DriverUnload = UnloadDriver;

	if (*KdDebuggerEnabled)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] Debugger Disable\n");
		KdDisableDebugger();
	}
	else
	{
		DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] Debugger Enable\n");
		KdEnableDebugger();
	}

	POBJECT_TYPE *obType = PsProcessType;
	PCALLBACK_ENTRY_ITEM CallbackEntry = NULL;
	CallbackEntry = (*obType)->CallbackList.Flink;

	if (MmIsAddressValid(CallbackEntry))
	{
		CallbackEntry->PreOperation = &Dummy;
	}
	return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);

}
```



## [0x02] Proof Of Concept

영상을 확인하면, 보호 드라이버가 로드되어 `notepad.exe`를 보호하고 있으나, 위에서 만든 우회 드라이버를 로드하면 프로세스 디버깅이 가능하고 커널 디버깅을 탐지하지 못하는 것을 알 수 있습니다.

<iframe src="https://youtube.com/embed/mCfIzeYHdbM" allowfullscreen="" width="720" height="365"></iframe>



## [0x03] Constraint

하지만 마찬가지로 제약사항이 존재합니다. 우회 드라이버를 로드하고 커널 디버깅을 시도하기 위해 `windbg` 에서 브레이크 포인트 예외를 발생시켜도 디버깅이 불가합니다. `KdDisableDebugger` 함수를 통해 디버거를 비활성화 했기 때문입니다. 뿐만아니라, 기존에 커널 디버깅을 위해 브레이크 포인트를 설정하였더라도 동작하지 않습니다.

저는 유저모드에서의 디버거 뿐 아니라, 커널모드의 디버거까지 자유롭게 사용하고 싶습니다. 저는 위와 같은 제약이 생긴 이유가 `KdDisableDebugger` 내에서 `KdpSuspendAllBreakpoints` 함수 때문이라고 생각했습니다.

`KdDebuggerEnabled` 변수의 경우 브레이크 포인트 예외와 깊은 관계를 가지고 있지 않습니다. 단지 `windbg` 에서 `pause` 기능 자체가 해당 변수와 관련이 있기 때문에 `pause` 가 되지 않는 것 뿐입니다.

`windbg`는 아래와 같이 `KdCheckForDebugBreak` 함수를 통해 현재 디버그 모드의 상태를 보고 `DbgBreakPointWithStatus` 함수로 브레이크 예외를 발생시켜 디버깅이 가능하도록 합니다.

```c
void KdCheckForDebugBreak()
{
  if ( !KdPitchDebugger && (_BYTE)KdDebuggerEnabled || KdEventLoggingEnabled )
  {
    if ( (unsigned __int8)KdPollBreakIn() )
      DbgBreakPointWithStatus(1i64);
  }
}
```

그래서 저는 `KdDisableDebugger` 함수를 호출하는 것이 아닌 필요 변수들의 값만 설정하여 두 가지 모드의 디버깅이 모두 가능한 상태로 만들기로 했습니다.



## [0x04] Conclusion

`Anti Kernel Debugging Bypass` 프로젝트의 소개에서 깊은 곳에서 궁극적으로 디버깅 중임을 알아차리지 못하게 하는 것이 이 프로젝트의 목표라고 이야기 했습니다. 다음 챕터에서는 `Control Debugger` 라고 불리는 디버거를 컨트롤하며 안티 디버깅 기법을 우회하는 기법에 대해 공개하겠습니다.