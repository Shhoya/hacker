---
title: ObRegisterCallbacks Bypass
keywords: documentation, technique, debugging
date: 2020-03-09
tags: [Windows, Reversing, Dev]
summary: "ObRegisterCallbacks Bypass(2)"
sidebar: antikernel_sidebar
permalink: antikernel_bypassob2.html
folder: antikernel
---

## [0x00] Overview

이전 챕터에서 `ObRegisterCallbacks` 에 대해 깊게 알아봤습니다. 이번에는 소개한대로 ObRegisterCallbacks Bypass 에 대해 알아보겠습니다.  소스코드는 `ControlDebugger` 라는 이름으로 만들어집니다. `ObRegisterCallbacks` 를 포함한 커널 디버깅 방지 우회 기능까지 들어가 있습니다.

- <a href="https://shhoya.github.io/Examples">예제 소스코드</a>



## [0x01] ObRegisterCallbacks Bypass

자 이제 코드를 작성해보겠습니다. 이 드라이버는 앞으로 커널 디버깅 방지, 프로세스 디버깅 방지를 우회하기 위한 드라이버입니다. 

하지만 우선 간단한 코드로 `ObRegisterCallbacks` 를 우회하는 방법을 알아보겠습니다.

### [-] callbacks.h

이전 챕터에서 문서화되지 않은 구조체들에 대한 정의와 `ObUnRegisterCallbacks`의 파라미터로 사용 될 `RegistrationHandle`이 선언되어 있습니다.

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

드라이버 진입점과 드라이버 언로드에 대한 함수 선언 헤더입니다.

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

```c
#include "common.h"

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	pDriver->DriverUnload = UnloadDriver;
	POBJECT_TYPE *obType = PsProcessType;
	PCALLBACK_ENTRY_ITEM CallbackEntry = NULL;
	CallbackEntry = (*obType)->CallbackList.Flink;
	RegistrationHandle = CallbackEntry->CallbackEntry;
	ObUnRegisterCallbacks(RegistrationHandle);

	return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);

}
```

이전 챕터에서 학습한대로 `OBJECT_TYPE` 의 `CallbackList`를 이용하여 `ObUnRegisterCallbacks`를 호출하고 있습니다. 너무 간단하기도 하지만 문제가 없지는 않습니다.

## [0x02] Constraint

1.  내가 원하는 콜백 루틴만을 해제하는게 불가능하다. 물론 `Altitude` 값을 알고 있다면 가능할 것으로 보입니다.
2. 드라이버 언로드 루틴에서 잘못된 핸들을 전달할 수 있다.

1번의 경우 제 짧은 지식으로는 `Altitude` 값으로 특정 드라이버의 루틴을 해제하는게 가능할 것으로 보입니다.

2번의 경우를 말해보자면, 현재 `AntiKernelDebugging.sys` 의 드라이버 언로드 루틴을 확인해보면 이해할 수 있습니다.

```c
VOID UnloadDriver(IN PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);
	
	PsRemoveLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
	if (hRegistration)	// 콜백 등록에 실패할 경우 예외 처리
	{
		ObUnRegisterCallbacks(hRegistration);
	}
	
	DbgPrintEx(DPFLTR_ACPI_ID, 3, "[INFO] Driver unload success\n");
}
```

현재 `hRegistration`에 값이 있는 경우, `ObUnRegisterCallbacks` 함수를 호출합니다. 그렇기 때문에 현재 우회 드라이버는 아무 문제없이 동작합니다.

그러나 혹여 예외처리가 되어있지 않다면, 잘못된 핸들 전달로 인한 블루 스크린을 맞이하게 됩니다.



## [0x03] Solution

`main.c` 부분만 아래와 같이 바꿔 진행해봅니다.

```c
#include "common.h"

VOID Dummy()
{
	
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	pDriver->DriverUnload = UnloadDriver;
	POBJECT_TYPE *obType = PsProcessType;
	PCALLBACK_ENTRY_ITEM CallbackEntry = NULL;
	CallbackEntry = (*obType)->CallbackList.Flink;
	CallbackEntry->PreOperation = &Dummy;
	/*RegistrationHandle = CallbackEntry->CallbackEntry;
	ObUnRegisterCallbacks(RegistrationHandle);*/

	return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);
}
```

`Dummy` 라는 이름으로 더미 함수를 하나 만들었습니다. 그리고 `CallbackEntry` 의 `PreOperation`을 `Dummy` 함수로 바꿨습니다.

끝입니다. 이제 `ObRegisterCallbacks` 로 등록된 콜백 루틴에서 벗어났습니다.

{% include warning.html content="테스트 후 드라이버를 언로드 할 때, 우회 드라이버부터 언로드 시 블루스크린이 발생합니다. 콜백 루틴이 덮어씌워져있기 때문입니다. antikerneldebugging.sys -> controldebugger.sys 순으로 해제하여야 정상 해제 됩니다. " %}



## [0x04] Proof Of Concept

영상을 확인해보면, 프로세스 디버깅 방지를 회피하여 디버깅이 가능한 것을 확인할 수 있습니다.
하지만 여전히 디버그 로그에서는 커널 디버깅을 탐지하고 있습니다.

<iframe src="https://youtube.com/embed/uig6EMTQHNI" allowfullscreen="" width="720" height="365"></iframe>



## [0x05] Conclusion

이제 커널 디버깅 방지를 우회하는 일만 남았습니다. 어서 또 다른 프로젝트도 작성해야 하는데 많은 내용을 넣으려 하니 계속 길어지고 있습니다.

어쨋든 이제 마지막 관문만이 남았습니다.

