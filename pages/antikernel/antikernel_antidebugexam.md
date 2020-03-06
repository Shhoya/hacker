---
title: Anti Kernel Debugging Tutorial
keywords: documentation, technique, debugging
tags: [Windows, Reversing, Dev]
summary: "드라이버를 이용한 커널 디버깅 방지"
sidebar: antikernel_sidebar
permalink: antikernel_antidebugexam.html
folder: antikernel
---

## [0x00] Overview

이전 챕터에서 두 가지의 콜백 루틴을 등록하는 함수에 대해 알아봤습니다. 굳이 콜백 루틴으로 접근한 이유는 간단하고 강력하기 때문입니다. 이번 챕터에서는 본격적으로 안티 디버깅 기법을 적용하여 동작을 분석하고 최대한 깊은 곳에서 우회하는 법에 대해 알아보겠습니다.

- <a href="https://github.com/shhoya/Examples">예제 소스코드</a>

## [0x01] Tutorial Design

우선 기존에 사용하던 헤더와 소스코드를 활용할 것입니다. 다만 조금은 정리할 필요를 느꼈기에 아래와 같이 정의하고 시작하겠습니다. 아래의 설계대로 진행이 되며, 추가되는 경우 바로 수정할 것이니 비어있는 부분은 신경쓰지 않아도 됩니다.

### [-] common.h

```c++
#pragma once
#include <ntifs.h>

/*//////////////////////////////////////////////
# File : common.h
# Desc : 모든 함수와 구조체, 전역변수 등으 선언
*///////////////////////////////////////////////


#define PROCESS_TERMINATE       0x0001
#define PROCESS_VM_OPERATION    0x0008
#define PROCESS_VM_READ         0x0010
#define PROCESS_VM_WRITE        0x0020

//============================================//
//======= DriverEntry & Unload Routine =======//
//============================================//

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath);
VOID UnloadDriver(IN PDRIVER_OBJECT pDriver);

//============================================//
//============= Callback Routine =============//
//============================================//

VOID LoadImageNotifyRoutine(IN PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo);
OB_PREOP_CALLBACK_STATUS PreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);
VOID PostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION pOperationInformation);

//============================================//
//========== User-defined Function  ==========//
//============================================//

VOID TerminateProcess(IN HANDLE pid);
NTSTATUS ObCallbackReg();
BOOLEAN GetOffset(PEPROCESS Process);
BOOLEAN GetPebOffset();


//============================================//
//=========== Undocumented API ===============//
//============================================//

typedef NTSTATUS(*NtQueryInformationProcess_t)(
	IN    HANDLE              ProcessHandle,
	IN    PROCESSINFOCLASS    ProcessInformationClass,
	OUT   PVOID               ProcessInformation,
	IN    ULONG               ProcessInformationLength,
	OUT   PULONG              ReturnLength
	);

typedef PVOID(*PsGetProcessDebugPort_t)(
	IN	PEPROCESS Process
	);

//============================================//
//======= Structure & Global Variable ========//
//============================================//

typedef struct _IMPORT_OFFSET
{
	int			UniqueProcessid_off;
	int			ActiveProcessLinks_off;
	int			ImageFileName_off;
	int			PEB_off;
}IMPORT_OFFSET;

PVOID hRegistration = NULL;	// ObUnRegisterCallbacks 전용
HANDLE hPid;
IMPORT_OFFSET iOffset;
PsGetProcessDebugPort_t PsGetProcessDebugPort;
BOOLEAN bOnOff = FALSE;
const char szSystem[] = "System";
const wchar_t szNtQueryInformationProcess[] = L"NtQueryInformationProcess";
const char szTarget[] = "notepad.exe";
```



### [-] offset.h

```c++
#pragma once
#include "common.h"

/*/////////////////////////////////////
# File : offset.h
# Desc : 오프셋 관련 함수에 대한 정의
*/////////////////////////////////////


/*
# Name  : GetOffset
# Param : PEPROCESS
# Desc  : EPROCESS 구조체의 특정 멤버 오프셋 구하는 함수
*/
BOOLEAN GetOffset(PEPROCESS Process)
{
	BOOLEAN success = FALSE;
	HANDLE PID = PsGetCurrentProcessId();
	PLIST_ENTRY ListEntry = { 0, };
	PLIST_ENTRY NextEntry = { 0, };

	for (int i = 0x80; i < PAGE_SIZE - 0x10; i += 4)
	{
		if (*(PHANDLE)((PCHAR)Process + i) == PID)
		{
			ListEntry = (PVOID*)((PCHAR)Process + i + 0x8);
			if (MmIsAddressValid(ListEntry) && MmIsAddressValid(ListEntry->Flink))
			{
				NextEntry = ListEntry->Flink;
				if (ListEntry == NextEntry->Blink)
				{
					iOffset.UniqueProcessid_off = i;
					iOffset.ActiveProcessLinks_off = i + 8;
					success = TRUE;
					break;
				}
			}
		}
	}
	if (!success)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[ERR] Not found offset\n");
		return success;
	}

	// ImageFileName Offset 
	success = FALSE;
	for (int i = iOffset.ActiveProcessLinks_off; i < PAGE_SIZE; i++)
	{
		if (!strncmp((PCHAR)Process + i, szSystem, 6))
		{
			iOffset.ImageFileName_off = i;
			success = TRUE;
			break;
		}
	}
	if (!success)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[ERR] Not found offset\n");
		return success;
	}

	if (!GetPebOffset())
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[ERR] Not found offset\n");
		return success;
	}
	return success;
}

/*
# Name  : GetPebOffset
# Param : x
# Desc  : EPROCESS 구조체 내 PEB 오프셋 구하는 함수
*/
BOOLEAN GetPebOffset()
{
	int LinkOffset = iOffset.ActiveProcessLinks_off;
	int ProcName = iOffset.ImageFileName_off;
	BOOLEAN success = FALSE;
	PEPROCESS Process = PsGetCurrentProcess();
	UNICODE_STRING routineName = { 0, };

	RtlInitUnicodeString(&routineName, szNtQueryInformationProcess);
	NtQueryInformationProcess_t NtQueryInformationProcess = MmGetSystemRoutineAddress(&routineName);

	for (int i = 0; i < 0x10; i++)
	{
		PROCESS_BASIC_INFORMATION ProcessInformation = { 0, };
		PLIST_ENTRY ListEntry = (PVOID*)((PCHAR)Process + LinkOffset);
		Process = ((PCHAR)ListEntry->Flink - LinkOffset);
		HANDLE Key = NULL;

		if (ObOpenObjectByPointer(Process, NULL, NULL, NULL, *PsProcessType, KernelMode, &Key) 
			== STATUS_SUCCESS)
		{
			PULONG Ret = NULL;
			NtQueryInformationProcess(
				Key, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), Ret);

			ZwClose(Key);
		}

		if (ProcessInformation.PebBaseAddress)
		{
			for (int j = iOffset.ActiveProcessLinks_off; j < PAGE_SIZE - 0x10; j += 4)
			{
				if (*(PHANDLE)((PCHAR)Process + j) == ProcessInformation.PebBaseAddress)
				{
					iOffset.PEB_off = j;
					success = TRUE;
					return success;
				}
			}
		}
	}
	return success;
}
```



### [-] callbacks.h

```c++
#pragma once
#include "offset.h"

/*//////////////////////////////////////////////
# File : callbacks.h
# Desc : 콜백 루틴에 대한 정의와 관련 함수 정의
*///////////////////////////////////////////////


/*
# Name  : LoadImageNotifyRoutine
# Param : PUNICODE_STRING, HANDLE, PIMAGE_INFO
# Desc  : 
*/
VOID LoadImageNotifyRoutine(IN PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo)
{
	// your code
}

/*
# Name  : PreCallback
# Param : PVOID, POB_PRE_OPERATION_INFORMATION
# Desc  :
*/
OB_PREOP_CALLBACK_STATUS PreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	// your code

}

/*
# Name  : PostCallback
# Param : PVOID, POB_POST_OPERATION_INFORMATION
# Desc  : 사용하지 않을 수 있음
*/
VOID PostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	// your code

}

/*
# Name  : TerminateProcess
# Param : HANDLE
# Desc  : 프로세스 강제 종료 시 사용
*/
VOID TerminateProcess(IN HANDLE pid)
{
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES obAttr = { 0, };
	CLIENT_ID cid = { 0, };

	obAttr.Length = sizeof(obAttr);
	obAttr.Attributes = OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE;
	cid.UniqueProcess = pid;

	if (ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &obAttr, &cid) 
		== STATUS_SUCCESS)	// Get process handle
	{
		if (ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED) 
			== STATUS_SUCCESS)	// Terminate process
		{
			DbgPrintEx(DPFLTR_ACPI_ID, 3,
				"[INFO] Success terminate process\n");
		}
		else
		{
			DbgPrintEx(DPFLTR_ACPI_ID, 0,
				"[ERR] Failed terminate process\n");
		}
	}
	else
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0,
			"[ERR] Failed open process\n");
	}
}

/*
# Name  : ObCallbackReg
# Param : x
# Desc  : ObRegisterCallbacks 호출
*/
NTSTATUS ObCallbackReg()
{
	OB_CALLBACK_REGISTRATION obRegistration = { 0, };
	OB_OPERATION_REGISTRATION opRegistration = { 0, };

	obRegistration.Version = ObGetFilterVersion();	// Get version
	obRegistration.OperationRegistrationCount = 1;	// OB_OPERATION_REGISTRATION count, opRegistration[2] 인 경우 2
	RtlInitUnicodeString(&obRegistration.Altitude, L"300000");	// 임의의 Altitude 지정
	obRegistration.RegistrationContext = NULL;

	opRegistration.ObjectType = PsProcessType;
	opRegistration.Operations = OB_OPERATION_HANDLE_CREATE;	// Create 또는 Open 시 동작
	opRegistration.PreOperation = PreCallback;	// PreOperation 등록
	opRegistration.PostOperation = PostCallback;	// PostOperation 등록

	obRegistration.OperationRegistration = &opRegistration;	// OperationRegistration 등록

	return ObRegisterCallbacks(&obRegistration, &hRegistration);
}
```



### [-] main.c

```c++
#include "callbacks.h"

/*//////////////////////////////////////////////////////
# File : main.c
# Desc : 드라이버 진입점과 종료 루틴, 사용자 정의 함수
*///////////////////////////////////////////////////////


NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	
	pDriver->DriverUnload = UnloadDriver;
	DbgPrintEx(DPFLTR_ACPI_ID, 3, "[INFO] Driver load success\n");



	return STATUS_SUCCESS;
}

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



## [0x02] Anti Debugging Technique

먼저 어떻게 디버깅을 방지할 것인가에 대한 생각부터 해보겠습니다. 제가 설계한 방법은 각 콜백 루틴 별로 아래와 같습니다.

- PreCallback : `EPROCESS` 구조체 내에 `DebugPort` 멤버를 이용하여 프로세스를 디버깅 방지
- PostCallback : 미설계
- LoadImageNotifyRoutine : 프로세스 이미지가 로드 될 때 `ntoskrnl` 내 전역변수와 함수를 이용하여 커널 디버깅 방지

`ObRegisterCallback`의 경우 프로세스 내에서 핸들 조작이 일어나면 계속해서 동작하기 때문에 지속적으로 프로세스를 감시하는데 유용합니다. 즉, 프로세스가 실행되고 디버거가 어태치를 하든, 디버거로 실행을 하든 탐지가 가능하다는 이야기 입니다.

`LoadImageNotifyRoutine`의 경우 커널에 존재하는 디버깅 관련 전역 변수와 함수를 이용합니다. 실제 중요한 내용은 해당 루틴에 있습니다. 재미있는 일들이 가능하니 상세하게 살펴보길 바랍니다.



### [-] DriverEntry & UnloadDriver Define

우선 비어있는 드라이버 진입점을 정의해보겠습니다. 드라이버 진입점에서 사용할 전역변수와 구조체는 `common.h` 내에 정의되어 있습니다.

- `PVOID hRegistration` : 드라이버 언로드 시, 등록한 `ObRegisterCallbacks`를 해제할 때 사
- `PsGetProcessDebugPort_t PsGetProcessDebugPort` : `PsGetProcessDebugPort` 함수 호출용

다음은 `PsGetProcessDebugPort_t` 의 선언입니다.

```c++
typedef PVOID(*PsGetProcessDebugPort_t)(
	IN	PEPROCESS Process
	);
```

문서화되지 않은 API로, `ntoskrnl` 내 존재합니다. 프로세스 객체를 전달하여 해당 프로세스의 디버그 포트 정보를 반환합니다. 위의 내용을 토대로 아래와 같이 작성합니다.

```c++
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	UNICODE_STRING PsGetProcessDebugPortString = { 0, };
	pDriver->DriverUnload = UnloadDriver;
	DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] Driver load success\n");

	if (GetOffset(PsGetCurrentProcess()))
	{
		RtlCreateUnicodeString(&PsGetProcessDebugPortString, L"PsGetProcessDebugPort");
		PsGetProcessDebugPort = (PsGetProcessDebugPort_t)MmGetSystemRoutineAddress(&PsGetProcessDebugPortString);

		if (ObCallbackReg() == STATUS_SUCCESS)
		{
			PsSetLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
		}
	}
	return STATUS_SUCCESS;
}
```

1. `GetOffset` 호출을 통해 `EPROCESS` 구조체 내 필요한 멤버의 오프셋을 알아옵니다.
2. `MmGetSystemRoutineAddress` 함수를 이용하여 `PsGetProcessDebugPort` 함수를 찾아야 합니다. `PUNICODE_STRING` 을 파라미터로 넘겨줘야 하기 때문에 `UNICODE_STRING` 구조체를 생성합니다.
3. `MmGetSystemRoutineAddress` 를 이용해 `PsGetProcessDebugPort` 함수의 주소를 얻습니다.
4. `ObCallbackReg` 함수로 콜백 루틴을 등록합니다.
5. `PsSetLoadImageNotifyRoutine` 함수로 콜백 루틴을 등록합니다.

이제 콜백 루틴을 정의할 차례입니다.

{% include warning.html content="MmGetSystemRoutineAddress의 반환 값이 NULL일 수 있습니다. 해당 함수가 존재하지 않을 경우이므로, 조건문으로 좀 더 안전하게 작성할 수 있습니다. " %}



### [-] PreCallback Define

먼저 `ObRegisterCallbacks` 의 `PreCallback` 함수를 정의해보겠습니다. 위의 `common.h` 내 하단에 관련 전역변수를 알아보겠습니다.

- `BOOLEAN bOnOff` : 지속적인 핸들 조작으로 오작동 할 수 있으므로, 특정 로직에서 스위치 작용
- `const char szTarget[]` :  보호 할 타겟 프로세스 명
- `PsGetProcessDebugPort_t PsGetProcessDebugPort` : `PsGetProcessDebugPort` 함수 호출용

```c++
/*
# Name  : PreCallback
# Param : PVOID, POB_PRE_OPERATION_INFORMATION
# Desc  : PsGetProcessDebugPort 를 이용하여 유저모드 디버깅 방지
*/
OB_PREOP_CALLBACK_STATUS PreCallback(
	PVOID RegistrationContext, 
	POB_PRE_OPERATION_INFORMATION pOperationInformation
)
{
	UNREFERENCED_PARAMETER(RegistrationContext);

	char szProcName[16] = { 0, };
	strcpy_s(szProcName, 16, ((DWORD64)pOperationInformation->Object + iOffset.ImageFileName_off));
	if (!_strnicmp(szProcName, szTarget, 16))
	{
		if (PsGetProcessDebugPort(pOperationInformation->Object))
		{
			if (!bOnOff)
			{
				bOnOff = TRUE;
				TerminateProcess(PsGetProcessId(pOperationInformation->Object));
				bOnOff = FALSE;
			}
		}
	}
}
```

위의 코드에서 디버깅 중인 경우 아래와 같이 동작하게 됩니다.

1. 현재 조작되는 프로세스 핸들에서 파일이름을 복사합니다.(`strcpy_s`)
2. `szTarget("notepad.exe")`와 비교하여 분기가 발생합니다.
3. 같을 경우 `PsGetProcessDebugPort` 함수를 이용하여 디버그 포트를 가져오고 해당 값이 존재하면 탐지 로직이 동작합니다.
4. 핸들 조작이 일어날 때 마다 동작하므로 오작동을 방지하기 위해 `bOnOff` 변수를 참으로 변경하고 `TerminateProcess` 함수로 해당 프로세스를 종료합니다.
5. 종료되면 다시 `bOnOff` 변수를 거짓으로 변경하여 지속적으로 감시합니다.

이대로 컴파일하여 드라이버를 로드하고 테스트를 진행할 수 있습니다.
드라이버가 로드 된 상태에서 `notepad.exe` 를 디버깅하려고 하면 `TerminateProcess` 함수에서 정의한대로, `ACCESS_DENIED` 에러로 인한 종료를 확인할 수 있습니다.

{% include note.html content="모든 정의가 끝난 후 영상을 통해 동작을 확인할 수 있습니다." %}



### [-] NotifyRoutine Define

```c++
/*
# Name  : LoadImageNotifyRoutine
# Param : PUNICODE_STRING, HANDLE, PIMAGE_INFO
# Desc  : KdDebuggerEnabled 와 KdDebuggerNotPresent 커널 전역 변수를 활용
*/
VOID LoadImageNotifyRoutine(
	IN PUNICODE_STRING FullImageName, 
	IN HANDLE ProcessId, 
	IN PIMAGE_INFO ImageInfo)
{
	PEPROCESS *Process = NULL;
	char szProcName[16] = { 0, };


	if (!ImageInfo->SystemModeImage)
	{
		if (PsLookupProcessByProcessId(ProcessId, &Process) == STATUS_SUCCESS)
		{
			strcpy_s(szProcName, 16, (PVOID*)((PCHAR)Process + iOffset.ImageFileName_off));
			if (!_strnicmp(szProcName, szTarget, 16))
			{
				if (*KdDebuggerNotPresent==FALSE)
				{
					DbgPrintEx(DPFLTR_ACPI_ID, 1, "[WARN] Debugger Present\n");
					//TerminateProcess(ProcessId);
				}
				else
				{
					if (*KdDebuggerEnabled)
					{
						DbgPrintEx(DPFLTR_ACPI_ID, 1, "[WARN] Kernel Debugger Enabled \n");
						//TerminateProcess(ProcessId);
					}
				}
			}
		}
	}
}
```

동작 과정은 아래와 같습니다.

1. 유저모드 이미지인지 확인합니다.
2. `PsLookupProcessByProcessId` 함수를 이용하여 프로세스 객체를 가져옵니다.
3. `ImageFileName`을 복사하고 타겟 프로세스 이름과 비교합니다.
4. `KdDebuggerNotPresent` 변수가 거짓인지 비교하여, 거짓인 경우 프로세스를 종료시킵니다.
5. 참인 경우, `KdDebuggerEnabled` 변수가 참인 경우 프로세스를 종료시킵니다.

이제 드라이버를 로드하고 어떻게 동작하는지 확인해보겠습니다.

{% include note.html content="TerminateProcess()를 주석 처리한 이유는 프로세스 디버깅 방지와 커널 디버깅 방지가 잘 적용되는지 확인하기 위함입니다. 주석을 해제하는 경우, 프로세스 디버깅 방지가 되는지 확인하기 어렵습니다." %}



## [0x03] Proof of Concept

위의 드라이버가 동작하는 모습을 영상으로 준비했습니다. 

<iframe src="https://youtube.com/embed/r11Qz5ace9s" allowfullscreen="" width="720" height="365"></iframe>

커널 디버깅을 탐지하여 디버그 로그에 출력되고, 프로세스 디버깅 시도 시 프로세스가 종료되는 것을 볼 수 있습니다.

## [0x04] Conclusion

지금까지는 시작과 같았습니다. 이제 본격적으로 이러한 안티 커널 디버깅 기법을 우회하는 방법에 대해 알아보겠습니다. `NotifyRoutine`에서 어떻게 커널 디버깅을 방지했는지 기억하고 찾아보고 다음 챕터를 읽으면 큰 도움이 될 것입니다.

