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
const char szSystem[] = "System";
const wchar_t szNtQueryInformationProcess[] = L"NtQueryInformationProcess";
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
		DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_ERROR_LEVEL, "[ERR] Not found offset\n");
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
		DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_ERROR_LEVEL, "[ERR] Not found offset\n");
		return success;
	}

	if (!GetPebOffset())
	{
		DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_ERROR_LEVEL, "[ERR] Not found offset\n");
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

		if (ObOpenObjectByPointer(Process, NULL, NULL, NULL, *PsProcessType, KernelMode, &Key) == STATUS_SUCCESS)
		{
			PULONG Ret = NULL;
			NtQueryInformationProcess(Key, ProcessBasicInformation, &ProcessInformation, sizeof(ProcessInformation), Ret);
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

	if (ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &obAttr, &cid) == STATUS_SUCCESS)	// Get process handle
	{
		if (ZwTerminateProcess(hProcess, STATUS_ACCESS_DENIED) == STATUS_SUCCESS)	// Terminate process
		{
			DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_WARNING_LEVEL,
				"[INFO] Success terminate process\n");
		}
		else
		{
			DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_WARNING_LEVEL,
				"[ERR] Failed terminate process\n");
		}
	}
	else
	{
		DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_WARNING_LEVEL,
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

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] ObRegisterCallbacks Test\n");

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
	DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] Driver load success\n");



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
	
	DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] Driver unload success\n");
}
```



