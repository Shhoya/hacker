---
layout: article
title: "[Dev]Get EPROCESS Offset"
key: 20200203
tags:
  - Windows
  - Dev
  - Kernel
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [0x00] Get EPROCESS Offset

<!--more-->

## [+] PID & ProcessListEntry Offset

### [-] Source

`Process`에서부터 4바이트씩 확인하여 PID와 동일한 위치를 찾는다. `ActiveProcessLinks`는 `UniqueProcessId` 오프셋의 8바이트 뒤에 위치하므로 해당 위치의 값이 유효한지 확인한다.

유효한 주소라면, `Flink`를 `NextEntry` 변수에 담는다.  그리고 현재 `ListEntry` 변수의 값과 `NextEntry`의 `Blink` 값을 비교하여 같다면 `UniqueProcessId`와 `ActiveProcessLinks`의 오프셋을 저장한다.  

```c
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
					DbgPrintEx(DPFLTR_ACPI_ID, 0,"[+] PID Offset : %X\n", i);
					DbgPrintEx(DPFLTR_ACPI_ID, 0,"[+] ActiveProcessLinks Offset : %X\n", i + 8);
					success = TRUE;
					break;
				}
			}
		}
	}
	if (!success)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0,"[!] Not Found Offset... Sorry :(\n");
		return success;
	}
}
```



## [+] ImageFileName Offset

### [-] Source

`System` 문자열을 이용하여 동일한 위치의 오프셋을 가져온다. 간단..

```
success = FALSE;
for (int i = iOffset.ActiveProcessLinks_off; i < PAGE_SIZE; i++)
{
	if (!strncmp((PCHAR)Process + i, aSystem, 6))
	{
		iOffset.ImageFileName_off = i;
		DbgPrintEx(DPFLTR_ACPI_ID, 0,"[+] ImageFileName Offset : %X\n", i);
		success = TRUE;
		break;
	}
}

if (!success)
{
	DbgPrintEx(DPFLTR_ACPI_ID, 0,"[!] Not Found Offset... Sorry :(\n");
	return success;
}
```

## [+] PEB Offset

### [-] Source

핵심은 `ObOpenObjectByPointer`와 `NtQueryInformationProcess` 함수이다.
`System` 프로세스에는 `PEB`가 NULL이므로, `ActiveProcessLinks`를 이용한다. `ObOpenObjectByPointer`로 프로세스를 넘겨 핸들을 구하고, 이를 이용하여 `NtQueryInformationProcess`를 호출한다.

`PROCESS_BASIC_INFORMATION` 구조체의 정보를 가져오고, `PebBaseAddress`가 존재하는지 확인한다. 존재하는 경우 마찬가지로 4바이트씩 증가시키며 해당 주소가 존재하는 오프셋을 찾고 이를 저장한다.

```c
BOOLEAN GetPebOffset()
{
	int LinkOffset = iOffset.ActiveProcessLinks_off;
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
			for (int i = iOffset.ActiveProcessLinks_off; i < PAGE_SIZE - 0x10; i += 4)
			{
				if (*(PHANDLE)((PCHAR)Process + i) == ProcessInformation.PebBaseAddress)
				{
					iOffset.PEB_off = i;
					DbgPrintEx(DPFLTR_ACPI_ID, 0,"[+] PEF Offset : %IX\n", i);
					success = TRUE;
					return success;
				}
			}
		}
	}
	return success;
}
```

# [0x01] Source Code

## [+] Common.h

```c
// Common.h
#pragma once
#include <ntifs.h>
#include <ntdef.h>

#define PROCESS_TERMINATE    0x0001
#define PROCESS_VM_OPERATION 0x0008
#define PROCESS_VM_READ		 0x0010
#define PROCESS_VM_WRITE     0x0020

//============================================//
//=========== Undocument Structure ===========//
//============================================//
typedef struct _IMPORT_OFFSET
{
	int			UniqueProcessid_off;		// 0x0000
	int			ActiveProcessLinks_off;		// 0x0004
	int			ImageFileName_off;          // 0x0008
	int			PEB_off;		           // 0x000C
}IMPORT_OFFSET;


//============================================//
//=========== Global Variable ================//
//============================================//
HANDLE hProcessId;
IMPORT_OFFSET iOffset;
HANDLE hWonder;
const char aSystem[] = "System";
const wchar_t szNtQueryInformationProcess[] = L"NtQueryInformationProcess";


//============================================//
//=========== Define Functions ===============//
//============================================//

VOID UnloadDriver(IN PDRIVER_OBJECT);
NTSTATUS DriverEntry(IN PDRIVER_OBJECT DriverObject, IN PUNICODE_STRING RegistryPath);


//============================================//
//=========== Undocumented API ===============//
//============================================//

typedef NTSTATUS(*NtQueryInformationProcess_t)(
	_In_	HANDLE					ProcessHandle,
	_Out_	PROCESSINFOCLASS		ProcessInformationClass,
	_In_	PVOID					ProcessInformation,
	_Out_	ULONG					ProcessInformationLength,
	_Out_	PULONG					ReturnLength
	);
```

## [+] Sub.h

```c
#pragma once
#include "Common.h"

/*
# ========================================================================================= #
# Get EPROCESS & ETHREAD Offset
# UniqueProcessId, ActiveProcessLinks, ImageFilename, PEB from EPROCESS
# ========================================================================================= #
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
			for (int i = iOffset.ActiveProcessLinks_off; i < PAGE_SIZE - 0x10; i += 4)
			{
				if (*(PHANDLE)((PCHAR)Process + i) == ProcessInformation.PebBaseAddress)
				{
					iOffset.PEB_off = i;
					DbgPrintEx(DPFLTR_ACPI_ID, 0,"[+] PEF Offset : %IX\n", i);
					success = TRUE;
					return success;
				}
			}
		}
	}
	return success;
}


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
					DbgPrintEx(DPFLTR_ACPI_ID, 0,"[+] PID Offset : %X\n", i);
					DbgPrintEx(DPFLTR_ACPI_ID, 0,"[+] ActiveProcessLinks Offset : %X\n", i + 8);
					success = TRUE;
					break;
				}
			}
		}
	}
	if (!success)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0,"[!] Not Found Offset... Sorry :(\n");
		return success;
	}

	// ImageFileName Offset 
	success = FALSE;
	for (int i = iOffset.ActiveProcessLinks_off; i < PAGE_SIZE; i++)
	{
		if (!strncmp((PCHAR)Process + i, aSystem, 6))
		{
			iOffset.ImageFileName_off = i;
			DbgPrintEx(DPFLTR_ACPI_ID, 0,"[+] ImageFileName Offset : %X\n", i);
			success = TRUE;
			break;
		}
	}
	if (!success)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0,"[!] Not Found Offset... Sorry :(\n");
		return success;
	}

	if (!GetPebOffset())
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0,"[!] Not Found Offset... Sorry :(\n");
		return success;
	}
	return success;

}
```

## [+] DriverEntry.c

```c
#include "Sub.h"
#include <suppress.h>

/*
# ========================================================================================= #
# Driver Entry
# ========================================================================================= #
*/
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
	NTSTATUS returnStatus = STATUS_SUCCESS;
	UNREFERENCED_PARAMETER(RegistryPath);
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[#] Load driver\n");
	GetOffset(PsGetCurrentProcess());
	DriverObject->DriverUnload = UnloadDriver;
	return returnStatus;
}

/*
# ========================================================================================= #
# Unload Driver
# ========================================================================================= #
*/
VOID UnloadDriver(PDRIVER_OBJECT DriverObject)
{
	UNREFERENCED_PARAMETER(DriverObject);
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[#] Unload driver\n");
}

```

