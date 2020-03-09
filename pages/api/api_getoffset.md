---
title: GetOffset
keywords: documentation, technique, offset, eprocess
date: 2020-03-09
tags: [Windows, Reversing, Dev]
summary: "Get EPROCESS Offset"
sidebar: api_sidebar
permalink: api_getoffset.html
folder: api

---

## [0x00] Syntax

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

	// DebugPort Offset(temp)
	PVOID PsGetProcessDebugPort = NULL;
	UNICODE_STRING PsGetProcessDebugPortString = { 0, };
	int offset = 0;
	RtlInitUnicodeString(&PsGetProcessDebugPortString, L"PsGetProcessDebugPort");
	PsGetProcessDebugPort = MmGetSystemRoutineAddress(&PsGetProcessDebugPortString);
	memcpy(&offset, (void*)((DWORD64)PsGetProcessDebugPort + 0x3), 2);
	iOffset.DebugPort_off = offset;

	return success;
}
```



```c
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

## [0x01] Parameters

### [-] GetOffset

`Process`

`PsGetCurrentProcess()` 를 전달(`system`)



### [-] GetPebOffset

`NONE`



## [0x02] Return Value

오프셋을 정상적으로 할당된 경우 `TRUE`, 그렇지 않은 경우 `FALSE` 반환



## [0x03] Remark

`GetPebOffset` 함수는 `GetOffset` 함수 내부에서 호출됩니다. 또한 현재 임시로 `EPROCESS` 내 `DebugPort`를 찾는 로직이 추가되어 있습니다.  필요한 변수 및 구조체는 아래와 같습니다.

```c
typedef struct _IMPORT_OFFSET
{
	int			UniqueProcessid_off;
	int			ActiveProcessLinks_off;
	int			ImageFileName_off;
	int			PEB_off;
}IMPORT_OFFSET;

typedef NTSTATUS(*NtQueryInformationProcess_t)(
	IN    HANDLE              ProcessHandle,
	IN    PROCESSINFOCLASS    ProcessInformationClass,
	OUT   PVOID               ProcessInformation,
	IN    ULONG               ProcessInformationLength,
	OUT   PULONG              ReturnLength
	);

IMPORT_OFFSET iOffset;
const char szSystem[] = "System";
const wchar_t szNtQueryInformationProcess[] = L"NtQueryInformationProcess";
```



