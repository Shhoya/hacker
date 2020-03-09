---
title: Code Integrity
keywords: documentation, technique, debugging
date: 2020-03-09
tags: [Windows, Reversing, Dev]
summary: "코드 무결성, 코드 서명"
sidebar: antikernel_sidebar
permalink: antikernel_codeintegrity.html
folder: antikernel
---

## [0x00] Overview

이제 이 프로젝트의 최종장입니다. 보호 드라이버를 우회하는 우회 드라이버를 만들었지만 좀 더 완벽하게 디버거를 제어하기 위해 `Control Debugger` 라는 드라이버를 작성했습니다. 예제코드는 아래에서 확인할 수 있습니다.

- <a href="https://shhoya.github.io/Examples">예제 소스코드</a>



## [0x01] Control Debugger Design

먼저 두 개의 프로젝트가 필요합니다.

1. 유저모드 콘솔 프로그램
   - `DeviceIoControl` 을 통해 드라이버와 통신하며 각 기능을 제어
2. 커널 드라이버
   - 유저모드에서 전달받은 데이터로 각 기능 동작
   - `KdDebuggerEnabled` 제어
   - `KdDebuggerNotPresent` 제어
   - `ObRegisterCallbacks` 콜백 루틴 해제 및 원복
   - `DebugPort` 변조



## [0x02] Driver Loader

먼저 드라이버를 로드하고, 통신하며 제어할 수 있는 유저모드 애플리케이션 소스 입니다.



### [-] main.cpp

드라이버를 로드하고 각 번호대로 동작하게 만들어졌습니다.

```cpp
#include <stdio.h>
#include <Windows.h>
#include <tchar.h>

#pragma warning(disable:4996)

#define DRIVERNAME _T("\\ControlDebugger.sys")
#define SERVICENAME _T("ControlDebugger")
#define ORDERGROUP _T("Shh0ya")

BOOL DriverLoader()
{
	TCHAR DriverPath[MAX_PATH] = { 0, };
	TCHAR currPath[MAX_PATH] = { 0, };

	lstrcpyW(DriverPath, _T("\\??\\"));
	GetCurrentDirectory(MAX_PATH, currPath);
	lstrcatW(DriverPath, currPath);
	lstrcatW(DriverPath, DRIVERNAME);

	SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE hService = CreateService(
		hScm, SERVICENAME, SERVICENAME, SC_MANAGER_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
		SERVICE_DEMAND_START, SERVICE_ERROR_IGNORE, DriverPath, ORDERGROUP, NULL, NULL, NULL, NULL);

	if (!hService)
	{
		if (GetLastError() != 0x431)
		{
			printf("[!] Error Code : 0x%X(%d)\n", GetLastError(), GetLastError());
			CloseHandle(hScm);
			system("pause");
			return FALSE;
		}
		else
		{
			hService = OpenService(hScm, SERVICENAME, SC_MANAGER_ALL_ACCESS);
			if (!hService)
			{
				printf("[!] Open Service Error : 0x%X(%d)\n", GetLastError(), GetLastError());
				system("pause");
				CloseHandle(hScm);
				return FALSE;
			}
		}
	}

	if (!StartService(hService, 0, NULL))
	{
		printf("[!] Service Start Error : 0x%X(%d)\n", GetLastError(), GetLastError());
		system("pause");
		DeleteService(hService);
		CloseHandle(hService);
		CloseHandle(hScm);
		return FALSE;
	}
	CloseHandle(hService);
	CloseHandle(hScm);
	return TRUE;
}

void StopService()
{
	SERVICE_STATUS Status;
	SC_HANDLE hScm = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	SC_HANDLE hService = OpenService(hScm, SERVICENAME, SERVICE_STOP);
	ControlService(hService, SERVICE_CONTROL_STOP, &Status);

	CloseHandle(hScm);
	CloseHandle(hService);

	return;
}

void SendControl(int mode)
{
	HANDLE deviceHandle;
	TCHAR linkName[] = _T("\\\\.\\ControlDebugger");
	DWORD dwRet = NULL;
	deviceHandle = CreateFile(linkName, GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	
	if (deviceHandle == INVALID_HANDLE_VALUE)
	{
		printf("[!] Invalid handle error\n");
		return;
	}

	if (mode == 0x6)
	{
		char sendBuf[MAX_PATH] = { 0, };
		system("cls");
		printf("[+] Target Process Id(Decimal) : ");
		scanf("%s", &sendBuf);

		if (!DeviceIoControl(deviceHandle, mode, sendBuf, sizeof(sendBuf), 0, 0, &dwRet, 0))
		{
			CloseHandle(deviceHandle);
			return;
		}
	}
	else
	{
		if (!DeviceIoControl(deviceHandle, mode, 0, 0, 0, 0, &dwRet, 0))
		{
			CloseHandle(deviceHandle);
			return;
		}
	}

	CloseHandle(deviceHandle);
	return;
}

int main()
{
	printf("[#] Driver Loader\n");
	printf("[#] Load Driver...\n");
	if (DriverLoader())
	{
		printf("[#] Driver Load Success!!!\n");
		Sleep(500);
		system("cls");
		int sel = 0;
		while (1)
		{
			printf("[#] Select\n\n");
			printf("[1] Debugger Enable\n");
			printf("[2] Debugger Disable\n");
			printf("[3] Kdcom Hooking\n");
			printf("[4] Overwrite Callbacks\n");
			printf("[5] Restore Callbacks\n");
			printf("[6] Overwrite DebugPort\n");
			printf("[7] Unload Driver\n");

			printf(": ");
			scanf("%d", &sel);
			system("cls");

			if (sel == 0x7)
			{
				StopService();
				break;
			}

			if (sel)
			{
				SendControl(sel);
			}
		}
		return 0;
	}

	else
	{
		printf("[!] Driver Load Failed...\n");
		return 0;
	}
}
```



## [0x03] Control Debugger Features

이제 드라이버 코드입니다. 먼저 기능별로 코드를 확인하고 전체 코드를 작성하겠습니다.



### [-] KdDebuggerControl

이전에는 `KdDisableDebugger` 함수를 통해 디버거를 비활성화해서 보호 드라이버를 우회했습니다. 하지만 제약이 존재했습니다. 커널 디버거를 사용할 수 없었습니다. 그래서 중요 변수인 `KdDebuggerEnabled` 의 값만을 변조합니다. 그럼 브레이크 예외 발생 시 디버거로 예외를 넘겨 디버거에서 처리할 수 있습니다.

```c
/*
# Name  : KdDebuggerControl
# Param : int
# Desc  : KdDebuggerEnabled 변수 제어
# Case  : 0x1, 0x2
*/
NTSTATUS KdDebuggerControl(int mode)
{
	if (mode == DEBUGGER_ENABLE)
	{
		*KdDebuggerEnabled = TRUE;		
	}
	else if (mode == DEBUGGER_DISABLE)
	{
		*KdDebuggerEnabled = FALSE;
	}
	return STATUS_SUCCESS;
}
```

{% include note.html content="브레이크 예외를 넘겨주지 못하는 이유는 KdDisableDebugger 함수 내 KdpSuspendAllBreakpoints 함수로 인한 것으로 보입니다." %}



### [-] Hook_KdReceivePacket

`WKE` 와 같은 커널 메모리 편집 도구를 이용하여 `KdDebuggerNotPresent`의 값을 변조하면 다시 원상복귀 되는 것을 볼 수 있습니다. 이는 커널과 디버거의 통신으로 인해서 입니다.

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

위와 같이 디버깅을 통해 확인할 수 있습니다. 또한 중요하게 확인해야 할 부분이 있습니다.

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

커널에 올라와있는 실제 이미지 이름이 `kdbazis.dll` 으로 되어있습니다. `VirtualKD`를 사용하면 `kdcom.dll` 을 `kdcom_old.dll`으로 백업하고 `VirtualKD`용 `kdcom.dll`이 적용됩니다. 그리고 이는 `VirtualKD` 디렉토리 내 `kdbazis.dll` 이라는 모듈로 리다이렉트 됩니다. 해당 모듈을 분석하여 `KdReceivePacket` 함수에서 `KdDebuggerNotPresent` 변수에 값을 쓰는 부분을 변조하였습니다.

```c
/*
# Name  : Hook_KdReceivePacket
# Param : x
# Desc  : KdDebuggerNotPresent 변조용
# Case  : 0x3
*/
NTSTATUS Hook_KdReceivePacket()
{
	NTSTATUS Status = STATUS_SUCCESS;
	PVOID KdReceivePacket = NULL;
	Status = GetModuleInformation("\\SystemRoot\\System32\\kdcom.dll");
	if (Status != STATUS_SUCCESS)
	{
		return STATUS_INVALID_ADDRESS;
	}
	else
	{
		KdReceivePacket = (DWORD64)TargetModule.ImageBase + 0x1861;	// KdReceivePacket+4a1 ( Write KdDebuggerNotPresent )
		memcpy(KdReceivePacket, bPatchBytes, 5);
		return STATUS_SUCCESS;
	}
}
```



### [-] OverWriteCallbacks

이전 로직과 크게 다르지 않습니다. 다만 복구 로직이 추가되었습니다. `CallbackEntry` 내 `PreOperation` 을 더미 함수로 복사하기 전에 백업을 하고, 복구 명령 시 다시 이전의 콜백 루틴으로 교체합니다.

```c
/*
# Name  : OverWriteCallbacks
# Param : int
# Desc  : 콜백 루틴을 더미 함수로 변조
# Case  : 0x4, 0x5
*/
NTSTATUS OverWriteCallbacks(int mode)
{
	POBJECT_TYPE* obType = PsProcessType;
	PCALLBACK_ENTRY_ITEM CallbackEntry = NULL;

	if (mode == OVERWRITE_CALLBACKS)
	{
		CallbackEntry = (*obType)->CallbackList.Flink;

		if (MmIsAddressValid(CallbackEntry))
		{
			pBackupCallback = CallbackEntry->PreOperation;
			CallbackEntry->PreOperation = &Dummy;
			return STATUS_SUCCESS;
		}
	}
	else if (mode == RESTORE_CALLBACKS)
	{
		CallbackEntry = (*obType)->CallbackList.Flink;

		if (MmIsAddressValid(CallbackEntry))
		{
			if (pBackupCallback)
			{
				CallbackEntry->PreOperation = pBackupCallback;
				
				return STATUS_SUCCESS;
			}
			else
			{
				return STATUS_ACCESS_DENIED;
			}
		}
	}	
	return STATUS_ACCESS_DENIED;
}
```



### [-] OverWriteDebugPort

사실 그냥 욕심으로 만들어 본 기능입니다. 타겟 프로세스의 디버그 포트가 존재하는 경우 NULL 값으로 설정합니다.

```c
/*
# Name  : OverWriteDebugPort
# Param : PIRP
# Desc  : 프로세스 디버그 포트 제어
# Case  : 0x6
*/
NTSTATUS OverWriteDebugPort(PIRP pIrp)
{
	int targetPID = atoi(pIrp->AssociatedIrp.SystemBuffer);
	PEPROCESS Process = NULL;
	PVOID pDebugPort = NULL;
	
	if (PsLookupProcessByProcessId(targetPID, &Process) == STATUS_SUCCESS)
	{
		pDebugPort = (void*)((DWORD64)Process + iOffset.DebugPort_off);
		if (MmIsAddressValid(pDebugPort))
		{
			memset(pDebugPort, 0, 8);
		}
	}

	return STATUS_SUCCESS;
}
```



## [0x04] Control Debugger

전체 소스코드입니다.



### [-] common.h

```c
#pragma once
#include <ntifs.h>

/*///////////////////////////////////////////////////
# File : common.h
# Desc : 모든 함수와 구조체, 전역변수 등 선언 및 정의
*////////////////////////////////////////////////////


#define DeviceName L"\\Device\\CONTROL_DEBUGGER"
#define DEBUGGER_ENABLE 0x01
#define DEBUGGER_DISABLE 0x02
#define KDCOM_HOOKING 0x03
#define OVERWRITE_CALLBACKS 0x04
#define RESTORE_CALLBACKS 0x05
#define OVERWRITE_DEBUGPORT 0x06

//============================================//
//================ Structure =================//
//============================================//

typedef enum _SYSTEM_INFORMATION_CLASS
{
	SystemBasicInformation, // q: SYSTEM_BASIC_INFORMATION
	SystemProcessorInformation, // q: SYSTEM_PROCESSOR_INFORMATION
	SystemPerformanceInformation, // q: SYSTEM_PERFORMANCE_INFORMATION
	SystemTimeOfDayInformation, // q: SYSTEM_TIMEOFDAY_INFORMATION
	SystemPathInformation, // not implemented
	SystemProcessInformation, // q: SYSTEM_PROCESS_INFORMATION
	SystemCallCountInformation, // q: SYSTEM_CALL_COUNT_INFORMATION
	SystemDeviceInformation, // q: SYSTEM_DEVICE_INFORMATION
	SystemProcessorPerformanceInformation, // q: SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION
	SystemFlagsInformation, // q: SYSTEM_FLAGS_INFORMATION
	SystemCallTimeInformation, // not implemented // SYSTEM_CALL_TIME_INFORMATION // 10
	SystemModuleInformation, // q: RTL_PROCESS_MODULES
	
} SYSTEM_INFORMATION_CLASS;
typedef struct _SYSTEM_MODULE_ENTRY
{
	HANDLE Section;				//0x0000(0x0008)
	PVOID MappedBase;			//0x0008(0x0008)
	PVOID ImageBase;			//0x0010(0x0008)
	ULONG ImageSize;			//0x0018(0x0004)
	ULONG Flags;				//0x001C(0x0004)
	USHORT LoadOrderIndex;		//0x0020(0x0002)
	USHORT InitOrderIndex;		//0x0022(0x0002)
	USHORT LoadCount;			//0x0024(0x0002)
	USHORT OffsetToFileName;	//0x0026(0x0002)
	UCHAR FullPathName[256];	//0x0028(0x0100)
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;
typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG               Count;
	SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;
typedef struct _CALLBACK_ENTRY
{
	INT16							Version;
	unsigned char					unknown[6];
	POB_OPERATION_REGISTRATION		RegistrationContext;
	UNICODE_STRING					Altitude;
} CALLBACK_ENTRY, * PCALLBACK_ENTRY;
typedef struct _CALLBACK_ENTRY_ITEM
{
	LIST_ENTRY						EntryItemList;
	OB_OPERATION					Operations1;
	OB_OPERATION					Operations2;
	PCALLBACK_ENTRY					CallbackEntry;
	POBJECT_TYPE					ObjectType;
	POB_PRE_OPERATION_CALLBACK		PreOperation;
	POB_POST_OPERATION_CALLBACK		PostOperation;
} CALLBACK_ENTRY_ITEM, * PCALLBACK_ENTRY_ITEM;
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

typedef struct _IMPORT_OFFSET
{
	int			UniqueProcessid_off;
	int			ActiveProcessLinks_off;
	int			ImageFileName_off;
	int			PEB_off;
	int         DebugPort_off;
}IMPORT_OFFSET;



//============================================//
//============= Glboal Variable ==============//
//============================================//

PVOID RegistrationHandle = NULL;
PVOID pBackupCallback = NULL;
PDEVICE_OBJECT pDevice = NULL;

UNICODE_STRING SymbolickLink = { 0, };
UNICODE_STRING NtQuerySystemInformationString = { 0, };
IMPORT_OFFSET iOffset = { 0, };
SYSTEM_MODULE_ENTRY TargetModule = { 0, };

const char szSystem[] = "System";
const wchar_t szNtQueryInformationProcess[] = L"NtQueryInformationProcess";

unsigned char bPatchBytes[5] = { 0xC6,0x01,0x01,0x90,0x90 };	// KdDebuggerPresent




//============================================//
//=========== Undocumented API ===============//
//============================================//

typedef NTSTATUS(*NtQuerySystemInformation_t)(
	_In_	SYSTEM_INFORMATION_CLASS	SystemInformationClass,
	_Out_	PVOID						SystemInformation,
	_In_	ULONG						SystemInformationLength,
	_Out_	PULONG						ReturnLength OPTIONAL
	);

typedef NTSTATUS(*NtQueryInformationProcess_t)(
	IN    HANDLE              ProcessHandle,
	IN    PROCESSINFOCLASS    ProcessInformationClass,
	OUT   PVOID               ProcessInformation,
	IN    ULONG               ProcessInformationLength,
	OUT   PULONG              ReturnLength
	);


//============================================//
//======= DriverEntry & Unload Routine =======//
//============================================//

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath);
VOID UnloadDriver(IN PDRIVER_OBJECT pDriver);


//============================================//
//========== User-defined Function  ==========//
//============================================//

VOID Dummy();

NTSTATUS GetModuleInformation(const char* szModuleName);
BOOLEAN GetOffset(PEPROCESS Process);
BOOLEAN GetPebOffset();

NTSTATUS ControlDebugger(PDEVICE_OBJECT pDevice, PIRP pIrp);
NTSTATUS KdDebuggerControl(int mode);
NTSTATUS Hook_KdReceivePacket();
NTSTATUS OverWriteCallbacks();
NTSTATUS OverWriteDebugPort(PIRP pIrp);
```



### [-] customapi.h

```c
#pragma once
#include "common.h"

/*//////////////////////////////////////////////
# File : customapi.h
# Desc : 기타 사용자 함수 정의
*///////////////////////////////////////////////


/*
# Name  : Dummy
# Param : x
# Desc  : 콜백 루틴 덮어쓰기용 더미 함수
*/
VOID Dummy()
{

}

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

/*
# Name  : GetModuleInformation
# Param : const char*
# Desc  : GetModuleHandle 커널 모드 버전
*/
NTSTATUS GetModuleInformation(const char* szModuleName)
{
	BOOLEAN tmpSwitch = FALSE;
	ULONG infoLen = 0;
	UNICODE_STRING ZwQueryString = { 0, };
	PSYSTEM_MODULE_INFORMATION pMod = { 0, };
	RtlInitUnicodeString(&ZwQueryString, L"ZwQuerySystemInformation");
	NtQuerySystemInformation_t ZwQuerySystemInformation = MmGetSystemRoutineAddress(&ZwQueryString);

	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, &infoLen, 0, &infoLen);
	pMod = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, infoLen, 'H0YA');
	RtlZeroMemory(pMod, infoLen);
	status = ZwQuerySystemInformation(SystemModuleInformation, pMod, infoLen, &infoLen);
	PSYSTEM_MODULE_ENTRY pModEntry = pMod->Module;
	for (int i = 0; i < pMod->Count; i++)
	{
		if (!_stricmp(pModEntry[i].FullPathName, szModuleName))
		{
			DbgPrint("[+] Find Module %s\n", pModEntry[i].FullPathName);
			TargetModule = pModEntry[i];
			tmpSwitch = TRUE;
			break;
		}
	}
	ExFreePoolWithTag(pMod, 'H0YA');
	if (!tmpSwitch)
	{
		return STATUS_NOT_FOUND;
	}
	return status;
}
```



### [-] control.h

```c
#pragma once
#include "customapi.h"
#include <stdlib.h>

/*//////////////////////////////////////////////
# File : control.h
# Desc : 디버거 제어와 관련된 함수 정의
*///////////////////////////////////////////////


/*
# Name  : KdDebuggerControl
# Param : int
# Desc  : KdDebuggerEnabled 변수 제어
# Case  : 0x1, 0x2
*/
NTSTATUS KdDebuggerControl(int mode)
{
	if (mode == DEBUGGER_ENABLE)
	{
		*KdDebuggerEnabled = TRUE;		
	}
	else if (mode == DEBUGGER_DISABLE)
	{
		*KdDebuggerEnabled = FALSE;
	}
	return STATUS_SUCCESS;
}

/*
# Name  : Hook_KdReceivePacket
# Param : x
# Desc  : KdDebuggerNotPresent 변조용
# Case  : 0x3
*/
NTSTATUS Hook_KdReceivePacket()
{
	NTSTATUS Status = STATUS_SUCCESS;
	PVOID KdReceivePacket = NULL;
	Status = GetModuleInformation("\\SystemRoot\\System32\\kdcom.dll");
	if (Status != STATUS_SUCCESS)
	{
		return STATUS_INVALID_ADDRESS;
	}
	else
	{
		KdReceivePacket = (DWORD64)TargetModule.ImageBase + 0x1861;	// KdReceivePacket+4a1 ( Write KdDebuggerNotPresent )
		memcpy(KdReceivePacket, bPatchBytes, 5);
		return STATUS_SUCCESS;
	}
}

/*
# Name  : OverWriteCallbacks
# Param : int
# Desc  : 콜백 루틴을 더미 함수로 변조
# Case  : 0x4, 0x5
*/
NTSTATUS OverWriteCallbacks(int mode)
{
	POBJECT_TYPE* obType = PsProcessType;
	PCALLBACK_ENTRY_ITEM CallbackEntry = NULL;

	if (mode == OVERWRITE_CALLBACKS)
	{
		CallbackEntry = (*obType)->CallbackList.Flink;

		if (MmIsAddressValid(CallbackEntry))
		{
			pBackupCallback = CallbackEntry->PreOperation;
			CallbackEntry->PreOperation = &Dummy;
			return STATUS_SUCCESS;
		}
	}
	else if (mode == RESTORE_CALLBACKS)
	{
		CallbackEntry = (*obType)->CallbackList.Flink;

		if (MmIsAddressValid(CallbackEntry))
		{
			if (pBackupCallback)
			{
				CallbackEntry->PreOperation = pBackupCallback;
				
				return STATUS_SUCCESS;
			}
			else
			{
				return STATUS_ACCESS_DENIED;
			}
		}
	}
	
	return STATUS_ACCESS_DENIED;
}

/*
# Name  : OverWriteDebugPort
# Param : PIRP
# Desc  : 프로세스 디버그 포트 제어
# Case  : 0x6
*/
NTSTATUS OverWriteDebugPort(PIRP pIrp)
{
	int targetPID = atoi(pIrp->AssociatedIrp.SystemBuffer);
	PEPROCESS Process = NULL;
	PVOID pDebugPort = NULL;
	
	if (PsLookupProcessByProcessId(targetPID, &Process) == STATUS_SUCCESS)
	{
		pDebugPort = (void*)((DWORD64)Process + iOffset.DebugPort_off);
		if (MmIsAddressValid(pDebugPort))
		{
			memset(pDebugPort, 0, 8);
		}
	}

	return STATUS_SUCCESS;
}


NTSTATUS ControlDebugger(PDEVICE_OBJECT pDeviceObject, PIRP pIrp)
{
	UNREFERENCED_PARAMETER(pDeviceObject);
	PIO_STACK_LOCATION pStack = NULL;
	ULONG ControlCode = 0;
	NTSTATUS Status = STATUS_SUCCESS;
	
	pStack = IoGetCurrentIrpStackLocation(pIrp);
	ControlCode = pStack->Parameters.DeviceIoControl.IoControlCode;
	if (ControlCode)
	{
		switch (ControlCode)
		{
		case DEBUGGER_ENABLE:
			Status = KdDebuggerControl(DEBUGGER_ENABLE);
			if (Status == STATUS_SUCCESS)
			{
				DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] Enable Debugger\n");
			}
			else
			{
				DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_ERROR_LEVEL, "[ERROR] Can't Control Debugger\n");
			}
			break;

		case DEBUGGER_DISABLE:
			Status = KdDebuggerControl(DEBUGGER_DISABLE);
			if (Status == STATUS_SUCCESS)
			{
				DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] Disable Debugger\n");
			}
			else
			{
				DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_ERROR_LEVEL, "[ERROR] Can't Control Debugger\n");
			}
			break;

		case KDCOM_HOOKING:
			Status = Hook_KdReceivePacket();
			if (Status == STATUS_SUCCESS)
			{
				DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] Patch Complete\n");
			}
			else
			{
				DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_ERROR_LEVEL, "[ERROR] Can't Patch\n");
			}
			break;

		case OVERWRITE_CALLBACKS:
			Status = OverWriteCallbacks(OVERWRITE_CALLBACKS);
			if (Status == STATUS_SUCCESS)
			{
				DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] Overwrite Callbacks\n");
			}
			else
			{
				DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_ERROR_LEVEL, "[ERROR] Can't Overwrite\n");
			}
			break;

		case RESTORE_CALLBACKS:
			Status = OverWriteCallbacks(RESTORE_CALLBACKS);
			if (Status == STATUS_SUCCESS)
			{
				
				DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] Restore Callbacks\n");
			}
			else
			{
				DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_ERROR_LEVEL, "[ERROR] Can't Restore\n");
			}
			break;

		case OVERWRITE_DEBUGPORT:
			Status = OverWriteDebugPort(pIrp);
			if (Status == STATUS_SUCCESS)
			{
				DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] DebugPort Overwrite\n");
			}
			else
			{
				DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_ERROR_LEVEL, "[ERROR] Can't Overwrite Debugport\n");
			}
			break;
		}
	}
	pIrp->IoStatus.Status = STATUS_SUCCESS;
	IoCompleteRequest(pIrp, IO_NO_INCREMENT);

	return STATUS_SUCCESS;
}
```



### [-] main.c

```c
#include "control.h"

/*//////////////////////////////////////////////
# File : main.c
# Desc : 드라이버 진입점, 해제 루틴 정의
*///////////////////////////////////////////////


NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);

	UNICODE_STRING deviceName = { 0, };

	RtlInitUnicodeString(&deviceName, DeviceName);
	RtlInitUnicodeString(&SymbolickLink, L"\\??\\ControlDebugger");

	if (GetOffset(PsGetCurrentProcess()))
	{
		if (IoCreateDevice(
			pDriver, 0, &deviceName, FILE_DEVICE_UNKNOWN,
			FILE_DEVICE_SECURE_OPEN, FALSE, &pDevice) == STATUS_SUCCESS)
		{
			IoCreateSymbolicLink(&SymbolickLink, &deviceName);
		}
	}
	pDriver->DriverUnload = UnloadDriver;
	pDriver->MajorFunction[IRP_MJ_CREATE] = ControlDebugger;
	pDriver->MajorFunction[IRP_MJ_DEVICE_CONTROL] = ControlDebugger;
	
	return STATUS_SUCCESS;
}

VOID UnloadDriver(PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);
	if (MmIsAddressValid(pDevice))
	{
		IoDeleteDevice(pDevice);
		IoDeleteSymbolicLink(&SymbolickLink);
	}

}
```





## [0x05] Proof Of Concept

영상은 `Control Debugger`를 이용하여 `ObRegisterCallbacks` 의 콜백 루틴을 더미 함수로 교체 및 복구 합니다. 그리고 순서대로 `KdDebuggerNotPresent` 를 우회하고 `KdDebuggerEnabled` 를 우회합니다.

<iframe src="https://youtube.com/embed/YcTgkXGNNBk" allowfullscreen="" width="720" height="365"></iframe>



## [0x06] Conclusion

이로써 모든 프로젝트 과정을 마쳤습니다. 안티 디버깅, 프로세스 보호는 기술의 발전만큼 매우 다양합니다. 새로운 기법이 나타나거나, 아주 오래전에 사용한 기법을 사용하기도 합니다. 더 많은 전역변수나 `RUNTIME_FUNCTION` 내 존재하는 함수들을 이용할 수도 있습니다. 그렇기 때문에 원시적인 방법이 최선이라고 생각합니다.

긴 글을 읽어주셔서 감사합니다. 궁금한 부분이나 필요한 부분이 있다면 상단에 피드백 메뉴를 통해 전달주시면 답변해드리겠습니다.

감사합니다.