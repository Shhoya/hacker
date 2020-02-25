---
layout: article
title: "[Dev]Get Process Information via PEB(x64)"
key: 20200225
tags:
  - Windows
  - Reversing
  - Dev
toc: true
mathjax: true
mathjax_autoNumber: true
published : false
---

# [+] Get Process Information via PEB

<!--more-->

## [0x00]  Introduction

바보 같은 짓을 했다가 버리기 아까워 포스팅 한다.
x64 masm 이 귀찮아서 그냥 있는 직접 만들어서 범용 쉘 코드를 제작해보자 했는데, 홀린듯이 이런 짓을 해버렸다.

예제 코드는 타겟 프로세스의 PEB를 이용하여 모듈 정보를 가져오고, PE 헤더를 이용하여 함수 주소를 가져와 정의된 대로 호출하도록 구현되어 있다.

음.. 그냥 PEB구조와 코딩 연습한 느낌이다. 예제 코드를 분석하며 설명을 한다.

## [0x01] Source Code

디버깅하여 `testProcAddress`가 호출되는 과정을 직접 확인해야 잘 동작했는지 알 수 있다.

### [-] define.h

헤더 파일이다. 문서화 되어있지 않은 API에 대한 정의와 필요한 부분만 뽑아내어 구조체로 만든 내용들이 있다.

```c++
#pragma once
#include <stdio.h>
#include <Windows.h>

/* enumeration */
typedef enum _PROCESSINFOCLASS {
	ProcessBasicInformation = 0,
	ProcessQuotaLimits = 1,
	ProcessIoCounters = 2,
	ProcessVmCounters = 3,
	ProcessTimes = 4,
	ProcessBasePriority = 5,
	ProcessRaisePriority = 6,
	ProcessDebugPort = 7,
	ProcessExceptionPort = 8,
	ProcessAccessToken = 9,
	ProcessLdtInformation = 10,
	ProcessLdtSize = 11,
	ProcessDefaultHardErrorMode = 12,
	ProcessIoPortHandlers = 13,   // Note: this is kernel mode only
	ProcessPooledUsageAndLimits = 14,
	ProcessWorkingSetWatch = 15,
	ProcessUserModeIOPL = 16,
	ProcessEnableAlignmentFaultFixup = 17,
	ProcessPriorityClass = 18,
	ProcessWx86Information = 19,
	ProcessHandleCount = 20,
	ProcessAffinityMask = 21,
	ProcessPriorityBoost = 22,
	ProcessDeviceMap = 23,
	ProcessSessionInformation = 24,
	ProcessForegroundInformation = 25,
	ProcessWow64Information = 26,
	ProcessImageFileName = 27,
	ProcessLUIDDeviceMapsEnabled = 28,
	ProcessBreakOnTermination = 29,
	ProcessDebugObjectHandle = 30,
	ProcessDebugFlags = 31,
	ProcessHandleTracing = 32,
	ProcessIoPriority = 33,
	ProcessExecuteFlags = 34,
	ProcessTlsInformation = 35,
	ProcessCookie = 36,
	ProcessImageInformation = 37,
	ProcessCycleTime = 38,
	ProcessPagePriority = 39,
	ProcessInstrumentationCallback = 40,
	ProcessThreadStackAllocation = 41,
	ProcessWorkingSetWatchEx = 42,
	ProcessImageFileNameWin32 = 43,
	ProcessImageFileMapping = 44,
	ProcessAffinityUpdateMode = 45,
	ProcessMemoryAllocationMode = 46,
	ProcessGroupInformation = 47,
	ProcessTokenVirtualizationEnabled = 48,
	ProcessOwnerInformation = 49,
	ProcessWindowInformation = 50,
	ProcessHandleInformation = 51,
	ProcessMitigationPolicy = 52,
	ProcessDynamicFunctionTableInformation = 53,
	ProcessHandleCheckingMode = 54,
	ProcessKeepAliveCount = 55,
	ProcessRevokeFileHandles = 56,
	ProcessWorkingSetControl = 57,
	ProcessHandleTable = 58,
	ProcessCheckStackExtentsMode = 59,
	ProcessCommandLineInformation = 60,
	ProcessProtectionInformation = 61,
	ProcessMemoryExhaustion = 62,
	ProcessFaultInformation = 63,
	ProcessTelemetryIdInformation = 64,
	ProcessCommitReleaseInformation = 65,
	ProcessReserved1Information = 66,
	ProcessReserved2Information = 67,
	ProcessSubsystemProcess = 68,
	ProcessInPrivate = 70,
	ProcessRaiseUMExceptionOnInvalidHandleClose = 71,
	ProcessSubsystemInformation = 75,
	ProcessWin32kSyscallFilterInformation = 79,
	ProcessEnergyTrackingState = 82,
	MaxProcessInfoClass                             // MaxProcessInfoClass should always be the last enum
}PROCESSINFOCLASS;

/* struct */
typedef LONG KPRIORITY;

typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
#ifdef MIDL_PASS
	[size_is(MaximumLength / 2), length_is((Length) / 2)] USHORT* Buffer;
#else // MIDL_PASS
	_Field_size_bytes_part_opt_(MaximumLength, Length) PWCH   Buffer;
#endif // MIDL_PASS
} UNICODE_STRING;

// custom struct
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY64         InLoadOrderLinks;
	LIST_ENTRY64         InMemoryOrderLinks;
	LIST_ENTRY64         InInitializationOrderLinks;
	PVOID               DllBase;
	PVOID               EntryPoint;
	DWORD               SizeOfImage;
	UNICODE_STRING         FullDllName;
	UNICODE_STRING         BaseDllName;
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

// custom struct
typedef struct _PEB_LDR_DATA {
	DWORD         Lenght;
	DWORD         Initialized;
	PVOID         SsHandle;
	LIST_ENTRY64   InLoadOrderModuleList;
	LIST_ENTRY64   InMemoryOrderModuleList;
	LIST_ENTRY64   InInitializationOrderModuleList;
}PEB_LDR_DATA, * PPEB_LDR_DATA;

// custom struct
typedef struct _PEB {
	unsigned char    dummy[0x10];
	PVOID          ImageBase;
	PPEB_LDR_DATA    Ldr;
} PEB, * PPEB;

typedef struct _PROCESS_BASIC_INFORMATION {
	NTSTATUS ExitStatus;
	PPEB PebBaseAddress;
	ULONG_PTR AffinityMask;
	KPRIORITY BasePriority;
	ULONG_PTR UniqueProcessId;
	ULONG_PTR InheritedFromUniqueProcessId;
} PROCESS_BASIC_INFORMATION, * PPROCESS_BASIC_INFORMATION;

typedef NTSTATUS(*NtQueryInformationProcess_t)(
	_In_    HANDLE                     ProcessHandle,
	_In_   PROCESSINFOCLASS            ProcessInformationClass,
	_Out_   PVOID                     ProcessInformation,
	_In_   ULONG                     ProcessInformationLength,
	_Out_   PULONG                     ReturnLength OPTIONAL
	);

```

#### PEB Struct

내가 필요한 `Ldr` 까지만 정의해주었다. windbg를 통해 x64 PEB 구조를 확인하여 정의하면 된다.

```c++
// custom struct
typedef struct _PEB {
	unsigned char    dummy[0x10];
	PVOID          ImageBase;
	PPEB_LDR_DATA    Ldr;
} PEB, * PPEB;
```

#### PEB_LDR_DATA

마찬가지로 필요한 오프셋 까지만 정의하였다. 실제 사용되는 멤버는 `InMemoryOrderModuleList` 이다.

```c++
// custom struct
typedef struct _PEB_LDR_DATA {
	DWORD         Lenght;
	DWORD         Initialized;
	PVOID         SsHandle;
	LIST_ENTRY64   InLoadOrderModuleList;
	LIST_ENTRY64   InMemoryOrderModuleList;
	LIST_ENTRY64   InInitializationOrderModuleList;
}PEB_LDR_DATA, * PPEB_LDR_DATA;
```

#### LDR_DATA_TABLE_ENTRY

위와 동일하며, 여러가지 유효 데이터를 확인하기 위해 `BaseDllName`까지 정의하였다.

```c++
// custom struct
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY64         InLoadOrderLinks;
	LIST_ENTRY64         InMemoryOrderLinks;
	LIST_ENTRY64         InInitializationOrderLinks;
	PVOID               DllBase;
	PVOID               EntryPoint;
	DWORD               SizeOfImage;
	UNICODE_STRING         FullDllName;
	UNICODE_STRING         BaseDllName;
}LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;

```



### [-] main.cpp

```c++
#include "define.h"
#pragma warning(disable:4996)

const wchar_t* targetModule = L"kernel32.dll";
const char* targetFunction = "GetProcAddress";
FARPROC pGetProcAddress = 0;

typedef FARPROC(*GetProcAddress_t)(
		HMODULE hMod,
		LPCSTR	lpProcName
	);

BOOL GetFunctionInfo(PVOID ImageBase)
{
	IMAGE_DOS_HEADER dosHeader = { 0, };
	IMAGE_NT_HEADERS64 ntHeader = { 0, };
	IMAGE_DATA_DIRECTORY dataDir = { 0, };
	IMAGE_EXPORT_DIRECTORY exportDir = { 0, };
	DWORD idx = 0;
	PVOID *namePtr = 0, *funcPtr = 0;
	char szFunc[MAX_PATH] = { 0, };

	memcpy(&dosHeader, ImageBase, sizeof(dosHeader));
	memcpy(&ntHeader, (PVOID)((DWORD64)ImageBase + dosHeader.e_lfanew), sizeof(IMAGE_NT_HEADERS64));
	memcpy(&dataDir, ntHeader.OptionalHeader.DataDirectory, 8);
	memcpy(&exportDir, (PVOID)((DWORD64)ImageBase + dataDir.VirtualAddress), sizeof(IMAGE_EXPORT_DIRECTORY));
	namePtr = (PVOID*)((DWORD64)ImageBase + exportDir.AddressOfNames);
	funcPtr = (PVOID*)((DWORD64)ImageBase + exportDir.AddressOfFunctions);

	for (int i = 0; i < exportDir.NumberOfNames; i++)
	{
		DWORD tmpOff = (DWORD)*namePtr;
		strcpy(szFunc, (const char*)(DWORD64)ImageBase + tmpOff);
		if(!strcmp(szFunc,targetFunction))
		{
			printf("[+] Found Function %s : %X\n", szFunc,i);
			idx = i*4;
			break;
		}
		namePtr = (PVOID*)((DWORD64)namePtr + 4);	// Export name table pointer ++ (DWORD)
		memset(szFunc, 0, MAX_PATH);
	}
	if (!idx)
	{
		printf("[!] Error, Not Found Function\n");
		return FALSE;
	}
	funcPtr = (PVOID*)((DWORD64)funcPtr + idx);	// Export address table pointer of GetProcAddress
	DWORD tmpOff = (DWORD)* funcPtr;
	
	pGetProcAddress = (FARPROC)((DWORD64)ImageBase+tmpOff);
	return TRUE;
}

BOOL GetProcessInfo(PROCESS_BASIC_INFORMATION ProcessInfo)
{
	PPEB Peb = ProcessInfo.PebBaseAddress;
	LDR_DATA_TABLE_ENTRY* LdrTableEntry = NULL;
	LdrTableEntry = (LDR_DATA_TABLE_ENTRY*)(Peb->Ldr->InMemoryOrderModuleList.Flink - 0x10);

	while(1)
	{
		__try
		{
			if (!wcsicmp(LdrTableEntry->BaseDllName.Buffer, targetModule))
			{
				if (GetFunctionInfo(LdrTableEntry->DllBase))
				{
					return TRUE;
				}
				else
				{
					return FALSE;
				}
			}
			LdrTableEntry = (LDR_DATA_TABLE_ENTRY*)(LdrTableEntry->InMemoryOrderLinks.Flink - 0x10);

		}__except(EXCEPTION_EXECUTE_HANDLER){
			printf("[!] Error, Not Found Module Name");
			return FALSE;
		}

	}
	return TRUE;
}


int main()
{
	PROCESS_BASIC_INFORMATION ProcessInformation = { 0, };
	PULONG Ret = NULL;
	NTSTATUS Status = 0;

	NtQueryInformationProcess_t NtQueryInformationProcess =
		(NtQueryInformationProcess_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");


	Status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &ProcessInformation, sizeof(PROCESS_BASIC_INFORMATION), Ret);
	if (Status != ERROR_SUCCESS)
	{
		printf("[!] Error Code : %IX\n", Status);
		return 0;
	}
	else
	{
		if (GetProcessInfo(ProcessInformation))
		{
			printf("[+] Found Function Address : %IX\n", pGetProcAddress);
		}

		else
		{
			printf("[!] Sorry, Not found function\n");
		}
	}
	GetProcAddress_t testProcAddress = (GetProcAddress_t)pGetProcAddress;
	testProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");


	return 0;
}
```

#### main()

`NtQueryInformationProcess`를 이용하여 `PROCESS_BASIC_INFORMATION` 구조체 정보(`ProcessBasicInformation`)를 가져온다.  그리고 `GetProcessInfo` 라는 정의 함수를 호출한다. 함수 이름대로 프로세스에서 내가 원하는 정보를 가져온다.

소스코드의 경우 프로세스에 로드 된 `kernel32.dll`의 `GetProcAddress` 함수 주소를 가져온다. 그리고 이를 `pGetProcAddress`에 복사하여 호출하는 형식이다. 

```c++
const wchar_t* targetModule = L"kernel32.dll";
const char* targetFunction = "GetProcAddress";
FARPROC pGetProcAddress = 0;

typedef FARPROC(*GetProcAddress_t)(
		HMODULE hMod,
		LPCSTR	lpProcName
	);

int main()
{
	PROCESS_BASIC_INFORMATION ProcessInformation = { 0, };
	PULONG Ret = NULL;
	NTSTATUS Status = 0;

	NtQueryInformationProcess_t NtQueryInformationProcess =
		(NtQueryInformationProcess_t)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQueryInformationProcess");


	Status = NtQueryInformationProcess(GetCurrentProcess(), ProcessBasicInformation, &ProcessInformation, sizeof(PROCESS_BASIC_INFORMATION), Ret);
	if (Status != ERROR_SUCCESS)
	{
		printf("[!] Error Code : %IX\n", Status);
		return 0;
	}
	else
	{
		if (GetProcessInfo(ProcessInformation))
		{
			printf("[+] Found Function Address : %IX\n", pGetProcAddress);
		}

		else
		{
			printf("[!] Sorry, Not found function\n");
		}
	}
	GetProcAddress_t testProcAddress = (GetProcAddress_t)pGetProcAddress;
	testProcAddress(GetModuleHandle(L"ntdll.dll"), "NtQuerySystemInformation");


	return 0;
}
```

#### GetProcessInfo()

`PROCESS_BASIC_INFORMATION` 구조체의 `PebBaseAddress` 멤버를 `PEB` 구조체 변수에 할당한다.
`Peb(PEB) -> Ldr(PEB_LDR_DATA) -> InMemoryOrderModuleList(LIST_ENTRY)` 와 같이 프로세스에 로드 된 모듈에 접근이 가능하다. `LIST_ENTRY` 구조체로 되어 있으므로, `Flink,Blink`와 같이 링크로 연결되어 있다.

자세한 설명은 소스코드 아래에 추가한다.

```c++
BOOL GetProcessInfo(PROCESS_BASIC_INFORMATION ProcessInfo)
{
	PPEB Peb = ProcessInfo.PebBaseAddress;
	LDR_DATA_TABLE_ENTRY* LdrTableEntry = NULL;
	LdrTableEntry = (LDR_DATA_TABLE_ENTRY*)(Peb->Ldr->InMemoryOrderModuleList.Flink - 0x10);

	while(1)
	{
		__try
		{
			if (!wcsicmp(LdrTableEntry->BaseDllName.Buffer, targetModule))
			{
				if (GetFunctionInfo(LdrTableEntry->DllBase))
				{
					return TRUE;
				}
				else
				{
					return FALSE;
				}
			}
			LdrTableEntry = (LDR_DATA_TABLE_ENTRY*)(LdrTableEntry->InMemoryOrderLinks.Flink - 0x10);

		}__except(EXCEPTION_EXECUTE_HANDLER){
			printf("[!] Error, Not Found Module Name");
			return FALSE;
		}

	}
	return TRUE;
}

```

소스코드를 보면 ```LdrTableEntry = (LDR_DATA_TABLE_ENTRY*)(Peb->Ldr->InMemoryOrderModuleList.Flink - 0x10);``` 위치에서 왜 `-0x10`을 하는가에 대한 의문이 들 수 있다.

x64 에서 `LIST_ENTRY` 구조체의 크기는 0x10이다. `LDR_DATA_TABLE_ENTRY` 구조체를 확인해보면 `InMemoryOrderLinks` 멤버가 딱 0x10 만큼 떨어진 위치에 존재하는 것을 알 수 있다.

이 의미는 `PEB_LDR_DATA` 구조체의 `InMemoryOrderModuleList.Flink, Blink` 는 `LDR_DATA_TABLE_ENTRY` 구조체의 `InMemoryOrderLinks` 와 참조하는 관계다.

그러므로 `LDR_DATA_TABLE_ENTRY` `InMemoryOrderModuleLIst.Flink, Blink` 에서 `-0x10` 만큼을 하면 `LDR_DATA_TABLE_ENTRY` 구조체를 확인할 수 있다. 프로세스에 로드 된 모듈의 `ImageBase`가 필요하므로 위와 같은 과정이 필요하다. 

#### GetFunctionInfo()

조잡한 코드다. PE구조에서 `Export Directory`의 정보를 이용하여 해당 모듈에서 내가 원하는 함수의 주소를 찾는 과정이다. 

요약하면, 

1. `GetProcessInfo` 함수에서 구한 모듈의 `ImageBase`를 전달받는다.
2. `IMAGE_DOS_HEADER`의 `e_lfanew` 의 값과 `ImageBase`를 더하여 `IMAGE_NT_HEADER`를 구한다.
3. `IMAGE_NT_HEADER` 내의 `OptionalHeader(IMAGE_OPTIONAL_HEADER)`에서 `DataDirectory(IMAGE_DATA_DIRECTORY)` 멤버를 구한다.
4. `DataDirectory`는 배열로 이루어져있으며, 첫번째 인덱스에 `Export Directory RVA` 값이 존재한다.
5. `IMAGE_EXPORT_DIRECTORY` 에서 `AddressOfFunctions` 와 `AddressOfNames` 의 RVA 값을 구한다.
6. 해당 RVA 값은 동일한 인덱스에 위치하므로, `GetProcAddress` 이름의 인덱스를 먼저 구하고, 함수의 주소를 구한다.

```c++
BOOL GetFunctionInfo(PVOID ImageBase)
{
	IMAGE_DOS_HEADER dosHeader = { 0, };
	IMAGE_NT_HEADERS64 ntHeader = { 0, };
	IMAGE_DATA_DIRECTORY dataDir = { 0, };
	IMAGE_EXPORT_DIRECTORY exportDir = { 0, };
	DWORD idx = 0;
	PVOID *namePtr = 0, *funcPtr = 0;
	char szFunc[MAX_PATH] = { 0, };

	memcpy(&dosHeader, ImageBase, sizeof(dosHeader));
	memcpy(&ntHeader, (PVOID)((DWORD64)ImageBase + dosHeader.e_lfanew), sizeof(IMAGE_NT_HEADERS64));
	memcpy(&dataDir, ntHeader.OptionalHeader.DataDirectory, 8);
	memcpy(&exportDir, (PVOID)((DWORD64)ImageBase + dataDir.VirtualAddress), sizeof(IMAGE_EXPORT_DIRECTORY));
	namePtr = (PVOID*)((DWORD64)ImageBase + exportDir.AddressOfNames);
	funcPtr = (PVOID*)((DWORD64)ImageBase + exportDir.AddressOfFunctions);

	for (int i = 0; i < exportDir.NumberOfNames; i++)
	{
		DWORD tmpOff = (DWORD)*namePtr;
		strcpy(szFunc, (const char*)(DWORD64)ImageBase + tmpOff);
		if(!strcmp(szFunc,targetFunction))
		{
			printf("[+] Found Function %s : %X\n", szFunc,i);
			idx = i*4;
			break;
		}
		namePtr = (PVOID*)((DWORD64)namePtr + 4);	// Export name table pointer ++ (DWORD)
		memset(szFunc, 0, MAX_PATH);
	}
	if (!idx)
	{
		printf("[!] Error, Not Found Function\n");
		return FALSE;
	}
	funcPtr = (PVOID*)((DWORD64)funcPtr + idx);	// Export address table pointer of GetProcAddress
	DWORD tmpOff = (DWORD)* funcPtr;
	
	pGetProcAddress = (FARPROC)((DWORD64)ImageBase+tmpOff);
	return TRUE;
}
```



언젠간 쓸모가 있겠지....





 

