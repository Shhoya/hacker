---
title: Process Protection
keywords: documentation, technique, debugging
tags: [Windows, Reversing, Dev]
summary: "드라이버를 이용한 프로세스 보호"
sidebar: antikernel_sidebar
permalink: antikernel_processprotect.html
folder: antikernel
---

## [0x00] Overview

프로세스 보호에 관한 내용입니다. 백신과 같은 보안 프로그램에서 어떤 식으로 프로세스를 보호하는지 먼저 알아야 합니다. 해당 챕터에서는 커널 드라이버를 이용하여 어떤 식으로 특정 프로세스 또는 파일 시스템을 보호하는지 확인할 수 있습니다.

단순히 안티 커널 디버깅 우회를 위해서라면 해당 챕터의 내용이 필요 없을 수 있습니다. 하지만 역공학을 위해서는 정공학은 필수적인 요소입니다.

이번 챕터에서는 `ObRegisterCallbacks` 함수, `PsSetLoadImageNotifyRoutine` 함수를 이용한 프로세스 보호와 우회 가능한 포인트를 확인합니다.



## [0x01] Process Protect(ObRegisterCallbacks)

커널에는 프로세스 또는 스레드가 생성될 때 동작하는 루틴, 이미지가 로드될 때 동작하는 루틴과 같이 다양한 콜백 루틴들이 존재합니다. 여기서 이미지는 모든 `PE Image`를 의미합니다. 

우리는 여기서 `ObRegisterCallbacks` 라는 함수를 이용하여 간단하게 프로세스를 보호하는 드라이버를 구현하고, 이를 분석해보겠습니다. 

먼저 `ObRegisterCallbacks` 함수와 사용되는 구조체에 관해 알아보겠습니다.



### [-] ObRegisterCallbacks

프로세스, 스레드 및 데스크톱 핸들 조작을 위한 콜백 루틴 목록을 등록하는 함수입니다.

```cpp
NTSTATUS ObRegisterCallbacks(
  POB_CALLBACK_REGISTRATION CallbackRegistration,
  PVOID                     *RegistrationHandle
);
```

- CallbackRegistration : 콜백 루틴 및 기타 등록 정보 목록을 가지고 있는 `OB_CALLBACK_REGISTRATION`의 포인터
- RegistrationHandle : 등록 된 콜백 루틴을 식별하는 값에 대한 포인터, `ObUnRegisterCallbacks` 에 전달하여 콜백 루틴의 등록을 취소



### [-] OB_CALLBACK_REGISTRATION

```cpp
typedef struct _OB_CALLBACK_REGISTRATION {
    _In_ USHORT                     Version;
    _In_ USHORT                     OperationRegistrationCount;
    _In_ UNICODE_STRING             Altitude;
    _In_ PVOID                      RegistrationContext;
    _In_ OB_OPERATION_REGISTRATION  *OperationRegistration;
} OB_CALLBACK_REGISTRATION, *POB_CALLBACK_REGISTRATION;
```

- Version : 요청 된 Object Callback Registration 의 버전, 드라이버는 `OB_FLT_REGISTRATION_VERSION` 값을 지정
- OperationRegistrationCount : `OperationRegistration` 배열의 항목 수
- Altitude : 드라이버의 고도(유니코드), MS에 등록되어 사용되며 로드 순서와도 관계가 있음
- RegistrationContext : 콜백 루틴이 실행될 때 해당 값을 콜백 루틴으로 전달
- OperationRegistration : `OB_OPERATION_REGISTRATION`의 포인터, `ObjectPre, PostCallback` 루틴이 호출되는 유형을 지정



### [-] OB_OPERATION_REGISTRATION

```cpp
typedef struct _OB_OPERATION_REGISTRATION {
    POBJECT_TYPE                *ObjectType;
    OB_OPERATION                Operations;
    POB_PRE_OPERATION_CALLBACK  PreOperation;
    POB_POST_OPERATION_CALLBACK PostOperation;
} OB_OPERATION_REGISTRATION, *POB_OPERATION_REGISTRATION;
```

- ObjectType : 콜백 루틴을 동작시키는 오브젝트 유형에 대한 포인터
  - PsProcessType : 프로세스 핸들 동작을 위한 유형
  - PsThreadType : 스레드 핸들 동작을 위한 유형
  - ExDesktopObjectType : 데스크톱 핸들 동작을 위한 유형
- Operations : 아래와 같은 플래그를 지정
  - OB_OPERATION_HANDLE_CREATE : 새로운 핸들(`ObjectType`에 따른)이 생성되거나 열었을 경우 동작
  - OB_OPERATION_HANDLE_DUPLICATE : 새로운 핸들을 복제하거나 복제된 경우 동작
- PreOperation : `OB_PRE_OPERATION_CALLBACK`의 포인터, 요청된 작업이 발생하기 전에 해당 루틴을 호출
- PostOperation : `OB_POST_OPERATION_CALLBACK`의 포인터, 요청된 작업이 발생한 후에 해당 루틴을 호출



### [-] OB_PRE(POST)_OPERATION_CALLBACK

```cpp
POB_PRE_OPERATION_CALLBACK PobPreOperationCallback;
POB_POST_OPERATION_CALLBACK PobPostOperationCallback;

OB_PREOP_CALLBACK_STATUS PobPreOperationCallback(
  PVOID RegistrationContext,
  POB_PRE_OPERATION_INFORMATION OperationInformation
)
{...}

void PobPostOperationCallback(
  PVOID RegistrationContext,
  POB_POST_OPERATION_INFORMATION OperationInformation
)
{...}
```

- RegistrationContext : `OB_CALLBACK_REGISTRATION` 내 `RegistrationContext`와 동일
- OperationInformation : `OB_PRE(POST)_OPERATION_INFORMATION`의 포인터, 핸들 동작의 파라미터를 지정



### [-] OB_PRE(POST)_OPERATION_INFORMATION

```c++
typedef struct _OB_PRE_OPERATION_INFORMATION {
    _In_ OB_OPERATION           Operation;
    union {
        _In_ ULONG Flags;
        struct {
            _In_ ULONG KernelHandle:1;
            _In_ ULONG Reserved:31;
        };
    };
    _In_ PVOID                         Object;
    _In_ POBJECT_TYPE                  ObjectType;
    _Out_ PVOID                        CallContext;
    _In_ POB_PRE_OPERATION_PARAMETERS  Parameters;
} OB_PRE_OPERATION_INFORMATION, *POB_PRE_OPERATION_INFORMATION;

typedef struct _OB_POST_OPERATION_INFORMATION {
    _In_ OB_OPERATION  Operation;
    union {
        _In_ ULONG Flags;
        struct {
            _In_ ULONG KernelHandle:1;
            _In_ ULONG Reserved:31;
        };
    };
    _In_ PVOID                          Object;
    _In_ POBJECT_TYPE                   ObjectType;
    _In_ PVOID                          CallContext;
    _In_ NTSTATUS                       ReturnStatus;
    _In_ POB_POST_OPERATION_PARAMETERS  Parameters;
} OB_POST_OPERATION_INFORMATION,*POB_POST_OPERATION_INFORMATION;
```

- Operation : Handle Operation의 유형
  - OB_OPERATION_HANDLE_CREATE : 프로세스 또는 스레드  핸들 생성
  - OB_OPERATIOIN_HANDLE_DUPLICATE : 프로세스 또는 스레드의 핸들이 복제
- Flags : 예약 된 영역, `KernelHandle` 사용
- KernelHandle : 핸들이 커널 핸들인지를 지정하는 값. TRUE인 경우 커널 핸들
- Reserved : 시스템에서 사용하기 위한 예약 영역
- Object : 프로세스 또는 스레드 오브젝트(EPROCESS, ETHREAD 등)
- ObjectType : `PsProcessType` 또는 `PsThreadType`
- CallContext : 드라이버의 특정 컨텍스트 정보에 대한 포인터
- ReturnStatus(POST) : 핸들 동작에 대한 `NTSTATUS`
- Parameters : `OB_PRE(POST)_OPERATION_PARAMETERS` 에 대한 포인터



### [-] OB_PRE(POST)_OPERATION_PARAMETERS

```c++
typedef union _OB_PRE_OPERATION_PARAMETERS {
  OB_PRE_CREATE_HANDLE_INFORMATION    CreateHandleInformation;
  OB_PRE_DUPLICATE_HANDLE_INFORMATION DuplicateHandleInformation;
} OB_PRE_OPERATION_PARAMETERS, *POB_PRE_OPERATION_PARAMETERS;

typedef union _OB_POST_OPERATION_PARAMETERS {
  OB_POST_CREATE_HANDLE_INFORMATION    CreateHandleInformation;
  OB_POST_DUPLICATE_HANDLE_INFORMATION DuplicateHandleInformation;
} OB_POST_OPERATION_PARAMETERS, *POB_POST_OPERATION_PARAMETERS;
```

- CreateHandleInformation : 열려있는 핸들과 관련 정보를 포함하는 `OB_PRE(POST)_CREATE_HANDLE_INFORMATION`  구조
- DuplicateHandleInformation : 복제된 핸들과 관련 정보를 포함하는 `OB_PRE(POST)_DUPLICATE_HANDLE_INFORMATION` 구조



### [-] OB_PRE(POST)_CREATE_HANDLE_INFORMATION

```c++
typedef struct _OB_PRE_CREATE_HANDLE_INFORMATION {
  ACCESS_MASK DesiredAccess;
  ACCESS_MASK OriginalDesiredAccess;
} OB_PRE_CREATE_HANDLE_INFORMATION, *POB_PRE_CREATE_HANDLE_INFORMATION;

typedef struct _OB_POST_CREATE_HANDLE_INFORMATION {
  ACCESS_MASK GrantedAccess;
} OB_POST_CREATE_HANDLE_INFORMATION, *POB_POST_CREATE_HANDLE_INFORMATION;
```

- DesiredAccess(PRE) : `OriginalDesiredAccess` 값과 기본적으로 동일하지만 `PreCallback` 루틴을 이용하여 액세스를 제한할 수 있음
- OriginalDesiredAccess(PRE) : 핸들에 요청 된 원래의 액세스를 지정하는 값
- GrantedAccess(POST) : 핸들에 부여 된 액세스를 지정하는 값



## [0x02] ObRegisterCallbacks Template

위의 내용을 토대로 `ObRegisterCallbacks` 함수를 사용해보고 어떻게 동작하는지 확인해보겠습니다.
우선 콜백 루틴이 어떻게 동작하는지 알기 위해 `ObRegisterCallbakcs` 함수의 템플릿을 만들었습니다.(x64 기준)

- <a href="https://github.com/shhoya/Examples">예제 소스코드</a> 

{% include warning.html content="BSOD가 발생할 수 있습니다. 속성 페이지 -> 링커 -> 명령줄 에 /INTEGRITYCHECK 옵션을 추가하고 컴파일해야 합니다." %}



### [-] common.h

```cpp
#pragma once
#include <ntifs.h>

//============================================//
//======= DriverEntry & Unload Routine =======//
//============================================//

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath);
VOID UnloadDriver(IN PDRIVER_OBJECT pDriver);


//============================================//
//====== Object Callback Routine Define ======//
//============================================//

OB_PREOP_CALLBACK_STATUS PreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);
void PostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION pOperationInformation);


//============================================//
//========== User-defined Function  ==========//
//============================================//

NTSTATUS ObRegExample();
```

드라이버 로드, 언로드 루틴, Pre,Post 콜백 루틴, 예제에 사용할 정의 함수에 대한 정의입니다.



### [-]  callbacks.h

```cpp
#pragma once
#include "common.h"

//============================================//
//======= Pre&Post Callback Functions ========//
//============================================//

OB_PREOP_CALLBACK_STATUS PreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(pOperationInformation);
	
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Pre Callback Routine");

	return OB_PREOP_SUCCESS;
}

void PostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(pOperationInformation);

	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Post Callback Routine\n");
}
```

`PreOperation`과 `PostOperation` 에 대한 콜백 루틴입니다. 동작할 때 단순히 출력만 하도록 작성되었습니다.



### [-] main.c

```c++
#include "callbacks.h"

PVOID hRegistration = NULL;	// 언로드 시, 사용하기 위해 전역변수로 선언

/*
# Name  : ObRegExample
# Param : x
# Desc  : OB_CALLBACK, OPERATION_REGISTRATION 구조체 초기화 및 ObRegisterCallbacks 를 이용해 콜백 루틴 등록
*/
NTSTATUS ObRegExample()
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

	return ObRegisterCallbacks(&obRegistration,&hRegistration);
}

/*
# Name  : DriverEntry
# Param : PDRIVER_OBJECT, PUNICODE_STRING
# Desc  : 드라이버 진입점
*/
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	UNREFERENCED_PARAMETER(pDriver);

	NTSTATUS ret = STATUS_SUCCESS;
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Load Driver\n");

	pDriver->DriverUnload = UnloadDriver;	// 언로드 루틴 등록

	ret = ObRegExample();

	if (ret==STATUS_SUCCESS)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Success Registeration\n");
	}
	else
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Failed Registration %X\n",ret);
	}
	return STATUS_SUCCESS;
}

/*
# Name  : UnloadDriver
# Param : PDRIVER_OBJECT
# Desc  : 드라이버 종료 루틴, 등록된 콜백 루틴을 해제
*/
VOID UnloadDriver(IN PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);

	if (hRegistration)	// 콜백 등록에 실패할 경우 예외 처리
	{
		ObUnRegisterCallbacks(hRegistration);
	}
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Unload Driver\n");
}
```

헷갈릴 수 있는 부분에 대해 주석처리 해놨습니다. `OSRLoader`를 이용하여 로드하면 `DbgView`에서 다음과 같은 출력을 확인할 수 있습니다.

<img src="https://github.com/Shh0ya/shh0ya.github.io/blob/master/rsrc/antikernel/proc_00.png?raw=true">



## [0x03] ObRegisterCallbacks Example

이제 위에서 만든 템플릿으로 실제 프로세스를 보호하는 내용을 작성합니다. `PreCallback`과 `PostCallback` 함수를 수정하여 프로세스 또는 스레드 객체가 생성, 복제 될 때 동작에 맞춰 제어할 수 있습니다.

- <a href="https://github.com/shhoya/Examples">예제 소스코드</a> 

{% include note.html content="해당 예제는 다양하게 수정 가능하도록 만들어졌습니다. 수정하여 테스트해야 합니다." %}

### [-] offset.h

```c++
#pragma once
#include <ntifs.h>

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

HANDLE hPid;
IMPORT_OFFSET iOffset;
const char szSystem[] = "System";
const wchar_t szNtQueryInformationProcess[] = L"NtQueryInformationProcess";
```

OS 버전 별 제약을 줄이고자 `EPROCESS` 구조체 오프셋을 구하기 위해 정의한 헤더 입니다.



### [-] callbacks.h

```c++
#pragma once
#include "offset.h"

#define PROCESS_TERMINATE       0x0001	// TerminateProcess
#define PROCESS_VM_OPERATION    0x0008	// VirtualProtect, WriteProcessMemory
#define PROCESS_VM_READ         0x0010	// ReadProcessMemory
#define PROCESS_VM_WRITE        0x0020	// WriteProcessMemory

//============================================//
//======= Pre&Post Callback Functions ========//
//============================================//

OB_PREOP_CALLBACK_STATUS PreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(pOperationInformation);

	char szProcName[16] = { 0, };
	strcpy_s(szProcName, 16, ((DWORD64)pOperationInformation->Object + iOffset.ImageFileName_off));
	if (!_strnicmp(szProcName, "notepad.exe",16))
	{
		if ((pOperationInformation->Operation == OB_OPERATION_HANDLE_CREATE))
		{
			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_TERMINATE) == PROCESS_TERMINATE)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_TERMINATE;
			}

			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_READ) == PROCESS_VM_READ)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_READ;
			}

			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_OPERATION) == PROCESS_VM_OPERATION)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_OPERATION;
			}

			if ((pOperationInformation->Parameters->CreateHandleInformation.OriginalDesiredAccess & PROCESS_VM_WRITE) == PROCESS_VM_WRITE)
			{
				pOperationInformation->Parameters->CreateHandleInformation.DesiredAccess &= ~PROCESS_VM_WRITE;
			}
		}
	}
	return OB_PREOP_SUCCESS;
}

void PostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION pOperationInformation)
{
	UNREFERENCED_PARAMETER(RegistrationContext);
	UNREFERENCED_PARAMETER(pOperationInformation);
	
	PLIST_ENTRY pListEntry = { 0, };
	char szProcName[16] = { 0, };
	strcpy_s(szProcName, 16, ((DWORD64)pOperationInformation->Object + iOffset.ImageFileName_off));
	if (!_strnicmp(szProcName, "notepad.exe", 16))
	{
		pListEntry = ((DWORD64)pOperationInformation->Object + iOffset.ActiveProcessLinks_off);
		if (pListEntry->Flink != NULL && pListEntry->Blink != NULL)
		{
			pListEntry->Flink->Blink = pListEntry->Blink;
			pListEntry->Blink->Flink = pListEntry->Flink;

			pListEntry->Flink = 0;
			pListEntry->Blink = 0;
		}
	}
}
```

실제 콜백 루틴의 동작이 작성되어 있습니다. `PreCallback` 에서는 핸들의 액세스 권한을 제어합니다. `PostCallback`에서는 `DKOM`으로 알려진 프로세스 은닉 기법이 작성되어 있습니다. 



### [-] common.h

```c++
#pragma once
#include "callbacks.h"

//============================================//
//======= DriverEntry & Unload Routine =======//
//============================================//

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath);
VOID UnloadDriver(IN PDRIVER_OBJECT pDriver);


//============================================//
//====== Object Callback Routine Define ======//
//============================================//

OB_PREOP_CALLBACK_STATUS PreCallback(PVOID RegistrationContext, POB_PRE_OPERATION_INFORMATION pOperationInformation);
void PostCallback(PVOID RegistrationContext, POB_POST_OPERATION_INFORMATION pOperationInformation);


//============================================//
//========== User-defined Function  ==========//
//============================================//

NTSTATUS ObRegExample();
BOOLEAN GetOffset(PEPROCESS Process);
BOOLEAN GetPebOffet();
```

`EPROCESS` 구조체 내 필요한 멤버들의 오프셋을 구하는 `GetOffset`과 `GetPebOffset` 함수가 선언되어 있습니다.



### [-] main.c

```c++
#include "common.h"

PVOID hRegistration = NULL;	// 언로드 시, 사용하기 위해 전역변수로 선언


/*
# Name  : GetPebOffset
# Param : x
# Desc  : EPROCESS 구조체 내 PEB 멤버 오프셋 구하기
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

/*
# Name  : GetOffset
# Param : PEPROCESS
# Desc  : EPROCESS 구조체 내 PID, EPROCESS List Entry, ImageFileName 오프셋 구하기
*/
BOOLEAN GetOffset(IN PEPROCESS Process)
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
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Not Found Offset... Sorry :(\n");
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
		return success;
	}

	if (!GetPebOffset())
	{
		return success;
	}
	return success;
}

/*
# Name  : ObRegExample
# Param : x
# Desc  : OB_CALLBACK, OPERATION_REGISTRATION 구조체 초기화 및 ObRegisterCallbacks 를 이용해 콜백 루틴 등록
*/
NTSTATUS ObRegExample()
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

	return ObRegisterCallbacks(&obRegistration,&hRegistration);
}

/*
# Name  : DriverEntry
# Param : PDRIVER_OBJECT, PUNICODE_STRING
# Desc  : 드라이버 진입점
*/
NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);
	UNREFERENCED_PARAMETER(pDriver);

	NTSTATUS ret = STATUS_SUCCESS;
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Load Driver\n");

	pDriver->DriverUnload = UnloadDriver;	// 언로드 루틴 등록
	if (GetOffset(PsGetCurrentProcess()))
	{
		ret = ObRegExample();

		if (ret == STATUS_SUCCESS)
		{
			DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Success Registeration\n");
		}
		else
		{
			DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Failed Registration %X\n", ret);
		}
	}

	else
	{
		DbgPrintEx(DPFLTR_ACPI_ID, 0, "[!] Failed Get EPROCESS Offsets\n");
	}
	return STATUS_SUCCESS;
}

/*
# Name  : UnloadDriver
# Param : PDRIVER_OBJECT
# Desc  : 드라이버 종료 루틴, 등록된 콜백 루틴을 해제
*/
VOID UnloadDriver(IN PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);

	if (hRegistration)	// 콜백 등록에 실패할 경우 예외 처리
	{
		ObUnRegisterCallbacks(hRegistration);
	}
	DbgPrintEx(DPFLTR_ACPI_ID, 0, "[+] Unload Driver\n");
}
```

`GetOffset`과 `GetPebOffset` 함수에 대한 설명은 `Archive` 내 `Shh0ya API` 내에 정리되어 있습니다.







