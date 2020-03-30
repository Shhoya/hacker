---
title:  "[#] Kernel Message Box"
tags: [Post, Windows, Dev]
published: true
permalink: kernelmsgbox.html
comments: true
summary: "커널에서 메시지 박스 구현"
---

## [0x00] Overview

보통 응용 프로그램을 만들다보면 메시지 박스를 자주 활용하게 됩니다. 이러한 이유로 커널에서도 드라이버가 직접 메시지 박스를 출력할 수 없을까라는 생각을 가졌습니다. 가능합니다. `ExRaiseHardError`라는 `NtRaiseHardError`와 동일한 함수를 이용하면 가능합니다.



## [0x01] Kernel MessageBox

`ExRaiseHardError` 함수가 호출되면 오류 메시지를 `csrss.exe` 프로세스의 오류 포트로 전송합니다. 그리고 `csrss.exe` 프로세스의 힘을 빌려 메시지 박스를 출력할 수 있게 됩니다.

간략하게 메모장을 실행 시, 커널에서 메시지 박스를 출력할 수 있도록 만들어봤습니다.

### [-] Common.h

`ExRaiseHardError`에 필요한 열거형 자료들과 몇 가지 함수를 선언하였습니다.

```c++
#pragma once
#include "DriverEntry.h"

// Structure, Functions declaration

typedef enum _HARDERROR_RESPONSE_OPTION {
	
	OptionAbortRetryIgnore,
	OptionOk,
	OptionOkCancle,
	OptionRetryCancle,
	OptionYesNo,
	OptionYesNoCancle,
	OptionShutdownSystem

}HARDERROR_RESPONSE_OPTION,*PHARDERROR_RESPONSE_OPTION;

typedef enum _HARDERROR_RESPONSE {

	ResponseReturnToCaller,
	ResponseNotHandled,
	ResponseAbort,
	ResponseCancel,
	ResponseIgnore,
	ResponseNo,
	ResponseOk,
	ResponseRetry,
	ResponseYes

} HARDERROR_RESPONSE, * PHARDERROR_RESPONSE;

typedef NTSTATUS(*ExRaiseHardError_t)(
	IN  NTSTATUS                       ErrorStatus,
	IN  ULONG                          NumberOfParameters,
	IN  ULONG                          UnicodeStringParameterMask OPTIONAL,
	IN  PULONG_PTR                     Parameters,
	IN  HARDERROR_RESPONSE_OPTION      ResponseOption,
	OUT PHARDERROR_RESPONSE            Response
	);

// Display Msg Box
#define MB_ICONSTOP        0x10
#define MB_ICONINFO        0x40
#define MB_OK              0x00
#define MB_OKCANCLE        0x01

ExRaiseHardError_t ExRaiseHardError;
VOID DisplayMessageBox(IN PWSTR Text, IN PWSTR Caption, IN HARDERROR_RESPONSE_OPTION ResponseOption, IN ULONG uType);

// Get export functions from ntoskrnl.exe 
PVOID GetRoutineAddress(IN PWSTR StringName);
```



### [-] DriverEntry.h

드라이버 진입점 및 알림 루틴을 선언하였습니다.

```c++
#pragma once
#include <ntifs.h>

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath);
VOID DriverUnload(IN PDRIVER_OBJECT pDriver);

VOID LoadImageNotifyRoutine(IN PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo);
```



### [-] Common.c

`GetRoutineAddress`는 문자열을 받아 `ntoskrnl.exe`에서 `EXPORT` 함수를 찾아 주소 값을 반환합니다.
`DisplayMessageBox`는 내부적으로 `ExRaiseHardError`를 호출하며, 이를 통해 메시지 박스를 출력합니다.

```c++
#include "Common.h"

PVOID GetRoutineAddress(IN PWSTR StringName)
{
	UNICODE_STRING RoutineName = { 0, };
	RtlInitUnicodeString(&RoutineName, StringName);
	return MmGetSystemRoutineAddress(&RoutineName);
}

VOID DisplayMessageBox(IN PWSTR Text, IN PWSTR Caption, IN HARDERROR_RESPONSE_OPTION ResponseOption, IN ULONG uType)
{
	UNICODE_STRING Message = { 0, };
	UNICODE_STRING Title = { 0, };
	RtlInitUnicodeString(&Message, Text);
	RtlInitUnicodeString(&Title, Caption);
	HARDERROR_RESPONSE Response = 0;

	ULONG_PTR Parameters[4] = { 0, };
	Parameters[0] = (ULONG_PTR)&Message;
	Parameters[1] = (ULONG_PTR)&Title;
	Parameters[2] = uType;
	Parameters[3] = 0;

	if (ExRaiseHardError != NULL)
	{
		ExRaiseHardError(STATUS_SERVICE_NOTIFICATION, 3, 3, Parameters, ResponseOption, &Response);
	}
}
```



### [-] DriverEntry.c

알림 루틴을 이용하여 메모장을 실행 시, 메시지 박스가 출력되도록 만들었습니다.

```c++
#include "Common.h"

VOID LoadImageNotifyRoutine(IN PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo)
{
	UNREFERENCED_PARAMETER(ProcessId);
	UNREFERENCED_PARAMETER(ImageInfo);

	PWSTR test = L"notepad.exe";

	if (wcsstr(FullImageName->Buffer, test))
	{
		DisplayMessageBox(L"Notepad Exec", L"[INFORMATION] Shh0ya", OptionOk, MB_OK | MB_ICONINFO);
	}
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pDriver);
	UNREFERENCED_PARAMETER(pRegPath);
	pDriver->DriverUnload = DriverUnload;

	NTSTATUS Status = STATUS_UNSUCCESSFUL;

	ExRaiseHardError = (ExRaiseHardError_t)GetRoutineAddress(L"ExRaiseHardError");
	if (ExRaiseHardError)
	{
		Status = PsSetLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
		
	}
	return Status;
}

VOID DriverUnload(IN PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);
	PsRemoveLoadImageNotifyRoutine(&LoadImageNotifyRoutine);

}
```



## [0x02] Conclusion

`ntoskrnl.exe` 에서 익스포트 되는 함수들을 자주 찾아보는게 좋습니다. 굳이 구현하지 않도록 잘 짜여진 함수들이 존재하기 때문입니다. 이러한 방법이 유용한 경우는 응용 프로그램의 디버깅 방지에도 좋습니다. 메시지 박스와 같은 오류메시지를 기반으로 분석을 시작하는 경우가 있기 때문입니다.