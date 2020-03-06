---
title: Process Protection
keywords: documentation, technique, debugging
tags: [Windows, Reversing, Dev]
summary: "드라이버를 이용한 프로세스 보호(2)"
sidebar: antikernel_sidebar
permalink: antikernel_processprotect2.html
folder: antikernel
---

## [0x00] Overview

프로세스 보호에 관한 내용입니다. 백신과 같은 보안 프로그램에서 어떤 식으로 프로세스를 보호하는지 먼저 알아야 합니다. 해당 챕터에서는 커널 드라이버를 이용하여 어떤 식으로 특정 프로세스 또는 파일 시스템을 보호하는지 확인할 수 있습니다.

단순히 안티 커널 디버깅 우회를 위해서라면 해당 챕터의 내용이 필요 없을 수 있습니다. 하지만 역공학을 위해서는 정공학은 필수적인 요소입니다.

이번 챕터에서는 `ObRegisterCallbacks` 함수, `PsSetLoadImageNotifyRoutine` 함수를 이용한 프로세스 보호와 우회 가능한 포인트를 확인합니다.



## [0x01] Process Protect(NotifyRoutine)

마찬가지로 콜백 루틴 중 하나입니다. 이름에서 알 수 있듯이 알려주는 루틴이라고 볼 수 있습니다. 이 중에 우리는 `PsSetLoadImageNotifyRoutine` 함수를 이용하여 콜백 루틴을 등록하고 사용할 것입니다.



### [-] PsSetLoadImageNotifyRoutine

로드되는 이미지들에 대한 알림을 받을 콜백 루틴을 등록하는 함수입니다.

```c++
NTSTATUS PsSetLoadImageNotifyRoutine(
  PLOAD_IMAGE_NOTIFY_ROUTINE NotifyRoutine
);
```

- NotifyRoutine : 이미지가 로드되는 것을 알리기 위해 구현한 `LOAD_IMAGE_NOTIFY_ROUTINE` 콜백 루틴의 포인터

{% include note.html content="최대 드라이버 수는 8개 입니다.Windows 8.1과 7 SP1부터 64개로 늘어났습니다." %}



### [-] LOAD_IMAGE_NOTIFY_ROUTINE

드라이버 이미지 또는 사용자 이미지(DLL, EXE) 가 가상 메모리에 매핑 될 때 호출되는 콜백 루틴

```c++
PLOAD_IMAGE_NOTIFY_ROUTINE PloadImageNotifyRoutine;

void PloadImageNotifyRoutine(
  PUNICODE_STRING FullImageName,
  HANDLE ProcessId,
  PIMAGE_INFO ImageInfo
)
{...}
```

- FullImageName : `UNICOE_STRING` 으로 이루어진 실행 가능한 이미지 파일 이름의 포인터(NULL 일 수 있음)
- ProcessId : 이미지가 맵핑 된 프로세스의 식별 값이지만, 드라이버의 경우 0
- ImageInfo : 이미지 정보가 포함 된 `IMAGE_INFO` 구조에 대한 포인터

{% include note.html content="https://docs.microsoft.com/ko-kr/windows-hardware/drivers/kernel/windows-kernel-mode-process-and-thread-manager#best" %}



### [-] IMAGE_INFO

```c++
typedef struct _IMAGE_INFO {
  union {
    ULONG Properties;
    struct {
      ULONG ImageAddressingMode : 8;
      ULONG SystemModeImage : 1;
      ULONG ImageMappedToAllPids : 1;
      ULONG ExtendedInfoPresent : 1;
      ULONG MachineTypeMismatch : 1;
      ULONG ImageSignatureLevel : 4;
      ULONG ImageSignatureType : 3;
      ULONG ImagePartialMap : 1;
      ULONG Reserved : 12;
    };
  };
  PVOID  ImageBase;
  ULONG  ImageSelector;
  SIZE_T ImageSize;
  ULONG  ImageSectionNumber;
} IMAGE_INFO, *PIMAGE_INFO;
```

- Properties : 공용체 내 모든 비트 값
- ImageAddressingMode : 항상 IMAGE_ADDRESSING_MODE_32BIT 로 설정
- SystemModeImage : 드라이버와 같이 커널 모드의 구성요소의 경우 1, 유저모드에 매핑 된 이미지의 경우 0
- ImageMappedToAllPids : 항상 0
- ExtendedInfoPresent : 해당 비트가 설정된 경우 `IMAGE_INFO`는 `IMAGE_INFO_EX`의 일부
- MachineTypeMismatch : 항상 0
- ImageSignatureLevel : 코드 무결성(CI)이 이미지에 레이블을 붙인 서명의 수준(`ntddk.h` 내 `SE_SIGNING_LEVEL_*` 상수 중 하나)
- ImageSignatureType : 코드 무결성(CI)이 이미지에 레이블을 붙인 서명의 유형(`ntddk.h` 내 `SE_IMAGE_SIGNATURE_TYPE` enum 의 값 중 하나)
- ImagePartialMap : 맵핑뷰가 전체 이미지를 맵핑하지 않는 경우 0이 아닌 값, 전체 이미지를 맵핑하는 경우 0
- Reserved : 항상 0
- ImageBase : 이미지의 ImageBase
- ImageSelector : 항상 0
- ImageSize : 이미지의 Virtual Size
- ImageSectionNumber : 항상 0



### [-] IMAGE_INFO_EX

`IMAGE_INFO` 구조체에서 `ExtendedInfoPresent`의 비트가 설정되면 `IMAGE_INFO_EX` 구조체 내부에 포함됩니다.

```c++
typedef struct _IMAGE_INFO_EX {
  SIZE_T              Size;
  IMAGE_INFO          ImageInfo;
  struct _FILE_OBJECT *FileObject;
} IMAGE_INFO_EX, *PIMAGE_INFO_EX;
```

- Size : `IMAGE_INFO_EX` 구조체의 크기
- ImageInfo : `IMAGE_INFO` 구조체
- FileObject : 드라이버에서 파일 객체를 참조하여 특정 작업을 할 수 있음, 이미지 파일에 대한 파일 객체



## [0x02] PsSetLoadImageNotifyRoutine Template

### [-] notify.h

굳이 만들 필요는 없지만 추후에 따로 정의할 수 있기 때문에 선언 헤더 파일을 만들었습니다.

```c++
#pragma once
#include <ntifs.h>

VOID LoadImageNotifyRoutine(IN PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo);
```



### [-] common.h

단순히 드라이버 엔트리와 언로드 루틴의 선언이 되어 있습니다.

```c++
#pragma once
#include "notify.h"

//============================================//
//======= DriverEntry & Unload Routine =======//
//============================================//

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath);
VOID UnloadDriver(IN PDRIVER_OBJECT pDriver);
```



### [-] main.c

드라이버 엔트리에서 `NotifyRoutine`을 등록하고, 어떠한 동작을 할지 정의되어 있습니다. 단순히 `ImageInfo` 내 `SystemModeImage` 비트를 이용하여 드라이버인지 유저모드 이미지인지 나눠 출력하고 있습니다.

```c++
#include "common.h"

VOID LoadImageNotifyRoutine(IN PUNICODE_STRING FullImageName, IN HANDLE ProcessId, IN PIMAGE_INFO ImageInfo)
{
	if (!ImageInfo->SystemModeImage)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, 
			"[INFO] Load Image Name : \n\t[%.4X] %wZ\n", ProcessId,FullImageName);
	}

	else
	{
		DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL,
			"[INFO] Load Driver Name : \n\t[%.4X] %wZ\n", ProcessId, FullImageName);
	}
}

NTSTATUS DriverEntry(IN PDRIVER_OBJECT pDriver, IN PUNICODE_STRING pRegPath)
{
	UNREFERENCED_PARAMETER(pRegPath);

	pDriver->DriverUnload = UnloadDriver;

	DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] Load Driver\n");
	
	if (PsSetLoadImageNotifyRoutine(&LoadImageNotifyRoutine) != STATUS_SUCCESS)
	{
		DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_ERROR_LEVEL, "[ERROR] Failed register\n");
		
	}
	else
	{
		DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] Success register\n");
	}

	return STATUS_SUCCESS;
}
VOID UnloadDriver(IN PDRIVER_OBJECT pDriver)
{
	UNREFERENCED_PARAMETER(pDriver);
	PsRemoveLoadImageNotifyRoutine(&LoadImageNotifyRoutine);
	DbgPrintEx(DPFLTR_ACPI_ID, DPFLTR_INFO_LEVEL, "[INFO] Unload Driver\n");

}

```



<img src="https://github.com/Shh0ya/shh0ya.github.io/blob/master/rsrc/antikernel/proc_01.png?raw=true">



## [0x03] PsSetLoadImageNotifyRoutine Example



