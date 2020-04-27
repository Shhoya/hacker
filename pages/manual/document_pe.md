---
title: PE Header inside
keywords: documentation, Windows, PE
date: 2020-04-27
tags: [Windows, Reversing, Kernel]
summary: "PE 헤더 구조"
sidebar: manual_sidebar
permalink: document_pe.html
folder: manual

---

## [0x00] Overview

PE 포맷에 관한 설명입니다. 가장 기본이 되지만 가장 쉽게 잊어버리는 내용이기도 합니다.
주로 코드와 주석내용으로 작성됩니다.

## [0x01] IMAGE_DOS_HEADER
주로 `e_lfanew` 멤버 또는 `e_magic` 멤버를 사용하는 일이 많습니다.
```c++
typedef struct _IMAGE_DOS_HEADER {      // DOS .EXE header
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved words
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved words
    LONG   e_lfanew;                    // File address of new exe header
  } IMAGE_DOS_HEADER, *PIMAGE_DOS_HEADER;
```


## [0x02] IMAGE_NT_HEADERS

```c++
typedef struct _IMAGE_NT_HEADERS64 {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
} IMAGE_NT_HEADERS64, *PIMAGE_NT_HEADERS64;

typedef struct _IMAGE_NT_HEADERS {
    DWORD Signature;
    IMAGE_FILE_HEADER FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
} IMAGE_NT_HEADERS32, *PIMAGE_NT_HEADERS32;
```

**`Signature`**

PE 이미지를 의미하는 식별 값입니다. 해당 바이트는 `PE\0\0(0x50450000)` 값을 가집니다.

**`FileHeader`**

파일의 헤더를 의미하는 `IMAGE_FILE_HEADER` 구조체입니다.

**`OptionalHeader`**

마찬가지로 파일 헤더지만 좀 더 세분화 된 내용들을 의미하는 멤버로 이루어진 `IMAGE_OPTIONAL_HEADER` 구조체입니다.

## [0x03] IMAGE_FILE_HEADER

COFF 헤더라고도 합니다.

```c++
typedef struct _IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
} IMAGE_FILE_HEADER, *PIMAGE_FILE_HEADER;
```

**`Machine`**

컴퓨터의 아키텍처 유형을 의미합니다. 해당 멤버는 아래와 같은 값을 가질 수 있습니다.

- `IMAGE_FILE_MACHINE_I386`  (0x014C) ; x86
- `IMAGE_FILE_MACHINE_IA64`  (0x0200) ; Intel Itanium
- `IMAGE_FILE_MACHINE_AMD64` (0x8664) ; x64

**`NumberOfSections`**

섹션의 수를 의미합니다. Windows 로더는 섹션의 수를 96개로 제한하고 있습니다.

**`TimeDateStamp`**

링커가 이미지를 생성한 날짜와 시간을 나타내며, 하위 32비트의 타임 스탬프로 구성됩니다.

**`PointerToSymbolTable`**

바이트 단위로 이루어진 심볼 테이블의 오프셋입니다.

**`NumberOfSymbols`**

심볼 테이블 내 심볼의 수 입니다.

**`SizeOfOptionalHeader`**

`OptionalHEader`의 크기입니다. 오브젝트 파일의 경우 반드시 이 값은 0 이어야 합니다.

**`Characteristics`**

이미지의 특성을 의미합니다. 아래와 같은 값을 가질 수 있습니다.

- `IMAGE_FILE_RELOCS_STRIPPED`(0x0001)  
    - 재배치 정보가 제거되었음을 의미합니다. BaseAddress에 로드되며 사용 불가한 주소인 경우 오류가 발생합니다.
- `IMAGE_FILE_EXECUTABLE_IMAGE`(0x0002)
    - 실행 가능한 파일을 의미합니다.
    
- `IMAGE_FILE_LINE_NUMBS_STRIPPED`(0x0004)
    - 라인 숫자가 파일에서 제거되었음을 의미합니다.
- `IMAGE_FILE_LOCAL_SYSM_STRIPPED`(0x0008)
    - 심볼 테이블이 파일에서 제거되었음을 의미합니다.
- `IMAGE_FILE_AGGRESIVE_WS_TRIM`(0x0010)
    - 해당 값은 더 이상 사용되지 않습니다.
- `IMAGE_FILE_LARGE_ADDRESS_AWARE`(0x0020)
    - 2GB 이상의 메모리 공간을 이용할 수 있음을 의미합니다.
- `IMAGE_FILE_BYTES_REVERSED_LO`(0x0x0080)
    - 해당 값은 더 이상 사용되지 않습니다.
- `IMAGE_FILE_32BIT_MACHINE`(0x0100)
    - 32비트를 지원합니다.
- `IMAGE_FILE_DEBUG_STRIPPED`(0x0200)
    - 디버깅 정보가 제거되어 다른 파일에 별도로 저장되어 있음을 의미합니다.
- `IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP`(0x0400)
    - 만약 이미지가 이동식 저장 장치에 있는 경우, 복사하여 스왑 파일에서 실행해야 합니다.
- `IMAGE_FILE_NET_RUN_FROM_SWAP`(0x0800)
    - 만약 이미지가 네트워크에 존재하는 경우 이미지를 복사하여 스왑 파일에서 실행해야 합니다.
- `IMAGE_FILE_SYSTEM`(0x1000)
    - 시스템 파일입니다.
- `IMAGE_FILE_DLL`(0x2000)
    - DLL 파일입니다. 실행 가능한 파일이지만 직접 실행은 불가능합니다.
- `IMAGE_FILE_UP_SYSTEM_ONLY`(0x4000)
    - 해당 파일은 단일 프로세서 컴퓨터에서만 실행해야 합니다.
- `IMAGE_FILE_BYTES_REVERSED_HI`(0x8000)
    - 더 이상 사용되지 않습니다.



## [0x04] IMAGE_OPTIONAL_HEADER

```c++
typedef struct _IMAGE_OPTIONAL_HEADER {
    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;
    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER32, *PIMAGE_OPTIONAL_HEADER32;

typedef struct _IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
} IMAGE_OPTIONAL_HEADER64, *PIMAGE_OPTIONAL_HEADER64;
```

**`Magic`**

이미지 파일의 상태를 의미합니다. 아래의 값을 가질 수 있습니다.

- `IMAGE_NT_OPTIONAL_HDR32_MAGIC`(0x010B)
  - 실행 가능한 32-bit 애플리케이션
- `IMAGE_NT_OPTIONAL_HDR64_MAGIC`(0x020B)
  - 실행 가능한 64-bit 애플리케이션
- `IMAGE_ROM_OPTIONAL_HDR_MAGIC`(0x0107)
  - ROM 이미지 파일

**`MajorLinkerVersion`**

링커의 메이저 버전 숫자를 의미합니다.

**`MinorLinkerVersion`**

링커의 마이너 버전 숫자를 의미합니다.

**`SizeOfCode`**

코드 섹션의 크기를 의미하거나 코드 섹션이 여러 개인 경우 모든 코드 섹션의 합을 의미합니다.

**`SizeOfInitializedData`**

초기화 된 데이터 섹션의 크기 또는 여러 개인 경우 모든 초기화 된 데이터 섹션의 합을 의미합니다.

**`SizeOfUninitializedData`**

초기화 되지 않은 데이터 섹션의 크기 또는 여러 개인 경우 모든 초기화 되지 않은 데이터 섹션의 합을 의미합니다.

**`AddressOfEntryPoint`**

`ImageBase` 기준으로 진입점 함수에 대한 포인터를 의미합니다. 

**`BaseOfCode`**

이미지 베이스 기준으로 코드 섹션의 시작에 대한 포인터를 의미합니다.

**`BaseOfData`**

이미지 베이스 기준으로 데이터 섹션의 시작에 대한 포인터를 의미합니다.

**`ImageBase`**

이미지가 메모리에 로드 될 때 첫 바이트의 주소를 의미합니다.

**`SectionAlignment`**

메모리에 로드 되는 각 섹션의 최소 할당 단위를 의미합니다. 기본 값은 페이지 크기로 0x1000 을 가지며 이 값은 `FileAlignment` 멤버보다 크거나 같아야 합니다.

**`FileAlignment`** 

각 섹션 로우 데이터의 최소 할당 단위를 의미합니다. 기본 값은 0x200을 가집니다. `SectionAlignment` 멤버가 페이지 크기보다 작은 경우, `SectionAlignment` 값과 같아야 합니다.

**메이저 버전과 마이너 버전은 생략합니다.**

**`SizeOfImage`**

모든 헤더를 포함한 이미지의 크기를 의미합니다. `SectionAlignment`의 배수 여야합니다.

**`SizeOfHeaders`**

헤더들 크기의 합입니다. `FileAlignment` 멤버의 값의 배수로 반올림됩니다.

**`Checksum`**

이미지 파일의 체크섬 값입니다. 유효성 검사에 사용됩니다.

**`Subsystem`**

해당 이미지를 실행하는 데 필요한 서브 시스템을 의미합니다. 아래와 같은 값으로 정의됩니다.

| Value                                            | Meaning                                                      |
| :----------------------------------------------- | :----------------------------------------------------------- |
| **IMAGE_SUBSYSTEM_UNKNOWN**(0)                   | Unknown subsystem.                                           |
| **IMAGE_SUBSYSTEM_NATIVE**(1)                    | No subsystem required (device drivers and native system processes). |
| **IMAGE_SUBSYSTEM_WINDOWS_GUI**(2)               | Windows graphical user interface (GUI) subsystem.            |
| **IMAGE_SUBSYSTEM_WINDOWS_CUI**(3)               | Windows character-mode user interface (CUI) subsystem.       |
| **IMAGE_SUBSYSTEM_OS2_CUI**(5)                   | OS/2 CUI subsystem.                                          |
| **IMAGE_SUBSYSTEM_POSIX_CUI**(7)                 | POSIX CUI subsystem.                                         |
| **IMAGE_SUBSYSTEM_WINDOWS_CE_GUI**(9)            | Windows CE system.                                           |
| **IMAGE_SUBSYSTEM_EFI_APPLICATION**(10)          | Extensible Firmware Interface (EFI) application.             |
| **IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER**(11)  | EFI driver with boot services.                               |
| **IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER**(12)       | EFI driver with run-time services.                           |
| **IMAGE_SUBSYSTEM_EFI_ROM**(13)                  | EFI ROM image.                                               |
| **IMAGE_SUBSYSTEM_XBOX**(14)                     | Xbox system.                                                 |
| **IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION**(16) | Boot application.                                            |



**`DllCharacteristics`**

이미지의 DLL 특성을 의미합니다. 아래와 같은 값으로 정의됩니다.

| Value                                                      | Meaning                                                      |
| :--------------------------------------------------------- | :----------------------------------------------------------- |
| 0x0001                                                     | Reserved.                                                    |
| 0x0002                                                     | Reserved.                                                    |
| 0x0004                                                     | Reserved.                                                    |
| 0x0008                                                     | Reserved.                                                    |
| **IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE**0x0040)           | The DLL can be relocated at load time.                       |
| **IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY**(0x0080        | Code integrity checks are forced. If you set this flag and a section contains only uninitialized data, set the **PointerToRawData** member of [IMAGE_SECTION_HEADER](https://docs.microsoft.com/windows/desktop/api/winnt/ns-winnt-image_section_header) for that section to zero; otherwise, the image will fail to load because the digital signature cannot be verified. |
| **IMAGE_DLLCHARACTERISTICS_NX_COMPAT**(0x0100)             | The image is compatible with data execution prevention (DEP). |
| **IMAGE_DLLCHARACTERISTICS_NO_ISOLATION**(0x0200)          | The image is isolation aware, but should not be isolated.    |
| **IMAGE_DLLCHARACTERISTICS_NO_SEH**(0x0400)                | The image does not use structured exception handling (SEH). No handlers can be called in this image. |
| **IMAGE_DLLCHARACTERISTICS_NO_BIND**(0x0800)               | Do not bind the image.                                       |
| 0x1000                                                     | Reserved.                                                    |
| **IMAGE_DLLCHARACTERISTICS_WDM_DRIVER**(0x2000)            | A WDM driver.                                                |
| 0x4000                                                     | Reserved.                                                    |
| **IMAGE_DLLCHARACTERISTICS_TERMINAL_SERVER_AWARE**(0x8000) | The image is terminal server aware.                          |



**`SizeOfStackReserver`**

스택에 예약 할 바이트 수를 의미합니다. 로드 시 `SizeOfStackCommit` 멤버가 지정한 메모리만 커밋됩니다. 나머지는 예약 크기에 도달 할 때까지 한 번에 한 페이지 씩 사용할 수 있습니다.

**`SizeOfStackCommit`**

스택에 커밋 할 바이트 수입니다.

**`SizeOfHeapReserve`**

로컬 힙에 예약 할 바이트 수를 의미합니다. 마찬가지로 `SizeOfHeapCommit` 멤버가 지정한 메모리만 커밋됩니다.

**`SizeOfHeapCommit`**

힙에 커밋 할 바이트 수입니다.

**`LoaderFlags`**

사용되지 않습니다.

**`NumberOfRvaAndSizes`**

`OptionalHeader`의 나머지 디렉토리 항목(ex Export, Import, Resource 등)들의 수를 의미합니다. 

**`DataDirectory`**

데이터 디렉토리의 첫 번째 `IMAGE_DATA_DIRECTORY` 구조체에 대한 포인터입니다.