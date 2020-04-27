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

