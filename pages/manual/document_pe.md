---
title: PE Header inside
keywords: documentation, Windows, PE
date: 2020-04-27
tags: [Windows, Reversing]
summary: "PE 헤더 구조"
sidebar: manual_sidebar
permalink: document_pe.html
folder: manual

---

## [0x00] IMAGE_DOS_HEADER
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


## [0x01] IMAGE_NT_HEADERS

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

- **`Signature`**

  PE 이미지를 의미하는 식별 값입니다. 해당 바이트는 `PE\0\0(0x50450000)` 값을 가집니다.

- **`FileHeader`**

  파일의 헤더를 의미하는 `IMAGE_FILE_HEADER` 구조체입니다.

- **`OptionalHeader`**

  마찬가지로 파일 헤더지만 좀 더 세분화 된 내용들을 의미하는 멤버로 이루어진 `IMAGE_OPTIONAL_HEADER` 구조체입니다.

## [0x02] IMAGE_FILE_HEADER

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



- **`Machine`**

  컴퓨터의 아키텍처 유형을 의미합니다. 해당 멤버는 아래와 같은 값을 가질 수 있습니다.

  - `IMAGE_FILE_MACHINE_I386`  (0x014C) ; x86
  - `IMAGE_FILE_MACHINE_IA64`  (0x0200) ; Intel Itanium
  - `IMAGE_FILE_MACHINE_AMD64` (0x8664) ; x64



- **`NumberOfSections`**

  섹션의 수를 의미합니다. Windows 로더는 섹션의 수를 96개로 제한하고 있습니다.



- **`TimeDateStamp`**

  링커가 이미지를 생성한 날짜와 시간을 나타내며, 하위 32비트의 타임 스탬프로 구성됩니다.



- **`PointerToSymbolTable`**

  바이트 단위로 이루어진 심볼 테이블의 오프셋입니다.



- **`NumberOfSymbols`**

  심볼 테이블 내 심볼의 수 입니다.



- **`SizeOfOptionalHeader`**

  `OptionalHEader`의 크기입니다. 오브젝트 파일의 경우 반드시 이 값은 0 이어야 합니다.



- **`Characteristics`**

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



## [0x03] IMAGE_OPTIONAL_HEADER

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



- **`Magic`**

  이미지 파일의 상태를 의미합니다. 아래의 값을 가질 수 있습니다.

  - `IMAGE_NT_OPTIONAL_HDR32_MAGIC`(0x010B)
    - 실행 가능한 32-bit 애플리케이션
  - `IMAGE_NT_OPTIONAL_HDR64_MAGIC`(0x020B)
    - 실행 가능한 64-bit 애플리케이션
  - `IMAGE_ROM_OPTIONAL_HDR_MAGIC`(0x0107)
    - ROM 이미지 파일



- **`MajorLinkerVersion`**

  링커의 메이저 버전 숫자를 의미합니다.



- **`MinorLinkerVersion`**

  링커의 마이너 버전 숫자를 의미합니다.



- **`SizeOfCode`**

  코드 섹션의 크기를 의미하거나 코드 섹션이 여러 개인 경우 모든 코드 섹션의 합을 의미합니다.



- **`SizeOfInitializedData`**

  초기화 된 데이터 섹션의 크기 또는 여러 개인 경우 모든 초기화 된 데이터 섹션의 합을 의미합니다.



- **`SizeOfUninitializedData`**

  초기화 되지 않은 데이터 섹션의 크기 또는 여러 개인 경우 모든 초기화 되지 않은 데이터 섹션의 합을 의미합니다.



- **`AddressOfEntryPoint`**

  이미지 베이스 기준으로 진입점 함수에 대한 포인터를 의미합니다. 



- **`BaseOfCode`**

  이미지 베이스 기준으로 코드 섹션의 시작에 대한 포인터를 의미합니다.



- **`BaseOfData`**

  이미지 베이스 기준으로 데이터 섹션의 시작에 대한 포인터를 의미합니다.



- **`ImageBase`**

  이미지가 메모리에 로드 될 때 첫 바이트의 주소를 의미합니다.



- **`SectionAlignment`**

  메모리에 로드 되는 각 섹션의 최소 할당 단위를 의미합니다. 기본 값은 페이지 크기로 0x1000 을 가지며 이 값은 `FileAlignment` 멤버보다 크거나 같아야 합니다.



- **`FileAlignment`** 

  각 섹션 로우 데이터의 최소 할당 단위를 의미합니다. 기본 값은 0x200을 가집니다. `SectionAlignment` 멤버가 페이지 크기보다 작은 경우, `SectionAlignment` 값과 같아야 합니다.

**메이저 버전과 마이너 버전은 생략합니다.**



- **`SizeOfImage`**

  모든 헤더를 포함한 이미지의 크기를 의미합니다. `SectionAlignment`의 배수 여야합니다.



- **`SizeOfHeaders`**

  헤더들 크기의 합입니다. `FileAlignment` 멤버의 값의 배수로 반올림됩니다.



- **`Checksum`**

  이미지 파일의 체크섬 값입니다. 유효성 검사에 사용됩니다.



- **`Subsystem`**

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



- **`DllCharacteristics`**

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



- **`SizeOfStackReserver`**

  스택에 예약 할 바이트 수를 의미합니다. 로드 시 `SizeOfStackCommit` 멤버가 지정한 메모리만 커밋됩니다. 나머지는 예약 크기에 도달 할 때까지 한 번에 한 페이지 씩 사용할 수 있습니다.



- **`SizeOfStackCommit`**

  스택에 커밋 할 바이트 수입니다.



- **`SizeOfHeapReserve`**

  로컬 힙에 예약 할 바이트 수를 의미합니다. 마찬가지로 `SizeOfHeapCommit` 멤버가 지정한 메모리만 커밋됩니다.



- **`SizeOfHeapCommit`**

  힙에 커밋 할 바이트 수입니다.



- **`LoaderFlags`**

  사용되지 않습니다.



- **`NumberOfRvaAndSizes`**

  `OptionalHeader`의 나머지 디렉토리 항목(ex Export, Import, Resource 등)들의 수를 의미합니다. 



- **`DataDirectory`**

  데이터 디렉토리의 첫 번째 `IMAGE_DATA_DIRECTORY` 구조체에 대한 포인터입니다.



## [0x04] IMAGE_DATA_DIRECTORY

`ntimagebase.h` 내 존재합니다.

```c++
typedef struct _IMAGE_DATA_DIRECTORY {
  DWORD VirtualAddress;
  DWORD Size;
} IMAGE_DATA_DIRECTORY, *PIMAGE_DATA_DIRECTORY;
```



- **`VirtualAddress`**

  테이블의 상대 가상 주소를 의미합니다.



- **`Size`**

  테이블의 사이즈를 의미합니다.

데이터 디렉토리 내 항목별 오프셋은 `OptionalHeader` 위치로부터 다음과 같은 오프셋으로 이루어져 있습니다.

| Offset (PE/PE32+) | Description                                       |
| :---------------- | :------------------------------------------------ |
| 0x60/0x70         | Export table address and size                     |
| 0x68/0x78         | Import table address and size                     |
| 0x70/0x80         | Resource table address and size                   |
| 0x78/0x88         | Exception table address and size                  |
| 0x80/0x90         | Certificate table address and size                |
| 0x88/0x98         | Base relocation table address and size            |
| 0x90/0xA0         | Debugging information starting address and size   |
| 0x98/0xA8         | Architecture-specific data address and size       |
| 0xA0/0xB0         | Global pointer register relative virtual address  |
| 0xA8/0xB8         | Thread local storage (TLS) table address and size |
| 0xB0/0xC0         | Load configuration table address and size         |
| 0xB8/0xC8         | Bound import table address and size               |
| 0xC0/0xD0         | Import address table address and size             |
| 0xC8/0xD8         | Delay import descriptor address and size          |
| 0xD0/0xE0         | The CLR header address and size                   |
| 0xD8/0xE8         | Reserved                                          |

각 항목별 정의는 아래와 같습니다. `DataDirectory[n]` 형식과 같이 배열 형태로 존재합니다.

```c++
// Directory Entries

#define IMAGE_DIRECTORY_ENTRY_EXPORT          0   // Export Directory
#define IMAGE_DIRECTORY_ENTRY_IMPORT          1   // Import Directory
#define IMAGE_DIRECTORY_ENTRY_RESOURCE        2   // Resource Directory
#define IMAGE_DIRECTORY_ENTRY_EXCEPTION       3   // Exception Directory
#define IMAGE_DIRECTORY_ENTRY_SECURITY        4   // Security Directory
#define IMAGE_DIRECTORY_ENTRY_BASERELOC       5   // Base Relocation Table
#define IMAGE_DIRECTORY_ENTRY_DEBUG           6   // Debug Directory
//      IMAGE_DIRECTORY_ENTRY_COPYRIGHT       7   // (X86 usage)
#define IMAGE_DIRECTORY_ENTRY_ARCHITECTURE    7   // Architecture Specific Data
#define IMAGE_DIRECTORY_ENTRY_GLOBALPTR       8   // RVA of GP
#define IMAGE_DIRECTORY_ENTRY_TLS             9   // TLS Directory
#define IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG    10   // Load Configuration Directory
#define IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT   11   // Bound Import Directory in headers
#define IMAGE_DIRECTORY_ENTRY_IAT            12   // Import Address Table
#define IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT   13   // Delay Load Import Descriptors
#define IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR 14   // COM Runtime descriptor
```

몇 가지 중요 항목들에 대한 자세한 내용을 알아보겠습니다.

### [-] IMAGE_EXPORT_DIRECTORY

주로 `Export Address Table`이라고도 부르는 Export 함수에 접근하기 위해 먼저 접근해야 하는 디렉토리입니다.

```c++
typedef struct _IMAGE_EXPORT_DIRECTORY {
    ULONG   Characteristics;
    ULONG   TimeDateStamp;
    USHORT  MajorVersion;
    USHORT  MinorVersion;
    ULONG   Name;
    ULONG   Base;
    ULONG   NumberOfFunctions;
    ULONG   NumberOfNames;
    ULONG   AddressOfFunctions;     // RVA from base of image
    ULONG   AddressOfNames;         // RVA from base of image
    ULONG   AddressOfNameOrdinals;  // RVA from base of image
} IMAGE_EXPORT_DIRECTORY, *PIMAGE_EXPORT_DIRECTORY;
```

- **`Name`**

  해당 라이브러리의 이름이 저장되어 있는 `RVA` 값을 의미합니다.

- **`Base`**

  `Ordinal`, 서수의 시작 값을 의미합니다. 0인 경우 0부터 서수가 시작됩니다. 이 값은 고정적이지 않습니다. 라이브러리마다 다른 값을 가지고 있습니다.

- **`NumberOfFunctions`**

  Export 하는 함수들의 수를 의미합니다.

- **`NumberOfNames`**

  Export 하는 함수들의 이름 수를 의미합니다. 대부분 `NumberOfFunctions`와 동일하지만 그렇지 않은 경우도 존재합니다.

- **`AddressOfFunctions`**

  Export하는 첫 번째 함수의 오프셋을 가지고 있는 포인터의 RVA 값을 의미합니다. 즉 `ImageBase + *(ImageBase+AddressOfFunctions) == Export 첫 번째 함수 주소` 가 됩니다.

- **`AddressOfNames`**

  Export하는 첫 번째 함수 이름의 오프셋을 가지고 있는 포인터의 RVA 값을 의미합니다. 마찬가지로 `ImageBase+ *(ImageBase+AddressOfNames) == Export 첫 번째 함수 이름`이 됩니다.

- **`AddressOfNameOrdinals`**

  Name Ordinal에 대한 포인터입니다.

{%include tip.html content="Ordinal, 서수는 인덱스라고 생각하면 이해하기 쉽습니다. 배열로 이루어져 있기 때문이기도 하고 이 서수 값으로 함수를 호출할 수 있습니다." %}



### [-] IMAGE_IMPORT_DESCRIPTOR & IMPORT_BY_NAME

```c++
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        ULONG   Characteristics;            // 0 for terminating null import descriptor
        ULONG   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    ULONG   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    ULONG   ForwarderChain;                 // -1 if no forwarders
    ULONG   Name;
    ULONG   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;

typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;
```

- **`Characteristics`**

  특성을 지칭합니다. 다만 현재 정보가 존재하지 않습니다.

- **`OriginalFirstThunk`**

  `IMAGE_IMPORT_BY_NAME` 구조체 포인터의 값이 저장되어 있습니다. 이를 Import Name Table이라고 부르기도 합니다. `ImageBase + *(ImageBase + OriginalFirstThunk) == Import 첫 번째 함수 이름`이 됩니다.

- **`TimeDataStamp`**

  마찬가지로 타임 스탬프를 의미합니다.

- **`ForwarderChain`**

  Import 함수 목록에서 첫 번째 forwarder의 32비트 인덱스를 의미합니다.

- **`Name`**

  Export 하는 라이브러리(Import 되는)의 이름이 저장되는 주소의 RVA 값입니다.

- **`FirstThunk`**

  흔히 알고 있는 `IAT`를 의미합니다. 



## [0x05] IMAGE_SECTION_HEADER

```c++
#define IMAGE_SIZEOF_SHORT_NAME              8

typedef struct _IMAGE_SECTION_HEADER {
    UCHAR   Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            ULONG   PhysicalAddress;
            ULONG   VirtualSize;
    } Misc;
    ULONG   VirtualAddress;
    ULONG   SizeOfRawData;
    ULONG   PointerToRawData;
    ULONG   PointerToRelocations;
    ULONG   PointerToLinenumbers;
    USHORT  NumberOfRelocations;
    USHORT  NumberOfLinenumbers;
    ULONG   Characteristics;
} IMAGE_SECTION_HEADER, *PIMAGE_SECTION_HEADER;
```

- **`Name`**

  섹션의 이름을 의미합니다.(.text, .data ...)

- **`Misc`**

  PhysicalAddress와 VirtualSize로 이루어진 공용체입니다. 실제 자주 사용하는 멤버는 VirtualSize로 `SizeOfRawData`보다 큰 경우 0으로 채워집니다. 말 그대로 메모리에 할당되는 섹션의 크기를 의미합니다.

- **`VirtualAddress`**

  메모리 내 섹션 시작 주소의 RVA 값을 의미합니다.

- **`SizeOfRawData`**

  파일 내에서 해당 섹션의 크기를 의미합니다. `VirtualSize`의 경우 `SectionAlignment`를 최소 단위로 하기 때문에 해당 멤버와 차이가 나게 됩니다. 마찬가지로 해당 멤버는 `FileAlignment` 값의 배수가 됩니다.

- **`PointerToRawData`**

  파일 내에서 해당 섹션 시작 주소의 RVA 값을 의미합니다. 역시 `FileAlignment` 값의 배수가 됩니다.

- **`PointerToRelocations`**

  섹션의 재배치 엔트리의 시작 부분에 대한 포인터 입니다. 재배치가 필요하지 않으면 0입니다.

- **`PointerToLineNumber`**

  섹션의 줄 번호 엔트리의 시작 부분에 대한 포인터 입니다. COFF 줄 번호가 존재하지 않으면 0입니다.

- **`NumberOfRelocations`**

  섹션의 재배치 엔트리의 수입니다. 실행 가능 이미지의 경우 0입니다.

- **`NumberOfLineNumbers`**

  섹션의 줄 번호 엔트리의 수입니다. 실행 가능 이미지의 경우 0입니다.

- **`Characteristics`**

  이미지의 특성에 대한 내용입니다. 아래와 같은 값을 가질 수 있습니다.

  | Flag                                                    | Meaning                                                      |
  | :------------------------------------------------------ | :----------------------------------------------------------- |
  | 0x00000000                                              | Reserved.                                                    |
  | 0x00000001                                              | Reserved.                                                    |
  | 0x00000002                                              | Reserved.                                                    |
  | 0x00000004                                              | Reserved.                                                    |
  | **IMAGE_SCN_TYPE_NO_PAD** <br />(0x00000008)            | The section should not be padded to the next boundary. This flag is obsolete and is replaced by IMAGE_SCN_ALIGN_1BYTES. |
  | 0x00000010                                              | Reserved.                                                    |
  | **IMAGE_SCN_CNT_CODE** <br />(0x00000020)               | The section contains executable code.                        |
  | **IMAGE_SCN_CNT_INITIALIZED_DATA** <br />(0x00000040)   | The section contains initialized data.                       |
  | **IMAGE_SCN_CNT_UNINITIALIZED_DATA** <br />(0x00000080) | The section contains uninitialized data.                     |
  | **IMAGE_SCN_LNK_OTHER** <br />(0x00000100)              | Reserved.                                                    |
  | **IMAGE_SCN_LNK_INFO** <br />(0x00000200)               | The section contains comments or other information. This is valid only for object files. |
  | 0x00000400                                              | Reserved.                                                    |
  | **IMAGE_SCN_LNK_REMOVE**<br />(0x00000800)              | The section will not become part of the image. This is valid only for object files. |
  | **IMAGE_SCN_LNK_COMDAT** <br />(0x00001000)             | The section contains COMDAT data. This is valid only for object files. |
  | 0x00002000                                              | Reserved.                                                    |
  | **IMAGE_SCN_NO_DEFER_SPEC_EXC** <br />(0x00004000)      | Reset speculative exceptions handling bits in the TLB entries for this section. |
  | **IMAGE_SCN_GPREL** <br />(0x00008000)                  | The section contains data referenced through the global pointer. |
  | 0x00010000                                              | Reserved.                                                    |
  | **IMAGE_SCN_MEM_PURGEABLE** <br />(0x00020000)          | Reserved.                                                    |
  | **IMAGE_SCN_MEM_LOCKED** <br />(0x00040000)             | Reserved.                                                    |
  | **IMAGE_SCN_MEM_PRELOAD** <br />(0x00080000)            | Reserved.                                                    |
  | **IMAGE_SCN_ALIGN_1BYTES** <br />(0x00100000)           | Align data on a 1-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_ALIGN_2BYTES** <br />(0x00200000)           | Align data on a 2-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_ALIGN_4BYTES** <br />(0x00300000)           | Align data on a 4-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_ALIGN_8BYTES** <br />(0x00400000)           | Align data on a 8-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_ALIGN_16BYTES** <br />(0x00500000)          | Align data on a 16-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_ALIGN_32BYTES** <br />(0x00600000)          | Align data on a 32-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_ALIGN_64BYTES** <br />(0x00700000)          | Align data on a 64-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_ALIGN_128BYTES** <br />(0x00800000)         | Align data on a 128-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_ALIGN_256BYTES** <br />(0x00900000)         | Align data on a 256-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_ALIGN_512BYTES** <br />(0x00A00000)         | Align data on a 512-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_ALIGN_1024BYTES** <br />(0x00B00000)        | Align data on a 1024-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_ALIGN_2048BYTES** <br />(0x00C00000)        | Align data on a 2048-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_ALIGN_4096BYTES** <br />(0x00D00000)        | Align data on a 4096-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_ALIGN_8192BYTES** <br />(0x00E00000)        | Align data on a 8192-byte boundary. This is valid only for object files. |
  | **IMAGE_SCN_LNK_NRELOC_OVFL** (0x01000000)              | The section contains extended relocations. The count of relocations for the section exceeds the 16 bits that is reserved for it in the section header. If the **NumberOfRelocations** field in the section header is 0xffff, the actual relocation count is stored in the **VirtualAddress** field of the first relocation. It is an error if IMAGE_SCN_LNK_NRELOC_OVFL is set and there are fewer than 0xffff relocations in the section. |
  | **IMAGE_SCN_MEM_DISCARDABLE** <br />(0x02000000)        | The section can be discarded as needed.                      |
  | **IMAGE_SCN_MEM_NOT_CACHED** <br />(0x04000000)         | The section cannot be cached.                                |
  | **IMAGE_SCN_MEM_NOT_PAGED** <br />(0x08000000)          | The section cannot be paged.                                 |
  | **IMAGE_SCN_MEM_SHARED** <br />(0x10000000)             | The section can be shared in memory.                         |
  | **IMAGE_SCN_MEM_EXECUTE** <br />(0x20000000)            | The section can be executed as code.                         |
  | **IMAGE_SCN_MEM_READ** <br />(0x40000000)               | The section can be read.                                     |
  | **IMAGE_SCN_MEM_WRITE** <br />(0x80000000)              | The section can be written to.                               |



## [0x06] Conclusion

이전 블로그에서 정리한 내용에 약간 좀 더 설명을 보태 작성하였습니다. 실제 이런 PE를 활용한 각종 내용들은 여기 PE Header Inside 섹션 내에 정리해보겠습니다.



## [0x07] Reference

1. [https://docs.microsoft.com/en-us/windows/win32/debug/pe-format](https://docs.microsoft.com/en-us/windows/win32/debug/pe-format)