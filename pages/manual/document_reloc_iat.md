---
title: Relocation & IAT
keywords: documentation, Windows, PE
date: 2020-12-31
tags: [Windows, Reversing]
summary: "PE 재배치와 IAT"
sidebar: manual_sidebar
permalink: document_reloc_iat.html
folder: manual

---

## [0x00] PE Relocation
기본적으로 Relocation Table 은 Data Directory 의 인덱스 6(상수 5)에 위치합니다.
```c++
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

해당 테이블의 목적은 재배치가 필요한 데이터를 표시하기 위함입니다. ASLR 이나 시스템 재시작 후에 변경되는 메모리 주소에 대한 범용성을 위함입니다.
임의로 만든 콘솔 프로그램 내 Relocation Table을 확인하면 아래와 같이 확인할 수 있습니다.

![reloc](https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/manual/rel_0.png?raw=true)

`IMAGE_BASE_RELOCATION` 이라는 구조체로 이루어져 있으며 아래와 같은 구조로 되어 있습니다.

```c++
typedef struct _IMAGE_BASE_RELOCATION
{
    DWORD VirtualAddress;
    DWORD SizeOfBlock;
    WORD TypeOffset[1];
}IMAGE_BASE_RELOCATION;
```

![reloc2](https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/manual/rel_1.png?raw=true)

위의 샘플 파일 기준으로 파일 오프셋 0x2800 내 Relocation Directory가 존재하며, Virtual Address 는 0x2000, SizeOfBlock 은 0x002C 입니다.
`Items` 필드는 Relocation이 필요한 데이터의 개수를 의미합니다.(개수를 구하는 내용은 잠시 후 얘기하겠습니다.)

TypeOffset의 경우 2byte 씩 0x0000 으로 끝나는 배열의 형태를 지니고 있습니다. 또한 다음과 같은 구조로 이해할 수 있습니다.

```c++
struct
{
    WORD Offset:12;
    WORD Type:4;
}TypeOffset;
```

상위 4bit 는 Type을 의미하며 나머지 12bit는 오프셋 정보를 담고 있습니다. 이러한 정보를 토대로 재배치가 필요한 데이터의 개수를 구할 수 있습니다.

총 Block의 사이즈에서 `IMAGE_BASE_RELOCATION` 사이즈만큼을 빼면 TypeOffset 만 사이즈만 남게되고 이를 `WORD` 사이즈로 나누면 재배치 필요 데이터 수를 구할 수 있습니다.

`Count = (0x2C(SizeOfBlock) - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD)`

위의 예제에서 첫 번째 TypeOffset 값은 `0xA1A0` 입니다. 상위 4bit가 Type이라고 했으니, `0xA` 가 타입이며 해당 의미는 헤더에 정의되어 있습니다.

```c++
#define IMAGE_REL_BASED_ABSOLUTE              0
#define IMAGE_REL_BASED_HIGH                  1
#define IMAGE_REL_BASED_LOW                   2
#define IMAGE_REL_BASED_HIGHLOW               3
#define IMAGE_REL_BASED_HIGHADJ               4
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_5    5
#define IMAGE_REL_BASED_RESERVED              6
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_7    7
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_8    8
#define IMAGE_REL_BASED_MACHINE_SPECIFIC_9    9
#define IMAGE_REL_BASED_DIR64                 10
```

`IMAGE_REL_BASED_DIR64(0xA)` 는 해당 데이터에 8바이트를 재배치 해야 한다는 의미입니다. 여기서 **재배치가 필요하다는 것은 특정 주소의 데이터가 실제 메모리 상의 주소를 고려하지 않은 메모리 주소가 고정되어 있다는 의미입니다.**

고정된 메모리 주소를 찾는 방법은 매우 쉽습니다. `IMAGE_BASE_RELOCATION.VirtualAddress` 와 `TypeOffset`의 Offset을 더 해주면 끝입니다. RVA 값이므로 파일 내에서 확인하기 위해 계산이 필요합니다.

- `Raw Offset = (0x2000 + (0xA1A0 & 0x0FFF)) - 0x2000(V.A in section header) + 0x1200(raw addr in Section header)`

위의 공식에 따르면 파일 내 오프셋은 0x13A0 입니다.

![reloc3](https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/manual/rel_2.png?raw=true)

실제로 해당 오프셋을 확인하면 이미지 베이스(0x0000000140000000) + 오프셋 0x17E8 값이 저장된 것을 확인할 수 있습니다. 메모리 상에서는 VA 값이기 때문에 0x21A0 오프셋에서 찾을 수 있습니다.

![reloc4](https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/manual/rel_3.png?raw=true)

실제 메모리 상에서 재배치된 모습을 확인할 수 있습니다.
그렇다면 실제로 재배치를 하려할 때, 여러 가지 수학적 공식을 사용할 수 있지만 가장 잘 알려진 방법은 Delta 값을 이용하는 것 입니다.

- `Delta = 메모리 상의 ImageBase - Raw 데이터 상의 ImageBase`  

이제 `Delta` 값과 고정 주소의 오프셋 값만 더 하면 끝입니다.

많은 `Manual Mapping` 에 대한 예제에서 재배치 부분을 Copy & Paste 하는 경향이 있습니다. 실제로 확인하면 다른 값이 재배치 데이터에 저장되는 것을 목격할 수 있습니다. 이러한 경우는 x64 프로세스에서 빈번히 발생하는 것으로 보입니다. 그럼에도 정상 실행이 가능합니다. 그 이유는 우리가 아주 큰 코드를 매핑할 일이 거의 없었기 때문입니다.

정상적으로 Relocation Table을 사용하고 이에 대한 호출이 필요하다면 분명 큰 오류가 발생할 것 입니다. 주의해야 합니다.

대부분의 예제는 4바이트 주소 값을 읽고 Delta와 더합니다.



## [0x01] Fix IAT

이미지(PE)를 로드할 때 Import Descriptor(IMAGE_IMPORT_DESCRIPTOR) 를 이용하여 해당하는 함수의 주소를 IAT에 적절하게 변경하여 사용합니다.
우리가 알아야 할 구조체는 세 가지 입니다.

```c++
typedef struct _IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD   Characteristics;            // 0 for terminating null import descriptor
        DWORD   OriginalFirstThunk;         // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD   TimeDateStamp;                  // 0 if not bound,
                                            // -1 if bound, and real date\time stamp
                                            //     in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                            // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD   ForwarderChain;                 // -1 if no forwarders
    DWORD   Name;
    DWORD   FirstThunk;                     // RVA to IAT (if bound this IAT has actual addresses)
} IMAGE_IMPORT_DESCRIPTOR;
typedef IMAGE_IMPORT_DESCRIPTOR UNALIGNED *PIMAGE_IMPORT_DESCRIPTOR;


typedef struct _IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
} IMAGE_IMPORT_BY_NAME, *PIMAGE_IMPORT_BY_NAME;

typedef struct _IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;  // PBYTE 
        ULONGLONG Function;         // PDWORD
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
} IMAGE_THUNK_DATA64;
typedef IMAGE_THUNK_DATA64 * PIMAGE_THUNK_DATA64;
```

각 필드에 대한 내용은 [여기](https://shhoya.github.io/document_pe.html#--image_import_descriptor--import_by_name) 에서 확인 가능합니다. 바로 IAT 수정 과정을 살펴보겠습니다.

먼저 아래와 같은 `Import Directory` 예제를 기준으로 확인하겠습니다.

![reloc5](https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/manual/rel_4.png?raw=true)

먼저 로더는 `OptionalHeader.DataDirectory[1]` 을 참조하여 `IMAGE_IMPORT_DESCRIPTOR` 구조를 찾습니다.

![reloc6](https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/manual/rel_5.png?raw=true)

번호 순서대로, `OriginalFirstThunk`, `TimeStamp`, `ForwarderChain`, `Name`, `FirstThunk` 입니다. `OriginalFirstThunk` 와 `FirstThunk` RVA 값을 따라가면 같은 데이터가 존재합니다. 말 그대로 `OriginalFirstThunk`는 IAT 수정 전의 원본 데이터를 의미하고, `FirstThunk` 는 수정 할 IAT를 의미합니다.

먼저 Import 할 외부 라이브러리를 로드해야 합니다. `Import Descriptor` 의 `Name` 멤버를 사용하여 구할 수 있습니다.
현재 `Name` 의 RVA 값은 0x2A30 입니다. 파일 내 오프셋으로 변환하면 0x1C30 이 됩니다.

![reloc7](https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/manual/rel_6.png?raw=true)

해당 이름을 가지고 `LoadLibraryA` 함수를 이용하여 라이브러리를 로드합니다. 이제 로드 된 모듈에서 어떤 함수를 사용하려하는지와 해당 함수의 주소를 알아내야 합니다. 
`OriginalFirstThunk` 의 RVA 값은 0x2890 입니다. 계산 시 0x1A90이 되며 아래와 같은 내용을 가지고 있습니다.

![reloc8](https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/manual/rel_7.png?raw=true)

각 데이터들은 `IMAGE_THUNK_DATA` 로 이루어져 있으며 x64 이기 때문에 8바이트로 이루어져 있습니다.
`IMAGE_THUNK_DATA` 내 멤버들을 확인하면 공용체로 각 데이터가 어떤 멤버를 의미하는지는 값을 통해서만 알아낼 수 있습니다.
예를 들어, 현재 0x2E68 이라는 값은 `AddressOfData` 멤버로 해당 RVA 값에는 `IMAGE_IMPORT_BY_NAME` 구조체의 데이터가 존재합니다.
실제로 확인해보면 아래와 같이 `IsDebuggerPresent` 함수를 사용하는 것을 알 수 있습니다.

![reloc9](https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/manual/rel_8.png?raw=true)

이를 구분하기 위해 MS에서는 몇 가지 매크로를 정의해두었습니다.

```c++
#define IMAGE_ORDINAL_FLAG64 0x8000000000000000
#define IMAGE_ORDINAL_FLAG32 0x80000000
#define IMAGE_ORDINAL64(Ordinal) (Ordinal & 0xffff)
#define IMAGE_ORDINAL32(Ordinal) (Ordinal & 0xffff)
#define IMAGE_SNAP_BY_ORDINAL64(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG64) != 0)
#define IMAGE_SNAP_BY_ORDINAL32(Ordinal) ((Ordinal & IMAGE_ORDINAL_FLAG32) != 0)
```

즉 로더는 `Original IAT(OriginalFirstThunk` 에 있는 데이터를 읽고 이 데이터가 서수(Ordinal) 인지, `IMAGE_IMPORT_BY_NAME` 에 대한 오프셋인지 구분합니다.
만약 서수인 경우, `GetProcAddress` 함수의 두 번째 파라미터로 `IMAGE_ORIDNAL64` 매크로를 이용하여 해당 함수를 Import 할 수 있게 됩니다.
마찬가지로 이름의 경우에도 같습니다.

이렇게 실제로 로드 된 모듈의 함수를 가져다 쓰기 위해 얻은 함수의 주소는 `IAT(FirstThunk)`에 기록 됩니다. 이는 실제로 로드된 프로세스에서 확인해보면 알 수 있습니다. 파일에서 확인한 것과 같이 다음과 같은 Import Descriptor를 지니고 있습니다.

```
ImageBase : 0x00007FF63EA20000
OriginalFirstThunk : 0x2890
TimeStamp : 0x0000
ForwarderChain : 0x0000
Name : 0x2A30
FirstThunk : 0x2000
```

아래는 `OriginalFirstThunk` 의 데이터 입니다. 파일과 동일합니다.

![reloc10](https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/manual/rel_9.png?raw=true)

다음은 `FirstThunk` 의 데이터 입니다. 실제로 Import 되는 함수의 주소들로 수정 된 것을 확인할 수 있습니다.

![reloc11](https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/manual/rel_10.png?raw=true)

## [0x02] Conclusion

현재 연구 중인 내용에 필요한 내용이라 정리해보았습니다. 위의 내용들을 명확히 이해하면 PE 커스텀 로더 개발이나 인젝션 기법 중 하나인 `Manual Mapping` 에도 활용이 가능합니다. 
