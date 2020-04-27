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

`Signature`

PE 이미지를 의미하는 식별 값입니다. 해당 바이트는 `PE\0\0(0x50450000)` 값을 가집니다.

`FileHeader`

파일의 헤더를 의미하는 `IMAGE_FILE_HEADER` 구조체입니다.

`OptionalHeader`

마찬가지로 파일 헤더지만 좀 더 세분화 된 내용들을 의미하는 멤버로 이루어진 `IMAGE_OPTIONAL_HEADER` 구조체입니다.


## [0x03] IMAGE_FILE_HEADER

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

`Machine`

컴퓨터의 아키텍처 유형을 의미합니다. 해당 멤버는 아래와 같은 값을 가질 수 있습니다.

- IMAGE_FILE_MACHINE_I386  (0x014C) ; x86
- IMAGE_FILE_MACHINE_IA64  (0x0200) ; Intel Itanium
- IMAGE_FILE_MACHINE_AMD64 (0x8664) ; x64


