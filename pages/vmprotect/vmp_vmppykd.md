---
title: VMP kernel driver analysis using pykd
keywords: documentation, technique, debugging
date: 2020-05-06
tags: [Windows, Reversing, Dev]
summary: "pykd를 이용한 패킹 드라이버 분석"
sidebar: vmp_sidebar
permalink: vmp_vmppykd.html
folder: vmprotect
---

## [0x00] Overview

악성코드, 게임 치트, 안티 치트 솔루션 등 커널 드라이버를 사용하는 제품이나 도구가 많이 있습니다. 트레이싱을 하기 위해서는 간결하고 적절한 해결책이 필요합니다. 저는 이를 해결하기 위해 windbg 플러그인 중 pykd 를 이용하였습니다. windbg와 파이썬을 함께 사용할 수 있는 매우 유용한 플러그인입니다.

## [0x01] Requirements

먼저 [여기](https://shhoya.github.io/vmp_vmpanalysis.html) 에서 선행학습을 통해 간략한 코드 가상화의 내용을 숙지해야 합니다. 아래와 같이 정의한 용어들을 확인하십시오.

- `vmmacro` : 여러 개의 매크로 함수가 존재, 특정 패턴으로 이루어져 있음
- `vmmacro_handler` : vmmacro를 호출하는 `push` 와 `call`명령어 세트
- `vmtable` : vmmacro의 집합

### [-] Virtual Machine

가상머신에 대한 정보와 해당 머신에서 사용하는 도구 목록입니다.

- Guest OS : Windows 10, 1903(OS Build 18362.30)



### [-] Host Machine

실습을 진행하는 호스트 OS의 정보 및 도구 목록입니다.

- Host OS : Windows 10 x64, 1909(OS Build 18363.720)
- Tools
  - Debugger & Disassembler : Windbg, IDA Pro
  - Visual Studio 2019 Community

{% include note.html content="추가 도구를 사용할 수 있습니다." %}



## [0x02] Windbg plugins

우선 실제 실습을 진행하기 앞서 windbg 에서 사용 가능한 플러그인 `dbgkit`와 `pykd`를 설치하는 과정과 사용 방법에 대해 설명하겠습니다.

### [-] DbgKit

**작성 중입니다.**



## [0x03] Conclusion

