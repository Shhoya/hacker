---
title: Capcom Driver Exploit Introduction
keywords: documentation, Vulnerability
date: 2020-04-14
summary: "Capcom 드라이버 취약점 분석"
sidebar: vuln_sidebar
permalink: vuln_capcom_introduction.html
folder: vuln

---

## [0x00] Introduction

약 3년 전에 해당 취약점은 공개되었으며 Windows Defender에서는 해당 드라이버 파일을 악성으로 분류합니다. 예상하기로는 캡콤 측에서 해당 제보를 취약점으로 받아들이지 않았고 이로 인해 CVE 할당도 되지 않은 것으로 보입니다. 하지만 꽤나 취약하며 이로 인해 보안 솔루션들의 커널 드라이버가 무력화하거나 서명 된 드라이버로 악용될 수 있었습니다. 

**해당 챕터에서 샘플 드라이버는 악성으로 분류되기 때문에 제공하지 않습니다.**



## [0x01] Requirements

취약점에 대한 분석을 위해 아래와 같은 환경을 구축하여 분석을 진행하였습니다.

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



## [0x02] Feedback

수정해야 할 내용이 있거나 잘못된 내용이 있다면 상단에 `Feedback`을 이용하여 메일을 주시면 감사하겠습니다.