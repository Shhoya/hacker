---
title: SMBGhost(CVE-2020-0796) Introduction
keywords: documentation, Vulnerability, SMB, CVE 
date: 2020-03-26
summary: "SMBGhost(CVE-2020-0796) 소개"
sidebar: vuln_sidebar
permalink: vuln_smb_introduction.html
folder: vuln

---

## [0x00] Introduction

SMBv3 의 취약점인 "SMBGhost"는 최신 버전(SMB 3.1.1)을 사용하여 네트워크 공유 시 복제 및 확산이 가능한 "Wormable" 취약점입니다.(McAfee)

"SMB"란 서버 메시지 블록(Server Message Block)으로 파일이나 디렉터리 및 주변 장치들을 공유할 때 사용하는 프로토콜입니다. 쉽게 윈도우 공유 폴더를 생각할 수 있습니다.

해당 취약점이 발생하는 원인은 조작된 SMB 헤더와 커널에서 사용하는 srv2.sys 드라이버 내 `Srv2DecompressData` 함수에서 정수 오버플로로 인해 발생합니다. 이 때 사용되는 헤더가 `SMB2_COMPRESSION_TRANSFORM_HEADER` 입니다.

`MS-SMB2` 에 있는 가이드에 따르면 아래와 같이 정의되어 있습니다.(<a href="https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/1d435f21-9a21-4f4c-828e-624a176cf2a0">링크</a>)

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_00.png?raw=true">

여기서 주의깊게 봐야하는 필드는 `OriginalCompressedSegmentSize`, `Offset/Length` 필드입니다. 
여러가지의 분석 문서를 확인하였고, 이를 토대로 직접 분석하였습니다.

현재 환경이 취약한 환경인지 확인하기 위해 총 2가지의 스캐너를 이용하였습니다.

- https://github.com/ioncodes/SMBGhost
- https://github.com/cve-2020-0796/cve-2020-0796

위의 스캐너를 통해 확인한 결과는 아래와 같습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_01.png?raw=true">

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/smbghost/smb_02.png?raw=true">

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
  - Packet Analyzer : Wireshark

{% include note.html content="추가 도구를 사용할 수 있습니다." %}



## [0x02] Feedback

수정해야 할 내용이 있거나 잘못된 내용이 있다면 상단에 `Feedback`을 이용하여 메일을 주시면 감사하겠습니다.