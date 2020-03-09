---
title: Preferences
keywords: documentation, Setup, technique, tools
date: 2020-03-09
tags: [Windows, Reversing, Dev]
summary: "초기 환경설정"
sidebar: antikernel_sidebar
permalink: antikernel_preferences.html
folder: antikernel
---

## [0x00] Overview

제가 사용하는 환경설정에 관한내용입니다. 주로 가상머신에 관한 설정으로 이루어져 있습니다. 



## [0x01] Install WinDbg

현재 WinDbg Preview가 있으나 기존의 WinDbg를 사용하겠습니다. 아래의 url에서 Windows 10 SDK 설치를 통해 WinDbg를 설치할 수 있습니다.

Link: <a href="https://docs.microsoft.com/ko-kr/windows-hardware/drivers/debugger/debugger-download-tools">Windbg Install</a>



## [0x02] Install VirtualKD on Windows

`VirtualKD` 를 이용하여 커널 디버깅 환경을 구축합니다.

1. <a href="https://sysprogs.com/legacy/virtualkd">VirtualKD</a>(https://sysprogs.com/legacy/virtualkd) 에서 다운로드 할 수 있습니다.
2. 압축을 해제하면 아래와 같은 목록을 확인할 수 있습니다.<img src="https://github.com/Shh0ya/shh0ya.github.io/blob/master/rsrc/antikernel/pre_00.png?raw=true">

3. `target` 폴더를 GuestOS로 복사하여 `vminstall.exe`를 실행하고 설치합니다.

   <img src="https://github.com/Shh0ya/shh0ya.github.io/blob/master/rsrc/antikernel/pre_01.png?raw=true">

4. 설치 후 재부팅을 하기전에 **HostOS**에서 `vmmon64.exe`를 실행합니다. 실행한 상태에서 **GuestOS**를 재부팅하고 `F8` 키를 눌러 아래와 같이 메뉴를 선택합니다.<img src="https://github.com/Shh0ya/shh0ya.github.io/blob/master/rsrc/antikernel/pre_02.png?raw=true">

   <img src="https://github.com/Shh0ya/shh0ya.github.io/blob/master/rsrc/antikernel/pre_03.png?raw=true">

5. 커널 디버깅을 하기 위한 환경설정이 완료되었습니다. 아래와 같이 자동으로 WinDbg가 시작됩니다. 만약 실행되지 않는 경우, `vmmon`에서 `Debugger path...` 버튼을 클릭하여 `windbg.exe` 경로를 지정해주시길 바랍니다.<img src="https://github.com/Shh0ya/shh0ya.github.io/blob/master/rsrc/antikernel/pre_04.png?raw=true">



## [0x03] Conclusion

위와 같이 환경을 설정하고, 이를 사용하는 것은 극 후반의 일입니다. 기본적인 windbg 명령어를 습득해두는 것이 도움이 될 것입니다. 다음 챕터에서는 안티 커널 디버깅의 목적에 대한 간략한 제 생각에 대한 글입니다.
