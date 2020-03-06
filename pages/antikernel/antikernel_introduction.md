---
title: Introduction
sidebar: antikernel_sidebar
permalink: antikernel_introduction.html
folder: antikernel
---

## [0x00] Overview

해당 챕터에서는 커널 디버깅을 탐지하는 기법들과 이를 우회하는 방법에 관한 내용이 포함되어 있습니다.
기본적으로 유저모드 디버깅에 대한 탐지 기법, 우회 기법을 알고 있다면 좀 더 쉽게 이해할 수 있습니다.

아래와 같은 챕터로 이루어져 있습니다.

- <a href="https://shhoya.github.io/antikernel_preferences.html">Preferences</a> : 간략한 가상머신 설정에 대한 설명입니다. `VirtualKD`를 이용하여 커널 디버깅을 준비합니다.
- <a href="https://shhoya.github.io/antikernel_antidebugging.html">Anti Debugging</a> : 실제 챕터에 들어가기 전에 안티 커널 디버깅에 대한 요약입니다.
- <a href="https://shhoya.github.io/antikernel_processprotect.html">Process Protect(1)</a> : 커널 드라이버에서 프로세스 보호를 어떤 식으로 하는지에 대한 내용입니다.
- <a href="https://shhoya.github.io/antikernel_processprotect2.html">Process Protect(2)</a> : 커널 드라이버에서 프로세스 보호를 어떤 식으로 하는지에 대한 내용입니다.
- <a href="https://shhoya.github.io/antikernel_antidebugexam.html">Anti Kernel Debugging</a> : 커널 드라이버를 이용한 안티 디버깅 기법에 대한 내용입니다.
- Kernel Debugging : 커널 디버깅을 OS에서 어떻게 처리하는지에 관한 내용입니다.
- Code Sign : 코드 무결성(CI)에 관한 내용입니다.
- Bypass : 커널 디버깅 중이라는 사실을 숨긴 채 디버깅을 하는 방법에 관한 내용입니다.

## [0x01] Requirements

제가 실습한 환경 및 도구에 대한 내용은 다음과 같습니다.

### [-] Virtual Machine

가상머신에 대한 정보와 해당 머신에서 사용할 도구 목록입니다.

- Guest OS : Windows 10 x64, 1809(OS Build 17763.973), Virtual Machine

- Tools

  - VirtualKD(client)
  - OSRLoader(Driver Loader)
  - WKE( or PCHunter)
- DbgView
  
  

### [-] Host OS

실제 실습을 진행하는 운영체제와 사용할 도구 목록입니다.

- Host OS : Windows 10 x64, 1803(OS Build 17134.1304) 

  {% include  warning.html content="GuestOS 보다 버전이 낮습니다. 이를 따를 필요는 없습니다. 그저 업데이트를 안 했을 뿐입니다. 해당 환경 및 도구가 실제 머신임을 확인하시길 바랍니다." %}

- Tools

  - Debugger & Disassembler : Windbg, x64dbg, IDA Pro 
  - Visual Studio 2019 Community(드라이버 개발 환경, WDM)

{% include  note.html content="해당 챕터가 완성될 때까지 추가 도구를 사용할 경우, 업데이트할 것입니다." %}



## [0x02] Feedback

수정해야 할 내용이 있거나 잘못된 내용이 있다면 상단에 `Feedback` 을 이용하여 메일을 주시면 감사하겠습니다.