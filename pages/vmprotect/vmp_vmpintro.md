---
title: VMProtect Introduction
keywords: documentation, technique, debugging
date: 2020-03-10
tags: [Windows, Reversing, Dev]
summary: "VMP Packer 개요"
sidebar: vmp_sidebar
permalink: vmp_vmpintro.html
folder: vmprotect
---

## [0x00] Overview

결론부터 미리 말씀드리자면 제가 하는 분석 및 언패킹 내용은 완벽하지 않습니다. 다만 분석에 어느정도 도움되는 수준이라고 말할 수 있을 것 같습니다.

VMP뿐 아니라, Themida와 같은 상용 프로텍터들은 대부분 내용이 비슷했습니다. 어쨋든 목표는 VMP로 패킹된 파일에 대한 분석을 어떻게 할 수 있는가 입니다.

아래와 같은 내용으로 구성되어 있습니다.

- VMProtect Anti Debugging : VMP 에서 사용하는 안티 디버깅 기법에 대한 내용과 관련 플러그인 내용입니다.
- VMP Analysis : VMP로 패킹되어 있는 파일에 대한 분석 내용입니다.



## [0x01] Requirements

실습 환경은 호스트 환경에서 진행됩니다.

- Windows 10 x64, 1803(OS Build 17134.1304)
- Tools
  - x64dbg
  - IDA Pro
  - VMProtect Ultimate v3.2.0



## [0x02] Feedback

수정해야 할 내용이나 잘못된 내용이 있다면 상단에 `Feedback`을 이용하여 메일 주시면 감사하겠습니다.

