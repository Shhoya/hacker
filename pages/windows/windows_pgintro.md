---
title: PatchGuard Introduction
keywords: documentation, technique, reversing, kernel, windows
date: 2020-11-10
tags: [Windows, Reversing, Vulnerability, Kernel]
summary: "Windows KPP Introduction"
sidebar: windows_sidebar
permalink: windows_pgintro.html
folder: windows
---

## [0x00] Overview

공식적으로 `KPP(Kernel Patch Protection)` 라고 불리며, `PatchGuard` 라는 이름으로 잘 알려져 있습니다.

PG는 아래와 같은 데이터 및 구조체 등을 보호합니다.

- System Service Tables(SSDT, KeServiceDescriptorTable)
- Interrupt Descriptor Table(IDT)
- Global Descriptor Table(GDT)
- System Images(ntoskrnl.exe, ndis.sys, hal.dll...)
- Processor MSR(syscall)
- 허용되지 않는 커널 스택의 사용

조금은 오래 된 문서들과 몇 가지 오픈소스 라이브러리를 통해 PG에 대해 알아보겠습니다.

## [0x01] Why

패치가드에 대한 분석을 시작한 이유는 당연히 우회하기 위해서 입니다.
물론 이를 통해 악용이 아니라, 악용하는 사람들과 동등한 기술력을 지니기 위해서 입니다.

먼저 `SYSCALL` 후킹에 대해 알아보면, 현재 `ETW(Event Tracing for Windows)` 기능(추후 포스팅 예정)을 이용한 `InfinityHook` 라이브러리가 존재합니다. 매우 유용하게 사용했고 유저모드의 보안 무력화가 손 쉽게 가능합니다. 

하지만 이에 맞춰 보안 제품들(`Anti-Virus`,`Anti-Cheat`,`EDR` 등)은 커널 모드에서의 대응을 당연시 하고 있습니다.

간단한 예를 들어보겠습니다.
`NtQuerySystemInformation` 함수를 이용하여 로드되어 있는 모듈에 대해 조사하고 이를 차단하는 보안 제품이 있다고 가정해봅니다.

유저 레벨에서 동작한다면 크게 아래와 같은 과정으로 동작합니다.

- `ntdll!NtQuerySystemInformation` -> `SYSCALL` -> `nt!NtQuerySystemInformation`

이러한 과정에서 `SYSCALL` 후킹을 통해 간단히 우회가 가능합니다.

커널 레벨에서 동작한다면 아래와 같은 과정으로 동작합니다.

- `nt!NtQuerySystemInformation`

이러한 상황에서 전달되는 모듈의 정보를 변조하고자 후킹을 한다면 커널 레벨의 후킹이 필요합니다.(물론 내부적으로 `nt!ExpQuerySystemInformation` 등 있지만 결국은 커널 레벨 후킹)

바로 여기서 `KPP`라는 벽이 생겨버립니다. `ntoskrnl.exe` 는 PG가 보호하는 영역이며 변조되는 경우 `CRITICAL_STRUCTURE_CORRUPTION(BugCheck 0x109)`가 발생하며 BSOD를 만나게 됩니다.

때문에 많은 악성코드, 게임 치트들은 보안 제품을 우회하기 위해 PG에 대해 잘 알고 있습니다.

{% include tip.html content="PG 우회의 가장 빠른 길은 VT-x 를 이용하는 것 입니다. 이는 추후에 업로드 예정입니다."%}