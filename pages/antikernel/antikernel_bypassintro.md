---
title: Bypass Introduction
keywords: documentation, technique, debugging
date: 2020-03-09
tags: [Windows, Reversing, Dev]
summary: "Bypass Introduction"
sidebar: antikernel_sidebar
permalink: antikernel_bypassintro.html
folder: antikernel
---

## [0x00] Overview

우회 기법을 챕터에 도착했습니다. 이번 챕터에서는 `ObRegisterCallbacks`을 이용한 디버깅 방지 우회 기법과 안티 커널 디버깅 우회 기법이 수록되어 있습니다.

준비물은 아래와 같습니다.

- IDA Pro
- Anti Kernel Debugging Driver(이전 챕터에서 만든 드라이버)
- windbg

이전 챕터들의 내용을 활용하여 시작하겠습니다. 

