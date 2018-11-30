---
layout: article
title: "[Mobile]Autoready release v1.1(New)"
key: 20181130
tags:
  - Android
  - Mobile
  - Tool
  - Dev
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+] Autoready release(v1.1)

<!--more-->

## [+] Download

<a href="https://github.com/Shhoya/Shhoya_autoready/raw/master/Release/Python Release(v1.1 New)/Autoready_v1.1.zip">Autoready python Download</a>

1.1 버전으로 오랜만에 기능도 추가해봤다. 개인정보도 넣고 싶었지만 그건 다음 릴리즈 때..

## [+] Change log

### 검색 기능 추가

- 단말기 내 앱 또는 앱 데이터를 검색하여 선택할 수 있는 기능 추가

### 고유식별정보 찾기 추가

- 데이터 내 고유식별정보(운전면허번호, 주민등록번호, 여권번호, 외국인등록번호) 검색 기능 추가
- `autoready.py -D` 를 이용해 데이터를 다운로드 받은 후, `autoready.py -s` 또는 `autoready.py --search`
- 단순 정규식 표현을 이용하여 검색, 현재 여권번호의 경우 정규표현식으로 정확히 추출이 어려워 주석처리

## [+] Issue

- 데이터 추출 옵션(`-D`) 사용 시, 간혹 모든 데이터를 못가져오는 이슈가 발견됨
- 해당 버그의 경우 고칠 의사가 없으며 안나오면 sdcard로 데이터를 이동하여 손수 가져오길 바람..
- 그 외 버그 놉

