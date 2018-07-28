---
layout: article
title: "[Mobile]Shhoya_Autoready 1.0 beta release"
key: 20180728
tags:
  - iOS
  - Android
  - Mobile
  - Tool
  - Dev
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+] Concept

## [+] Mobile PT

<!--more-->

### Download

<a href="https://github.com/Shhoya/Shhoya_autoready/raw/master/Releases/shhoya_autoready_v1.0.zip">Autoready Download</a>

- Version 1.0 beta release


### Requirement

Local

- Frida 11.0.6 (12.x 의 경우 메모리덤프 에러)
- python 2.7
- adb

Android

- frida-server 11.0.6


### Using C++

으음.. C++ 공부하다가 문득 모바일 앱 진단 간편화 도구를 만들어보자 라는 생각을 했다.
물론 예전에 C로도 구현을 해보긴했지만 이번엔 나름 몇가지 기능을 추가해서 만들어봤다.

### Function

현재 iOS는 준비중이다. 사실상 배치 스크립트처럼 봐도 무관한 프로그램이지만 내 공부겸 C++을 이용해서 만들어본 것이므로 뿌듯하다.

iOS의 경우 문제가 많다. 10.x 이하 버전과  11.x 이상 버전의 동작이 심오하게 다르기 때문에 현재 어떤식으로 구현하면 좋을지 고민 중이다.

안드로이드 기능의 동작방식은 다음과 같다.

1. adb를 이용하여 설치된 apk 목록을 가져와 `app_list.txt`를 저장한다.
2. 해당 `app_list.txt` 내 목록을 선택하여 `adb pull` 명령어로 apk를 저장한다.
3. 이 후 `apktools.jar` 를 이용해 앱을 디컴파일 한다.
4. 데이터 추출의 경우 마찬가지로 `data_list.txt`로 설치된 앱 데이터 목록을 저장한다.
5. `/data/data` 내에서 직접 다운로드가 불가능한 경우가 있기 때문에 데이터를 복사한다.
   - `/sdcard/Download` 디렉토리 내 `Autoready` 디렉토리를 생성
   - `/data/data` 내 전체 데이터를 `Autoready` 디렉토리로 복사( 무식하지만 ... 임시방편;)
6. `adb pull` 명령어를 이용해 `data_list.txt` 에서 선택한 앱 데이터를 다운로드한다.
7. 빌드의 경우 `apktools.jar` 를 이용해 앱을 빌드하고 `signapk.jar` 를 이용해 사인해 사용가능한 앱으로 만든다.
8. 메모리 덤프의 경우 `fridump` 를 이용해 앱에 대한 전체 메모리 덤프를 추출한다.
   - `frida-ps` 명령어를 이용해 현재 실행 중인 app에 대한 목록을 불러 온다.
   - 앱의 pid나 앱 이름으로 진행하고 싶었으나 한글 인코딩 등의 문제가 있어 앱의 identifier를 입력받는다.
   - 목록에서 com.shhoya.shhoya~ 이런식으로 되어 있는게 identifier 이다. 이걸 복사해서 입력하면 된다.

### ISSUE

첫번째, Android 특정 버전 이하에서는 앱 다운로드 시 base.apk 로 다운로드 되지 않는다. 이럴 때 디컴파일이 자동으로 되지 않는데, 해당 파일을 base.apk로 파일 이름을 변경해서 `Only Decompile` 메뉴를 이용하면 된다.

두번째, 에러에 대한 예외처리 아직 없다. 그냥 다 되는거처럼 보일 수 있으나 어느정도 티는 난다.. 계속 추가예정



### Usage

실행파일 : Shhoya_autoready_v1.0.exe
사용도구 : apktool, signapk, frida, fridump

데이터 추출의 경우 `/data/data` 를 통째로 복사한 후 작업이 끝나면 복사된 파일들은 다시 삭제한다. 너무 대량인 경우 긴 작업 시간이 필요하므로 앱들은 정리해놓고 진단 대상 앱만 설치해둘 것을 권장한다.

메모리 덤프의 경우 앱의 전체 메모리 덤프를 추출하므로 시간이 오래걸린다. 감안해야된다.

데이터 추출 및 메모리 덤프 후 특정 문자열을 찾을 때는 powershell을 이용해 `findstr` 명령어를 추천한다.
메모리의 경우 `dump` 디렉토리 내 `strings.txt`로 문자열들이 저장되므로 참조해봐도 좋다.

점점 업데이트를 해보겠드아ㅏ!



