---
layout: article
title: "[Rev]Windbg Plugin"
key: 20190530
tags:
  - Reversing
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] Windbg Plugin

<!--more-->

Windbg의 커맨드창은 여전히 낯설다. 몇가지 플러그인 설치 방법과 사용법을 알아본다.

## [+] Mex

- <https://www.microsoft.com/en-us/download/confirmation.aspx?id=53304> 다운로드
- 실행 시 원하는 디렉토리에 설치(압축파일로 떨어짐)
- 해당 압축 파일 내 x64, x86버전이 있으므로 windbg 설치 경로 내 winext 디렉토리에 모듈을 이동
- windbg 실행 후 `.load` 명령으로 통해 `.load mex.dll` 으로 불러오기 완료
- `!mex.p` , `!mex.lt` 로 프로세스와 스레드에 대한 상세하게 분석 가능함(`!mex.help`)

```
Microsoft (R) Windows Debugger Version 10.0.18362.1 AMD64
Copyright (c) Microsoft Corporation. All rights reserved.

CommandLine: "C:\Users\hunho\Documents\Visual Studio 2017\Projects\CPP1\Release\CPP1.exe"
Symbol search path is: srv*
Executable search path is: 
ModLoad: 00000000`003f0000 00000000`003f6000   CPP1.exe
ModLoad: 00007ffd`ef200000 00007ffd`ef3e1000   ntdll.dll
ModLoad: 00000000`77ce0000 00000000`77e70000   ntdll.dll
ModLoad: 00000000`77bf0000 00000000`77c42000   C:\WINDOWS\System32\wow64.dll
ModLoad: 00000000`77c50000 00000000`77cc8000   C:\WINDOWS\System32\wow64win.dll
(42c4.b0c): Break instruction exception - code 80000003 (first chance)
ntdll!LdrpDoDebuggerBreak+0x30:
00007ffd`ef2cc93c cc              int     3
0:000> .load mex.dll
0:000> !mex.p
Name                                Ses PID            PEB              Mods Handle Thrd
=================================== === ============== ================ ==== ====== ====
.  0	id: 42c4	create	name: cpp1.exe   1 42c4 (0n17092) 00000000006b6000    5     35    1

CommandLine: "C:\Users\hunho\Documents\Visual Studio 2017\Projects\CPP1\Release\CPP1.exe"
Last event: 42c4.b0c: Break instruction exception - code 80000003 (first chance)

Show Threads: Unique Stacks    !listthreads (!lt)    ~*kv
0:000> !mex.lt
 # DbgID ThdID Wait Function                  User Kernel Info     TEB              Create Time
== ===== ===== ============================== ==== ====== ======== ================ ==========================
->     0   b0c ntdll!LdrpDoDebuggerBreak+0x30    0      0 Event... 00000000006b8000 05-20-2019 01:01:33.923 오후
```



## [+] DbgKit(Only Kernel mode)

- <http://www.andreybazhan.com/dbgkit.html> 다운로드
- 마찬가지로 압축 파일 내 모듈이 존재함
- windbg 설치 경로 내 아키텍쳐별 winext로 이동
- `.load dbgkit.dll`
- `!dbgkit.help` 시 친절히 나옴

해당 모듈은 커널모드에서만 사용 가능하다. 서비스,프로세스,스레드 등 중요정보를 GUI 형식으로 이쁘게 보여준다. 마치 Process Explorer나 Process Hacker로 보듯이.... 커널 디버깅 시 매우 유용



## [+] TWindbg(Like Peda)

괜찮은 하이라이트가 뭐 없나 찾다가... @T0rchwo0d 도 사용하고 있는 `TWindbg`!

- <https://github.com/bruce30262/TWindbg> 다운로드
- `pip install pykd` 로 설치(python 2.7 기준)
- 다운로드 받은 `TWindbg` 압축을 풀고 `TWindbg` 폴더를 통째로 Windbg 설치 경로에 놓는다. `x64,x86` 나누지말고 기본 설치경로 기준 `Deubggers` 내에 이동
- python2.7 설치 경로 내에서 `pykd.pyd` 파일을 찾아 위와 마찬가지로 `winext` 경로에 가져다 놓는다.
- 바탕화면이나 어디든 `windbg` 바로가기를 만들어 다음과 같이 명령줄을 만든다. `"C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\windbg.exe" -c ".load pykd.pyd; !py -g TWindbg\TWindbg.py"`

초록초록하기도하고... 일단 `peda`와 같이 동적 디버깅 중 많은걸 볼 수 있어 좋다.

파이썬으로 되어있어 컬러들도 내 맘대로 꾸며볼 수 있다.



끗!