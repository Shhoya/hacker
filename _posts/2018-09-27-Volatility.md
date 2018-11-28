---
layout: article
title: "[Forensic]Volatility"
key: 20180927
tags:
  - Framework
  - Memoryscan
  - WriteUp
  - Forensic
sidebar:
  nav: sidem
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] Volatility(SEC-T CTF 2018)

<!--more-->

## [+] Concept

### Volatility ?

> Volatility is a python based command line tool that helps in analyzing virtual memory dumps. It provides a very good way to understand the importance as well as the complexities involved in Memory Forensics.

가상 메모리 덤프 분석 시 효율적으로 분석하기 위한 파이썬 기반의 커맨드라인 도구이다.!
볼라틸리티는 휘발성이라는 의미로 휘발성 데이터인 메모리를 분석하는 것에서 이름을 따온 것 같다.
이번 SEC-T CTF에서 나온 포렌식 문제를 통해 공부를하즈아

## [+] Usage

### imageinfo

`imageinfo` 명령어는 해당 덤프가 발생한 OS 및 아키텍쳐를 분별하는데 사용된다. 또한 이 정보는 다른 명령어를 사용할 때 전달하는 `--profile` 의 값이기도 하다. 여러 가지의 아키텍쳐가 나올 경우 올바른 프로파일을 선택하는 것에 주의를 해야 한다.

```
$ volatility -f batou imageinfo
Volatility Foundation Volatility Framework 2.6
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : Win7SP1x64, Win7SP0x64, Win2008R2SP0x64, Win2008R2SP1x64_23418, Win2008R2SP1x64, Win7SP1x64_23418
                     AS Layer1 : WindowsAMD64PagedMemory (Kernel AS)
                     AS Layer2 : VMWareAddressSpace (Unnamed AS)
                     AS Layer3 : FileAddressSpace (/mnt/hgfs/CTF/SectCTF/batou/batou)
                      PAE type : No PAE
                           DTB : 0x187000L
                          KDBG : 0xf800028480a0L
          Number of Processors : 2
     Image Type (Service Pack) : 1
                KPCR for CPU 0 : 0xfffff80002849d00L
                KPCR for CPU 1 : 0xfffff880009ea000L
             KUSER_SHARED_DATA : 0xfffff78000000000L
           Image date and time : 2018-09-11 04:17:17 UTC+0000
     Image local date and time : 2018-09-10 21:17:17 -0700
```

### pslist

`pslist` 는 덤프 될 때 실행 중이던 프로세스의 목록을 보여준다. 오프셋, PID, PPID 등 유용한 정보가 많이 존재하는 자주 사용하게 될 명령어이다. 그러나 숨겨진 프로세스에 대해서는 확인할 수 없다. 그럴 때 `psscan` 명령어를 이용하여 숨겨진 프로세스까지 확인이 가능하다.

```
$ volatility -f batou --profile=Win7SP1x64 psscan
Volatility Foundation Volatility Framework 2.6
Offset(P)          Name                PID   PPID PDB                Time created                   Time exited                   
------------------ ---------------- ------ ------ ------------------ ------------------------------ ------------------------------
0x000000003de683c0 dwm.exe            1660    792 0x0000000014479000 2018-09-11 04:16:05 UTC+0000                                 
0x000000003de72b30 explorer.exe       1720   1652 0x00000000154e2000 2018-09-11 04:16:05 UTC+0000                                 
0x000000003df57b30 SearchProtocol     1040   1988 0x000000000d026000 2018-09-11 04:16:13 UTC+0000                                 
0x000000003df77b30 SearchFilterHo     1140   1988 0x000000000d92f000 2018-09-11 04:16:13 UTC+0000                                 
0x000000003df9f100 SearchProtocol     1340   1988 0x00000000106ca000 2018-09-11 04:16:13 UTC+0000                                 
0x000000003dfaf4a0 iexplore.exe       1536   1720 0x000000000c130000 2018-09-11 04:16:15 UTC+0000                                 
0x000000003dfe54f0 iexplore.exe       1636   1536 0x000000000be44000 2018-09-11 04:16:17 UTC+0000                                 
0x000000003dfef570 StikyNot.exe       1872   1720 0x0000000006f04000 2018-09-11 04:16:20 UTC+0000                                 
0x000000003e08d3a0 taskhost.exe       1728    460 0x0000000014187000 2018-09-11 04:16:05 UTC+0000                                 
0x000000003e1da210 notepad.exe         204   1720 0x0000000028c02000 2018-09-11 04:16:31 UTC+0000                                 
0x000000003e22bb30 svchost.exe         748    460 0x000000001ba0c000 2018-09-11 04:15:34 UTC+0000                                 
0x000000003e23eb30 svchost.exe         792    460 0x000000001b619000 2018-09-11 04:15:34 UTC+0000                                 
0x000000003e264890 svchost.exe         820    460 0x000000001b31f000 2018-09-11 04:15:34 UTC+0000                                 
0x000000003e2b32a0 svchost.exe         944    460 0x000000001bf2a000 2018-09-11 04:15:35 UTC+0000                                 
0x000000003e2eb890 svchost.exe         212    460 0x000000001bb38000 2018-09-11 04:15:35 UTC+0000                                 
0x000000003e367b30 spoolsv.exe         300    460 0x000000001b064000 2018-09-11 04:15:35 UTC+0000                                 
0x000000003e379b30 svchost.exe         968    460 0x000000001b8c6000 2018-09-11 04:15:36 UTC+0000                                 
0x000000003e4de060 csrss.exe           316    308 0x000000002004a000 2018-09-11 04:15:32 UTC+0000                                 
0x000000003e4f0b30 lsass.exe           468    372 0x000000001ea74000 2018-09-11 04:15:33 UTC+0000                                 
0x000000003e5062b0 wininit.exe         372    308 0x000000001fc50000 2018-09-11 04:15:33 UTC+0000                                 
0x000000003e510a00 winlogon.exe        400    356 0x000000001f19d000 2018-09-11 04:15:33 UTC+0000                                 
0x000000003e551060 services.exe        460    372 0x000000001eb54000 2018-09-11 04:15:33 UTC+0000                                 
0x000000003e55bb30 lsm.exe             476    372 0x000000001f47c000 2018-09-11 04:15:33 UTC+0000                                 
0x000000003e5b7b30 svchost.exe         584    460 0x000000001e7c5000 2018-09-11 04:15:34 UTC+0000                                 
0x000000003e612b30 svchost.exe         664    460 0x000000001b903000 2018-09-11 04:15:34 UTC+0000                                 
0x000000003edbe2d0 SearchIndexer.     1988    460 0x000000000fe67000 2018-09-11 04:16:12 UTC+0000                                 
0x000000003f41c750 smss.exe            232      4 0x0000000025ac0000 2018-09-11 04:15:30 UTC+0000                                 
0x000000003febdb30 notepad++.exe      1568   1720 0x0000000005f4c000 2018-09-11 04:16:39 UTC+0000   2018-09-11 04:16:48 UTC+0000  
0x000000003ffbdae0 System                4      0 0x0000000000187000 2018-09-11 04:15:30 UTC+0000                                 
0x000000003ffc65f0 csrss.exe           364    356 0x000000001fb97000 2018-09-11 04:15:33 UTC+0000
```

### pstree

음 흔히 알고 있는 `pstree`와 같다. `pslist`와 마찬가지로 숨겨진 프로세스를 확인할 수는 없지만 부모,자식 프로세스의 관계를 쉽게 확인할 수 있다는 장점이 있다.

```
$ volatility -f batou --profile=Win7SP1x64 pstree
Volatility Foundation Volatility Framework 2.6
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0xfffffa8002c52b30:explorer.exe                     1720   1652     30    676 2018-09-11 04:16:05 UTC+0000
. 0xfffffa8002d8f4a0:iexplore.exe                    1536   1720     18    426 2018-09-11 04:16:15 UTC+0000
.. 0xfffffa8002dc54f0:iexplore.exe                   1636   1536     17    346 2018-09-11 04:16:17 UTC+0000
. 0xfffffa8002bba210:notepad.exe                      204   1720      1     60 2018-09-11 04:16:31 UTC+0000
. 0xfffffa8002dcf570:StikyNot.exe                    1872   1720     11    142 2018-09-11 04:16:20 UTC+0000
 0xfffffa8000ca4ae0:System                              4      0     73    444 2018-09-11 04:15:30 UTC+0000
. 0xfffffa80019fc750:smss.exe                         232      4      2     30 2018-09-11 04:15:30 UTC+0000
 0xfffffa8000cad5f0:csrss.exe                         364    356      8    209 2018-09-11 04:15:33 UTC+0000
 0xfffffa80026f0a00:winlogon.exe                      400    356      5    117 2018-09-11 04:15:33 UTC+0000
 0xfffffa80026be060:csrss.exe                         316    308      9    303 2018-09-11 04:15:32 UTC+0000
 0xfffffa80026e62b0:wininit.exe                       372    308      4     80 2018-09-11 04:15:33 UTC+0000
. 0xfffffa8002731060:services.exe                     460    372     13    182 2018-09-11 04:15:33 UTC+0000
.. 0xfffffa80027f2b30:svchost.exe                     664    460      7    233 2018-09-11 04:15:34 UTC+0000
.. 0xfffffa800281eb30:svchost.exe                     792    460     21    420 2018-09-11 04:15:34 UTC+0000
... 0xfffffa8002c483c0:dwm.exe                       1660    792      5     77 2018-09-11 04:16:05 UTC+0000
.. 0xfffffa8002947b30:spoolsv.exe                     300    460     13    276 2018-09-11 04:15:35 UTC+0000
.. 0xfffffa80028932a0:svchost.exe                     944    460     14    238 2018-09-11 04:15:35 UTC+0000
.. 0xfffffa8002797b30:svchost.exe                     584    460     13    358 2018-09-11 04:15:34 UTC+0000
.. 0xfffffa8002844890:svchost.exe                     820    460     34    724 2018-09-11 04:15:34 UTC+0000
.. 0xfffffa8002a6d3a0:taskhost.exe                   1728    460      9    166 2018-09-11 04:16:05 UTC+0000
.. 0xfffffa8001f9e2d0:SearchIndexer.                 1988    460     15    652 2018-09-11 04:16:12 UTC+0000
... 0xfffffa8002d57b30:SearchFilterHo                1140   1988      6     84 2018-09-11 04:16:13 UTC+0000
... 0xfffffa8002d37b30:SearchProtocol                1040   1988      8    240 2018-09-11 04:16:13 UTC+0000
... 0xfffffa8002d7f100:SearchProtocol                1340   1988      8    229 2018-09-11 04:16:13 UTC+0000
.. 0xfffffa8002959b30:svchost.exe                     968    460     20    315 2018-09-11 04:15:36 UTC+0000
.. 0xfffffa80028cb890:svchost.exe                     212    460     18    367 2018-09-11 04:15:35 UTC+0000
.. 0xfffffa800280bb30:svchost.exe                     748    460     18    351 2018-09-11 04:15:34 UTC+0000
. 0xfffffa800273bb30:lsm.exe                          476    372     11    141 2018-09-11 04:15:33 UTC+0000
. 0xfffffa80026d0b30:lsass.exe                        468    372      8    446 2018-09-11 04:15:33 UTC+0000
```

### cmdscan

`cmdscan`은 명령어 프롬프트에 입력한 내용을 확인할 수 있다.  위에서부터 사용한 예제에는 `cmdscan`으로 확인 결과, 내용이 발견되지 않아 예제는 없다.

### filescan

`FILE_OBJECT`의 핸들을 확인할 수 있는 명령어 이다. 해당 명령어를 통해 문제에 제시되었던 `notepad` 문자열을 검색해보면 위에서 숨겨진 프로세스(혹은 종료된)로 발견되었던 `Notepad++` 디렉토리에 백업 파일이 존재하는 것을 확인 가능하다.

```
$ volatility -f batou --profile=Win7SP1x64 filescan |grep -i notepad
Volatility Foundation Volatility Framework 2.6
0x000000003dc3d3d0     16      0 R--rw- \Device\HarddiskVolume2\ProgramData\Microsoft\Windows\Start Menu\Programs\Notepad++.lnk
0x000000003dc44f20      9      0 R--r-- \Device\HarddiskVolume2\Program Files (x86)\Notepad++\plugins\mimeTools\mimeTools.dll
0x000000003dc5fbc0      5      0 R--r-d \Device\HarddiskVolume2\Windows\System32\notepad.exe
0x000000003dc62070     16      0 R--rw- \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Accessories\Notepad.lnk
0x000000003dc8fbc0     16      0 R--r-d \Device\HarddiskVolume2\Windows\System32\en-US\notepad.exe.mui
0x000000003dc8fdd0     16      0 R--r-d \Device\HarddiskVolume2\Program Files (x86)\Notepad++\SciLexer.dll
0x000000003dc8ff20     16      0 R--rw- \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\config.xml
0x000000003de6df20     16      0 R--rwd \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\plugins\config\DSpellCheck.ini
0x000000003e1ffa10     13      0 R--rw- \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\langs.xml
0x000000003e1ffcb0      8      0 R--r-- \Device\HarddiskVolume2\Program Files (x86)\Notepad++\plugins\DSpellCheck\DSpellCheck.dll
0x000000003e27da50     15      0 R--r-- \Device\HarddiskVolume2\Program Files (x86)\Notepad++\SciLexer.dll
0x000000003e50fd60     15      0 R--r-- \Device\HarddiskVolume2\Program Files (x86)\Notepad++\notepad++.exe
0x000000003e55f070     16      0 R--rw- \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\shortcuts.xml
0x000000003e55f300     15      0 R--rw- \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\stylers.xml
0x000000003f38e6b0      1      1 R--r-d \Device\HarddiskVolume2\Windows\System32\en-US\notepad.exe.mui
0x000000003fe9c930     16      0 R--rw- \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\backup\new 2@2018-09-10_203737
0x000000003fead410     16      0 R--rw- \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\backup\new 1@2018-09-10_202915
0x000000003fec75a0     16      0 R--rwd \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\plugins\config\converter.ini
0x000000003fec76f0      9      0 R--r-- \Device\HarddiskVolume2\Program Files (x86)\Notepad++\plugins\NppConverter\NppConverter.dll
0x000000003fecaf20     10      0 R--rw- \Device\HarddiskVolume2\Program Files (x86)\Notepad++\plugins\Config\Hunspell\en_US.dic
0x000000003fecc770     16      0 R--rw- \Device\HarddiskVolume2\Program Files (x86)\Notepad++\plugins\Config\Hunspell\en_US.aff
0x000000003fecc8c0     12      0 R--r-- \Device\HarddiskVolume2\Program Files (x86)\Notepad++\plugins\NppExport\NppExport.dll
0x000000003fece070     16      0 R--rw- \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\contextMenu.xml
0x000000003fece220     16      0 R--rw- \Device\HarddiskVolume2\Program Files (x86)\Notepad++\change.log
0x000000003feced10     16      0 R--rw- \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\session.xml
0x000000003ffa21c0     13      0 R--r-d \Device\HarddiskVolume2\Program Files (x86)\Notepad++\notepad++.exe
```

### dumpfiles

메모리 안에 `FILE_OBJECT`를 추출할 때 사용한다. 위에서 얻은 오프셋 또는 PID를 이용해 추출이 가능하다.

```
$ volatility -f batou --profile=Win7SP1x64 dumpfiles -Q 0x000000003fe9c930 -D ./pp
Volatility Foundation Volatility Framework 2.6
DataSectionObject 0x3fe9c930   None   \Device\HarddiskVolume2\Users\Batou\AppData\Roaming\Notepad++\backup\new 2@2018-09-10_203737
```

`-Q` 옵션을 이용해 오프셋을 지정해주고 `-D` 옵션으로 디렉토리를 설정하여 추출이 가능하다. 해당 파일을 열어보면 다음과 같은 내용을 볼 수 있다.

```
$ cat file.None.0xfffffa8000da35c0.dat 

53 45
43 54 7b 
34 6c 6c 5f 79 6f 75 72 5f 4e 30 74 33 73 5f 34 72 33 5f 62 33 6c 30 6e 67 5f 74 30 5f 75 35
```

```python
data=[0x53,0x45,0x43,0x54,0x7b,0x34,0x6c,0x6c,0x5f,0x79,0x6f,0x75,0x72,0x5f,0x4e,0x30,0x74,0x33,0x73,0x5f,0x34,0x72,0x33,0x5f,0x62,0x33,0x6c,0x30,0x6e,0x67,0x5f,0x74,0x30,0x5f,0x75,0x35,0x7d]
flag=''
for i in range(len(data)):
    flag+=chr(data[i])
print flag
```

```
SECT{4ll_your_N0t3s_4r3_b3l0ng_t0_u5}
```

플래그가 출력되는 것을 확인할 수 있다. 이 문제는 여러가지 삽질을 해서 못풀었지만 그래도 볼라틸리티의 기본적인 사용법을 배우기 좋은 문제라고 생각이된다.

끗.