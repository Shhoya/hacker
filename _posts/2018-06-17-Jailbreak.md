---
dlayout: article
title: "[WriteUp]Jailbreak(Viettel Mates CTF 2018)"
key: 20180617
tags:
  - CTF
  - WriteUp
  - Reversing
  - Binary
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+] Jailbreak(Viettel Mates CTF 2018)

<!--more-->

## [+] IPA File

### Write Up

문제의도가 맞는건지 모르지만 너무 쉽게 풀려서 당황했다;
우선 바이너리 파일을 다운로드 받으면 IPA 파일을 던져준다. 처음 iOS 앱 분석을 시작할 때 IPA 파일에 대해 알아보니 IPA는 그저 Archive다. Compress File이다..

자, 그럼 Jailbreak.IPA 파일을 압축을 푼다.(반디집 사용)
Payload 디렉토리 안에 IPA파일과 같은 파일명의 Jailbreak 바이너리 파일을 볼 수 있다.

CydiaImpactor 를 이용하여 해당 IPA파일을 탈옥된 iOS에 설치하여 실행해본다.
내 탈옥된 iOS는 10.2.1 인데, 무심하게도 해당 앱은 11.x 이상에서만 실행이 된다. 때문에 정상 폰에서 실행하기로 했다.

여기서 문제, 정상폰에 변조한 바이너리 파일을 어떻게 넣을 것인가..! 탈옥한 iOS의 경우 root의 권한이 존재하기 때문에 간단히 바이너리 파일만 넣을 수 있다.

일단 앱을 실행하고 'Check' 버튼을 클릭하면 "Sorry, you must change the status to something else" 라는 문구가 떨어진다. 이를 이용해 분기문을 변조하면 플래그가 나올꺼라 생각이 들었다.

![Jailbreak](https://github.com/Shhoya/Shhoya.github.io/blob/master/assets/images/task/jail.png?raw=true "jailbreak"){:.border}

가장 가운데 있는 loc_1007218 함수에서 분기문인 **TBZ**를 **TBNZ**로 변조해 주면 된다. 해당 OP code를 바이너리에서 찾아 HxD 를 이용해 변조하여 저장한다.

그렇게 압축해서 IPA로 확장자를 바꾼 뒤, Cydia Impactor를 이용해 정상 폰에 넣어서 실행해주면 플래그를 얻을 수 있다.

![Jailbreak](https://github.com/Shhoya/Shhoya.github.io/blob/master/assets/images/task/jail2.jpg?raw=true "jailbreak"){:.border}



끗;

