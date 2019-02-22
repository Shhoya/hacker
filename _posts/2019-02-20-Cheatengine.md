---
layout: article
title: "[Rev]Cheat Engine(1)"
key: 20190220
tags:
  - Reversing
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] Cheat Engine

<!--more-->

처음 게임의 메모리를 수정하여 사용하던 트레이너, 에디터 등은 게임핵, 치트오매틱 등 여러가지 도구들이 많았다. 그러다 이번에 구입한 책에서 치트엔진을 다룬다. 예제파일을 통해 실제 문제를 풀어보니 오우야.... 정말 좋쟈나 라는 생각을했다.

내가 원하는 값을 찾고 수정하는 것이 궁극적인 목표이다. 예제파일은 단순히 점을 움직여 원하는 위치에 놓게 되면 Success가 되는 문제이다.

그림을 넣기 귀찮으니........... 찾아보길...........! www.notarch.com/gamehacking 에 가면 있을꺼다..

몇가지 자세한 사용법을 보고나서 해결했다. 빠르게 솔루션만 남긴다.

치트엔진에서는 `First Scan`과 `Next Scan`을 이용해 기존 값과 비교하여 변한 값들을 찾아가며 내가 원하는 메모리 주소를 얻는다.

그 중 `Scan Type` 설정을 할 수 있는데 이 점을 이용해 나는 문제를 풀었다.

게임을 실행하고 점을 움직이기 전에 `First Scan`을 시도한다. 그러나 나는 해당 값을 알지 못한다. 움직인 점을 그려주는 부분이 있을 것이고 움직이면 특정한 값이 증가하거나 감소할 것이다.

이 때 `Scan Type`에서 먼저 `Unknown Initial Value`로 설정하고 `Memory Scan Option`에서 해당 프로세스로 설정한 다음 `First Scan`을 클릭한다. 약 10,240 개의 값을 찾을 수 있다. 

다음 점의 위치를 이동 시켜본다. 그리고 스캔타입을 `Change Value`로 바꾼 다음 `Next Scan`을 클릭한다. 그러면 범위가 줄어들어 약 6개정도의 값이 나온다. 이 중에 어떤 값을 변경하면 점의 위치가 바뀌는 것을 확인할 수 있다.

하지만 위,아래 또는 좌,우의 좌표만 변경되는 것을 알 수 있다. 그럼 다시 처음으로 돌아가 찾지 못한 좌표 메모리(x 또는 y)를 찾아 변조해보면 된다.

여기서는 좌표에 관한 메모리가 고정으로 할당되어 DWORD 만큼 차이가 난다. 

찾은 메모리의 값을 x축은 27, y축을 3으로 맞춰주면 썪쎼쓰를 하게된다.

![Cheat1](https://github.com/Shhoya/Shhoya.github.io/blob/master/assets/images/task/cheat1.png?raw=true "cheat"){:.border}



끝!!! 오늘은 피곤...

# [+] Reference

1. ***Game Hacking***

