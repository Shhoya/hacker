---
layout: article
title: "[Rev]Cheat Engine(2)"
key: 20190222
tags:
  - Reversing
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] Cheat Engine(2)

<!--more-->

<a href="https://github.com/GameHackingBook/GameHackingCode">예제파일</a>

아.. 재미있다. 책이 다소 불친절한 면이 없지 않다. 구글에도 잘 나오지 않는 문제라 조금 헤맸다.

## [+] MemoryPointers.exe

사실 책을 읽으면서도 잘 이해는 안됐다. 포인터 체인이라느니... 뭐 낯선 용어가 책에 많이있었다. 더 공부해야겠다.

내가 생각할 때 포인터체인은 아마 더블포인터 같은 형식을 의미하는 것 같다.

게임에서 특정 데이터에 대해서는 동적으로 항상 다른 주소에 저장되어야 안전하다. 이 예제에선 이러한 방법을 치트엔진을 통해 우회하는 것을 설명하려는 것 같다.(어디까지나 내 예상..)

이런 경우 정적인 베이스 포인터를 찾고, 그에 맞는 포인터 체인을 구성하여 값을 변조하는 방법을 써야 한다.

수동으로 베이스 메모리 포인터를 찾는 방법과 자동(?)으로 찾아주는 유익한 기능으로 풀이를 시작한다.

### Writeup

먼저 치트엔진으로 해당 예제에 어태치한 후에 마찬가지로 `Scan Type`을 `Unknown initial value`로 선택하고 `First Scan`을 돌린다.

좌표 개념을 생각해보면 x축에서 좌측이면 감소할 것이고 우측이면 증가할 것이다. 이를 기반으로 `Scan Type`을 `Increased Value` 또는 `Decreased Value`로 맞추고 검은 점을 움직이며 `Next Scan`을 통해 오차 범위를 줄여나간다.

몇번 돌리다보면 약 33개정도로 결과가 추려지는 것을 볼 수 있으며 좌표 값이 있는 메모리 주소를 확인할 수 있다.

그런데 초록색(스태틱)이 아닌 검정색이다.. 이제 포인터 체인을 찾는 수동 방법이다.

#### Manually

찾은 값을 더블클릭하여 주소 리스트에 추가하고, 해당 값에서 오른쪽 클릭 후 `Find out what writes to this address` 버튼을 클릭한다.

이 기능은 해당 주소에 어떤 값이 쓰여지는 경우에 어떠한 명령에 의해 변경되는지 찾아주는 기능이다.(굿)

이 상태로 키보드를 입력하여 이동하면 `mov [eax], ecx` 명령에 의해 해당 주소에 값이 쓰여지는 것을 알 수 있다.

자 이제, 해당 주소 값을 다시 스캔한다. `eax`에 있는 값은 처음 찾은 x축 값의 주소이다.

`New Scan`을 클릭 하고, `0x24D26B0`(x축 값이 저장된 주소) 을 스캔한다.

2개정도 나오는데 주소 값이 비슷한게 바로 그 주소다. 그러나 아직 초록색(스태틱) 주소가 아니므로 위와 같은 짓을 반복한다.

찾은 값을 리스트에 추가하고 이번엔 `Find out what access to this address` 를 클릭한다. 마찬가지로 해당 주소에 접근하는 경우 어떤 명령에 의해 접근하는가를 찾는 기능이다.

그러면 `mov eax,[edx+20]` 이라는 값이 보인다. `edx`에 있는 값(0x24D27A0) 을 또 검색하고 이런식으로 여러번 하다보면 스캔 결과에 초록빛 영롱한 스태틱 주소가 나온다.

해당 스태틱 주소를 추가하고 포인터로 변경한 다음 얻은 스태틱 주소를 넣고 `Add Offset` 으로 4개를 추가한다.

위의 과정을 반복하면 *p+0x20,40,80 이런 식의 체인이라는 것을 알 수 있다. 그러므로 0,20,40,80 만큼 포인터 체인을 만들고 OK를 눌러준다.

y축은 간단하게 해당 주소를 하나 더 추가해서 offset을 4,20,40,80으로 맞춰주면된다.

그리고 고정하고 좌표를 맞춰준 뒤 tab키를 클릭하면 썩쎾쓰

#### Pointer Scanner

마찬가지로 먼저 해당 좌표 값에 맞는 주소를 먼저 찾는다.(스캔)
또 약 33개의 결과에서 좌표 주소를 찾을 수 있는데 추가한 다음 이번엔 다음과 같이 진행한다.

마우스 우측 클릭 후 `Pointer scan for this address` 를 클릭하고 아래와 같이 설정하고 스캔을 한다.

![Cheat1](https://github.com/Shhoya/Shhoya.github.io/blob/master/assets/images/task/cheat2.png?raw=true "cheat"){:.border}

그러면 딱봐도 아 저거다 하는 기본 주소가 나온다.
두개를 추가하고 하나는 마찬가지로 오프셋을 4,20,40,80 으로 설정한 후 고정하고 쏘면 끝난다.

![Cheat1](https://github.com/Shhoya/Shhoya.github.io/blob/master/assets/images/task/cheat3.png?raw=true "cheat"){:.border}

끝!!! 불친절해도 어쩔 수 없다. 책이 더 불친절하다.....
그래도 재미다

# [+] Reference

1. ***Game Hacking***

