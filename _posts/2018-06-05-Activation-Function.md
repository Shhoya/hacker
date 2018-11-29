---
layout: article
title: "[ML]Activation Function"
key: 20180605
tags:
  - Dev
  - ML
  - Neural
  - Python
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+] Activation Function

<!--more-->

## [+] Sigmoid Function



### Concept

이제 활성화 함수에 대해 공부해본다.. 사실 내일 새벽에 다낭으로 해외여행을 가지만 짬이 나서 잠시!!

시그모이드 함수는 신경망에서 매우 많이 사용된다고 한다.
수식은 다음과 같다.



$$h(x) ={ 1 \over 1+exp(-x)}$$



수학적으로 자연상수를 뜻한다고 한다... 수학적으로 접근 시 매우 어려우니 단순히 함수라고 생각하자.
입력이 있으면 그에 대해 출력해준다. 

### Example

$$h(1.0) = 0.731...$$ 

$$h(2.0) = 0.880...$$

이러한 입력과 출력으로 식별한다고 생각하면 될 것 같다. 단, 시그모이드 함수를 왜 자주 쓰는지가 중요한 것 같다.



## [+] Step Function

### Concept

쉽게 생각하여 입력의 결과가 0을 넘으면 1을 출력하고 그 외에는 0을 출력하는 함수다.
실제 구글링을하여 Wiki를 찾아보면 엄청 복잡하게 설명되어 있지만 사실 위의 말이 모든걸 의미한다.

### implementation

python 의 numpy 모듈과 matplotlib 를 이용하여 계단함수를 구현할 수 있다. 그렇다면 어떻게 그래프가 나타나는지 확인해본다.

```python
import numpy as np
import matplotlib.pylab as plt

def step_function(x):
    return np.array(x >0, dtype=np.int)

x = np.arange(-5.0,5.0,0.1)
y = step_function(x)
plt.plot(x,y)
plt.ylim(-0.1,1.1)
plt.show()

```

실제 실행하면 다음과 같은 그래프를 확인할 수 있다.

![stepf](https://github.com/Shhoya/Shhoya.github.io/blob/master/assets/images/task/step1.png?raw=true "StepFunc"){:.border}

정말 계단 같다. 0을 경계로 1 또는 0만을 출력하는 것을 볼 수 있다. 이러한 계단과 같은 형태 때문에 계단함수라고 불린다.
이상으로 개념을 마치고 다음 부턴 실제 활성화 함수들의 진지한(?) 구현을 해보겠다..;

## [+] Reference

1. <a href="http://www.hanbit.co.kr/store/books/look.php?p_code=B8475831198">*"밑바닥부터 시작하는 딥러닝"*</a>

2. <a href="https://en.wikipedia.org/wiki/Step_function">*"Wiki Step Function"*</a>
