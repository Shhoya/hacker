---
layout: article
title: "[ML]3Layer Neural Network(2)"
key: 20180716
tags:
  - Dev
  - ML
  - Neural
  - Python
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+] Three Layer Nueral Network(2)

<!--more-->

## [+] Three Layer

### Forward

3층까지 가는데 너무 멀다.; 

![3layer](https://github.com/Shhoya/Shhoya.github.io/blob/master/assets/images/task/3layer5.png?raw=true "3layer"){:.border}

후딱 정리하고 자야지

```python
import numpy as np

def sigmoid(x):
    return 1 / (1+np.exp(-x))

def identity_func(x):
    return x

def init_network():
    network={}
    network['W1'] = np.array([[0.1,0.3,0.5],[0.2,0.4,0.6]])
    network['b1'] = np.array([0.1,0.2,0.3])
    network['W2'] = np.array([[0.1,0.4],[0.2,0.5],[0.3,0.6]])
    network['b2'] = np.array([0.1,0.2])
    network['W3'] = np.array([[0.1,0.3],[0.2,0.4]])
    network['b3'] = np.array([0.1,0.2])

    return network

def forward(network, x):
    W1, W2, W3 = network['W1'], network['W2'], network['W3']
    b1, b2, b3 = network['b1'], network['b2'], network['b3']

    a1 = np.dot(x,W1)+b1
    z1 = sigmoid(a1)
    a2 = np.dot(z1,W2)+b2
    z2 = sigmoid(a2)
    a3 = np.dot(z2,W3)+b3
    y = identity_func(a3)

    return y

network = init_network()
x = np.array([1.0,0.5])
y = forward(network, x)
print(y)
```

``init_network`` 함수의 경우 가중치와 편향을 초기화하고 딕셔너리 변수 `network` 에 저장한다.
해당 `network`에 각 층에 필요한 가중치와 편향을 저장하고 이를 이용해 `forward` 함수로 입력 값 `x`와 가중치 편향을 전달하여 연산을 한다.

이는 현재 순방향 , 즉 입력에서 출력으로 전달되는 형식이다. 곧 역방향도 해봐야되는데 에라이.. 어렵지만뭐 파이썬 공부한다 생각한다.



## [+] Reference

1. <a href="http://www.hanbit.co.kr/store/books/look.php?p_code=B8475831198">*"밑바닥부터 시작하는 딥러닝"*</a>
2. <a href="https://en.wikipedia.org/wiki/Artificial_neural_network">*"Wikipedia_Neural_Network"*</a>