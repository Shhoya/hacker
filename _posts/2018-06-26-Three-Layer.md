---
layout: article
title: "[ML]3Layer Neural Network"
key: 20180626
tags:
  - Dev
  - ML
  - Neural
  - Python
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+] Three Layer Neural Network

<!--more-->

## [+] Matrix

### Matrix

먼저 파이썬으로 다차원 배열을 통해 행렬의 내적을 구하는 방법들을 학습한다.

```python
#-*-coding:utf-8-*-
import numpy as np
import matplotlib.pylab as plt

# 다차원배열

A = np.array([[1,2],[3,4],[5,6]])
print("Array : \n",A)
print("차원 수 : ",np.ndim(A)) #배열의 차원 수 확인
print("행렬 : ",A.shape) # 행렬
```

```
Console
Array :
[[1 2]
[3 4]
[5 6]]
차원 수 : 2
행렬 : (3, 2)
```

그 외에 행렬의 내적을 구하기 위해서는 np.dot() 함수를 이용하면 간단하게 행렬의 내적을 구할 수 있다..
형상이 다른 행렬의 내적도 마찬가지로 계산할 수 있는데 난 수포자였기 때문에 여기서 살짝 헷갈렸었다.

행렬 A의 첫번째 차원의 원소 수(열의 수)와 행렬 B의 0번째 차원의 원소 수(행 수)가 같아야 계산이 가능하다.

```
[1 2 3  	[1 2
 4 5 6] 과 	3 4]  = Error
```

2x3의 행렬과 2x2의 행렬의 내적은 오류를 내뿜게 된다..
A(3x2) * B(2x4) = C(3x4) 으로 만들 때 A와 B의 대응하는 차원의 원소 수가 같아야 한다. 행렬 C는 행렬 A의 행 수와 행렬 B의 열 수가 된다. A(**3**x2) * B(2x**4**) = C(**3**x**4**)

이 행렬 내적에 대해 익히는 이유는 아주 적은 코드로 신경망의 순방향 처리를 완성할 수 있다고 한다..

## [+] Three Layer Neural Network

### Concept

![3layer](https://github.com/Shhoya/Shhoya.github.io/blob/master/assets/images/task/3layer.png?raw=true "3layer"){:.border}

위의 그림의 표기법을 알아둬야 한다.. $$W_{12}^{(1)}$$  여기서 하나 하나씩 뜯어 설명해본다.
$$(1)$$ = 1층의 가중치
$$1$$ = 다음 층의 첫번째 뉴런
2 = 앞 층의 2번째 뉴런
을 의미한다.

해석해보면 앞 층의 2번째 뉴런($$x_2$$)에서 다음 층의 첫번째 뉴런($$a_{1}^{(1)}$$)으로 향할 때의 가중치($$w$$) 라는 의미가 된다.
중요하다 앞으로 신경망 그림마다 요게 나온다...

![3layer](https://github.com/Shhoya/Shhoya.github.io/blob/master/assets/images/task/3layer2.png?raw=true "3layer"){:.border}

'1' 은 편향을 의미한다. 편향은 인덱스가 하나밖에 없는 것을 확인할 수 있다.($$b_1^{(1)}$$)
$$a_1^{(1)}$$ 를 수식으로 나타내보면 다음과 같다. 가중치를 곱하고 신호 두개와의 편향을 합해 계산한다.

$$a_1^{(1)} = w_{11}^{(1)}x_1 + w_{12}^{(1)}x_2 + b_1^{(1)}$$

이걸... 행렬의 내적을 이용하면 1층의 가중치를 간소화할 수 있다.

$$A^{(1)} = XW^{(1)} + B^{(1)}$$

자 전체적으로 보면 다음과 같다.

$$A^{(1)} = (a_1^{(1)} a_2^{(1)} a_3^{(1)})$$ , $$X = (x_1 x_2)$$ , $$B^{(1)} = (b_1^{(1)} b_2^{(1)} b_3^{(1)})$$ 

$$W^{(1)}$$ = 3x2 형상의 행렬.. 수식 쓰기가 빡세다 ㅠ. 

임의의 값을 이용해 파이썬으로 구현해본다. 그 전에 이전에 썼던 활성화 함수에 대한 존재를 잊어선 안된다. 활성화 함수를 이용해 $$z_1^{(1)}$$ 를 변환되는 그림은 아래와 같다.

![3layer](https://github.com/Shhoya/Shhoya.github.io/blob/master/assets/images/task/3layer3.png?raw=true "3layer"){:.border}

이를 파이썬으로 구현하면 다음과 같은 코드를 쓸 수 있다.

```python
#-*-coding:utf-8-*-
import numpy as np

def step_func(x):
    return np.array(x >0,dtype=np.int)


def sigmoid(x):
    return 1 / (1+np.exp(-x))

X = np.array([1.0, 0.5]) #입력 신호
W1 = np.array([[0.1, 0.3, 0.5],[0.2, 0.4, 0.6]]) #가중치
B1 = np.array([0.1, 0.2, 0.3]) #편향

print(W1.shape)
print(X.shape)
print(B1.shape)

A1 = np.dot(X,W1)+B1 #행렬의 내적 + 편향
print(A1)
Z1 = sigmoid(A1) #활성화 함수를 이용해 신호 변환
print(Z1)

```

```
Console
(2, 3)
(2,)
(3,)
[0.3 0.7 1.1]
[0.57444252 0.66818777 0.75026011]
```

여기서 나는 깨달음을 얻었뜨아.
활성화 함수를 계단함수를 써보면 0보다 큰 값이 나오기 때문에 무조건 '1'을 출력하는 것을 볼 수 있을 것이다.
시그모이드 함수를 사용하니 그 값이 매우 섬세한(?) 것을 볼 수 있다.

요즘 관심을 갖고 공부를 하니 좀 더 뭔가 보이는게 많아진다. 좋다.

이 정도 깨달음이면 오늘은 여기까지.

## [+] Reference

1. <a href="http://www.hanbit.co.kr/store/books/look.php?p_code=B8475831198">*"밑바닥부터 시작하는 딥러닝"*</a>
2. <a href="https://en.wikipedia.org/wiki/Artificial_neural_network">*"Wikipedia_Neural_Network"*</a>