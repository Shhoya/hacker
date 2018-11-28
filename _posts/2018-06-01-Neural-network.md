---
layout: article
title: "[ML]Neural Network"
key: 20180601
tags:
  - Dev
  - ML
  - Neural
sidebar:
  nav: sidem
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+]Neural Network

<!--more-->

## [+]Concept

### Neural Network ?

신경망을 알아야 하는 이유는 <a href="https://shhoya.github.io/2018/05/30/First-Post.html">퍼셉트론</a>의 한계때문이다. 뭐 이전에 너무 대충 설명해놔서 그렇긴하지만 찾아보면 될꺼다... ~~무책임..~~

퍼셉트론의 경우 가중치를 직접 설정해줘야 했다. 논리 게이트를 표현할 때 수동으로 적절한 값을 지정해줘야했다. 이러한 한계를 신경망이 해결해준다. 

> ***"신경망은 가중치를 정할 때, 데이터를 학습한 모델이 정한다."***

하지만.... 그 전에 알아야 할게 너무많다.  갈 길이 엄청나게 멀...다



![NeuralNet](https://raw.githubusercontent.com/Shhoya/Shhoya.github.io/master/assets/images/task/neural_network.png "Neuralnet"){:.border}

위의 그림에서 입력, 은닉, 출력 순서로 뉴런이 구성되어 있는 것을 볼 수 있다. 
(출처: https://en.wikipedia.org/wiki/Artificial_neural_network)





### Perceptron

기존에 너무 대충 설명해서 다시 한번 짚고 넘어간다. 위에서 그린 그림으로 퍼셉트론을 표현해보면 다음과 같다.

![Perceptron](https://raw.githubusercontent.com/Shhoya/Shhoya.github.io/master/assets/images/task/perceptron.png "Perceptron"){:.border}

아름답다. output of function 부분을 보면 이전에 설명한 공식이다. 자, 입력이 총 3개가 들어온다(그림에서는 $$1$$를 입력으로 안쳤지만 난 다 친다.)

$$1$$, $$x_1$$,$$x_2$$ 입력에 각각 $$b,w_1,w_2$$ 가중치를 곱하여 다음 뉴런에서 이 값들을 모두 합하여 그 값이 0을 넘으면 1, 0을 넘지 않으면 0을 출력하게 되는 것이다.

이를 함수로 표현하면,

$$y = f(w_1x_1 + w_2x_2 + b)$$



$$f(x) = 0 (x<=0)$$

$$f(x) = 1(x > 0)$$

이 된다. 얼마나 간결한 표현인가................ 수학은 멋있다.



## [+]Activation Function

### Activation function ?

하.. 지옥에 온걸 환영한다. 난 이미 여기부터 굉장히 머리아팠고 지금도 아파온다. 위에서 $$f(x)$$ 함수로 간결하게 표현한 것을 볼 수 있다. 이는 입력 값의 총 합을 출력 값으로 변환하는 함수인 것인데, 이러한 함수를 **활성화 함수(Activation Function)** 이라고 한다.

말 그대로 활성화를 일으키는가, 일으키지 않는가를 결정하는 일을 한다.

![Neural](https://raw.githubusercontent.com/Shhoya/Shhoya.github.io/master/assets/images/task/active.png "Neural"){:.border}

위의 그림을 식으로 표현하면 아래와 같다.



$$a=b + x_1w_1 + x_2w_2$$

$$y = h(a)$$

가중치를 조합하여 나온 결과 $$a$$ 노드, 활성화 함수 $$h()$$ 를 통해 $$y$$ 노드로 변환되는 과정을 표현한 것이다.





### So What ?



단층 퍼셉트론(Simple layer Perceptron)과 다층 퍼셉트론(Multi layer Perceptron)을 구분 짓는다고 한다. 
이게 왜 중요하냐... 활성화 함수가 뭐고 퍼셉트론이 그래서 뭔가 라는 생각을 했다. 

단층 퍼셉트론은 **계단 함수를 활성화 함수**로 사용한 모델.

다층 퍼셉트론은 **신경망을 사용**하는 모델. (다층으로 구성되며 시그모이드 함수 등의 **섬세**한 활성화 함수를 사용하는 네트워크)

이제 이 활성화 함수들에 대해 공부해야 한다. 정말 어렵다 

## [+] Reference

1. <a href="http://www.hanbit.co.kr/store/books/look.php?p_code=B8475831198">*"밑바닥부터 시작하는 딥러닝"*</a>
2. <a href="https://en.wikipedia.org/wiki/Artificial_neural_network">*"Wikipedia_Neural_Network"*</a>
3. <a href="https://en.wikipedia.org/wiki/Perceptron">*"Wikipedia_Perceptron"*</a>

