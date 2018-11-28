---
layout: article
title: "[Dev]Web Scraping(BeautifulSoup)"
key: 20180730
tags:
  - Dev
  - Python
  - ML
sidebar:
  nav: sidem
toc: true
mathjax: true
mathjax_autoNumber: true
published : true
---

# [+] Web Scraping

<!--more-->

## [+] BeautifulSoup Module

### Basic

음..뭐 파이썬 공부도 할겸.. 쓸데가 많으니.............
간단하게 BeautifulSoup 에 대해 소개하자면, 해당 모듈을 이용해 간단하게 HTML, XML 에서 정보 추출이 가능하다. 

### Install

설치는 매우 간단하다.

`pip install beautifulsoup4`

끗..;



### Test Code

테스트 코드는 다음과 같다.

```python
#-*-coding:utf-8-*-
from bs4 import BeautifulSoup
"""import sys
reload(sys)
sys.setdefaultencoding('utf8')
"""
html="""
<html><body>
    <h1>웹 스크레이핑 테스트</h1>
    <p>P 태그 내용</p>
    <p>P2 태그 내용</p>
</body></html>
"""

soup=BeautifulSoup(html,'html.parser')

h1=soup.html.body.h1
p1=soup.html.body.p
p2=p1.next_sibling.next_sibling

print "h1= "+h1.string
print "p= "+p1.string
print "p= "+p2.string

```

위의 코드는 python2.7 에서 사용한 코드이다.

```python
"""import sys
reload(sys)
sys.setdefaultencoding('utf8')
"""
```

이 부분은 간혹 인코딩 에러가 날 수 있다.
`UnicodeEncodeError: 'ascii' codec can't encode characters in position 4-10: ordinal not in range(128)` 

위와 같은 에러코드인데 이럴 경우 기본 인코딩을 utf8로 설정해주어 잘 출력되게 할 수 있다. 해당 코드를 실행하면 다음과 같은 결과를 받을 수 있다.

```console
h1= 웹 스크레이핑 테스트
p= P 태그 내용
p= p2 태그 내용
```



**To be Continue...**