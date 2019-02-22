---
layout: article
title: "[Mobile]Frida Android Hooking"
key: 20180604
tags:
  - Security
  - Mobile
toc: true
mathjax: true
mathjax_autoNumber: true
---

# [+] Frida Android Hooking

<!--more-->

## [+] Android Hooking

### Analyze

종종 루팅된 단말기에서 앱 실행이 되지 않는 경우가 있다. 루팅 탐지로 인해 실행이 불가능한 현상인데, 정적분석을 통해 smali 코드 변조도 있고 방법은 여러가지가 있다.

그 중 Frida 를 이용해 특정 함수에 후킹을 걸어 루팅 탐지를 우회하는 방법을 분석해본다.
먼저 대상이 될 앱을 분석해야 한다.

```java
public static void a(Activity arg3){
    ...
    boolean v2;
    try {
        Runtime.getRuntime().exec("su");
        v2=true;
    }
    catch(Exception){
        v2=false;
    }
    ...
}

public static boolean a(...){
    ...
    ...
     
}
```

특정 문자나 문자열을 찾아 루팅 탐지 로직을 찾아보니 위와 같은 코드로 되어있다 치자.

아주 간단하게 smali 코드를 변조하여 v2를 false 처리해주면 우회될 일이다. 하지만 앱의 무결성을 검증하는 로직이 매우 복잡하게 이뤄져있다면, 변조하여도 실행하기가 빡시다.

이럴 때 아주 유용하다...



### JS Code



```java
function Hooking() {
	console.log("[*] Hook Start");
	
	Java.perform(function(){
		var Check_Root = Java.use("com.qwerty.qwer.qw.q"); //후킹할 클래스
		Check_Root.a.overload('android.app.Activity').implementation = function(v){	
             console.log("[*] Success");
			return false;
		} //후킹할 클래스에 존재하는 a()메소드의 리턴 값을 false, 하나 이상의 a() 메소드가 존재하므로 overload()를 통해 특정 메소드를 선택
		})
};


setImmediate(function() {
	Hooking();
});
```

위와 같이 js 파일을 미리 짜놓고 frida를 이용해 값을 변조할 수 있다.





### Usage



**단말기**

```shell
Android_Shhoya:/ #frida-server
```



**PentestBox**

```shell
 > frida -l hooking.js -U -f com.~~.~~.hookingapp
     ____
    / _  |   Frida 10.7.7 - A world-class dynamic instrumentation toolkit
   | (_| |
    > _  |   Commands:
   /_/ |_|       help      -> Displays the help system
   . . . .       object?   -> Display information about 'object'
   . . . .       exit/quit -> Exit
   . . . .
   . . . .   More info at http://www.frida.re/docs/home/
Spawned `com.~~.~~.hookingapp`. Use %resume to let the main thread start executing!

[*] Hook Start

[Samsung ~~~::com.~~.~~.hookingapp]-> %resume

[*] Success
```



끄읏...!