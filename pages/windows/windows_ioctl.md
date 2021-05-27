---
title: I/O Control Code
keywords: documentation, technique, reversing, kernel, windows
date: 2021-05-27
tags: [Windows, Reversing, Kernel]
summary: "I/O Control Code"
sidebar: windows_sidebar
permalink: windows_ioctl.html
folder: windows
---

## [0x00] Concept

I/O Control Code(IOCTLs) 는 유저모드 애플리케이션과 드라이버 간의 통신 또는 드라이버 스택 내 드라이버 간의 내부 통신에 사용됩니다. I/O Control Code 는 `IRP` 를 이용하여 전송됩니다.

유저모드 애플리케이션은 `DeviceIoControl` 이라는 함수를 호출하여 `IOCTL` 을 드라이버로 전송합니다. I/O Manager 가 `IRP` 의 스택 로케이션에 `IRP_MJ_DEVICE_CONTROL` 요청을 만들고 디바이스 스택 내 최상단 드라이버로 전송하게 됩니다.

위의 설명은 `MSDN` 에 설명되어 있습니다. 또한 해당 내용에서 사용되는 드라이버 스택, 디바이스 스택, 스택 로케이션 등은 해당 블로그 내 `IRP` 챕터에서 확인할 수 있습니다.

## [0x01] I/O Control Code

I/O Control Code는 32비트로 아래와 같은 레이아웃을 지니고 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/ioctl_00.png?raw=true">

`wdm.h` , `ntddk.h` 에 정의 된 `CTL_CODE` 매크로로 새로운 IOCTL 코드를 정의할 수 있습니다.

```cpp
#define IOCTL_Device_Function CTL_CODE(DeviceType, Function, Method, Access)
```

`IOCTL_Device_Function` 은 이름에 대한 규칙으로 `IOCTL_Audio_VolumeControl` 같은 식으로 표현할 수 있습니다.

- DeviceType
  - 해당 값은 드라이버의 디바이스 오브젝트의 `DeviceType` 의 값과 일치해야 합니다.(0x8000 보다 높은 값을 사용해야 하며 이보다 작은 값은 MS에서 예약 된 값으로 사용됩니다.
- FunctionCode(Function)
  - 수행 할 기능에 대한 식별 값입니다. 0x800 미만은 MS의 예약 값이며 0x800 이상의 값을 사용해야 합니다.
- TransferType(Method)
  - 드라이버 호출자와 드라이버 간의 데이터를 전달하는 방법에 대한 식별 값입니다.
    - METHOD_BUFFERED : 시스템 버퍼를 이용
    - METHOD_IN_DIRECT, OUT_DIRECT :  `MDL` 을 이용
    - METHOD_NEITHER : 유저모드 버퍼의 VA 를 전달
- Access(RequiredAccess)
  - I/O Manager는 IRP를 만들고 호출자가 지정된 권한을 요청한 경우에만 해당하는 IOCTL 코드로 드라이버를 호출합니다.
    - FILE_ANY_ACCESS, READ_DATA, WRITE_DATA

## [0x02] Reference

1. [MSDN I/O Control Code](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/introduction-to-i-o-control-codes)