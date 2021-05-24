---
title: I/O Request Packet
keywords: documentation, technique, reversing, kernel, windows
date: 2021-05-24
tags: [Windows, Reversing, Kernel]
summary: "I/O Request Packet"
sidebar: windows_sidebar
permalink: windows_irp.html
folder: windows

---

## [0x00] Concept

I/O 시스템이 I/O 요청을 처리할 때 필요한 정보를 저장하는 하나의 패킷 구조라고 할 수 있습니다.

가능하면 I/O Manger 는 프로세서 당 존재하는 3개의 IRP Nonpaged lookaside list 중 하나에서 IRP를 할당합니다.

`Lookaside List` 는 빠른 메모리 할당을 위해 사용되며 메모리 관리를 위한 메커니즘 입니다. 풀과 다른 점은 고정된 크기만 할당할 수 있다는 점입니다. 그렇기에 풀은 유연하게 사용이 가능한 장점이 있다면, `Lookaside List` 는 `SpinLock` 을 사용하지 않기 때문에 더 빠릅니다.

위에서 말한 3개의 `Lookaside List` 는 사이즈 별로 `Stack Location` 의 개수가 다릅니다.

- Small IRP Lookaside List : 하나의 스택 로케이션을 갖는 IRP 저장
- Medium IRP Lookaside List : 4개(2 ~ 4)의 스택 로케이션을 갖는 IRP
- Large IRP Lookaside List : 4개 보다 많은 스택 로케이션을 갖는 IRP(최대 20개)

20개 이상의 스택 로케이션이 필요한 경우에는 Non-Paged pool 에서 IRP를 할당합니다.

`Windows internals` 에서는 위와 같이 설명하고 있습니다. 다만 이 부분을 이해하기 위해서는 Windows의 I/O 메커니즘을 이해해야 했습니다.

이 포스팅은 `IRP` 에 대한 간략한 설명보단 전체적인 I/O 흐름에 대한 내용입니다.

## [0x01] Device Stack

`Device Stack` 은 `DeviceObject` 와 `Driver` 의 정렬 된 목록이라고 볼 수 있습니다.(`DeviceObject` 는 하나의 `DriverObject` 에서 여러 개를 가질 수 있습니다.)

일반적으로 `Device Stack` 은 첫 번째로 생성 될 `DeviceObject` 는 가장 아래에 존재하고, `Device Stack` 에 생성되고 연결 될 마지막 `DeviceObject` 는 상단에 위치 합니다.

아래 그림은 각 디바이스 노드에 존재하는 `Device Stack` 을 표현한 그림입니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/irp_00.png?raw=true">

## [0x02] Driver Stack

디바이스 드라이버로 전송되는 대부분의 요청은 IRP 로 패키징 되어 IRP의 정보를 기반으로 요청을 처리합니다. 이러한 디바이스는 `Device Node` 로 표현할 수 있고, `Device Stack(1개 이상)` 이 존재합니다.

일반적으로 디바이스에 `Read/Write/Control` 요청을 보내면 이 요청을 `IRP` 로 패키징하고, I/O Manager 는 `Device Node` 를 찾고 해당 `Device Stack` 에 `IRP` 를 전달합니다.

이 때 이러한 `Device Stack` 의 개수와 관계없이 `I/O Request` 에 관여하는 모든 드라이버 시퀀스 또는 조합을 `Driver Stack` 이란 개념으로 설명합니다.

※ `Device Stack` , `Driver Stack` 은 다른 개념입니다. 매우 중요합니다.

먼저 `Driver Stack` 의 개념을 설명하기 위해 여러 `Device Stack` 에서의 I/O 요청을 살펴보겠습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/irp_01.png?raw=true">

1. `IRP` 가 "My USB Storage Device" 라는 노드의 `Device Stack` 에 있는 `FDO(Function Device Object)` 인 "Disk.sys" 에 의해 생성 됩니다. 그리고 "Disk.sys" 는 생성된 `IRP` 를 `Device Stack` 하단의 "Usbstor.sys" 로 전달합니다.
2. "Usbstor.sys" 는 "My USB Storage Device" 노드의 `PDO(Physical Device Object)` 이며, 동시에 "USB Mass Storage Device" 노드의 `FDO` 입니다. 이 시점에서 `IRP` 는 "Usbstor.sys"가 소유하고 있으며 `PDO` , `FDO` 모두 접근이 가능합니다.
3. "Usbstor.sys" 가 IRP에 대한 처리가 끝나면 마찬가지로 하위에 `PDO` 드라이버 인 "Usbhub.sys"로 `IRP` 를 전달합니다.
4. "Usbhub.sys"도 마찬가지로 하위의 "Usbuhci.sys(Miniport), Usbport.sys(Port)" 로 IRP를 전달합니다. 이제 해당 드라이버들은 "USB Host Controller" 하드웨어와 실제 통신을 수행하며 물리적 USB 스토리지 디바이스와 통신하게 됩니다.

드라이버 간의 `IRP` 전달은 `IoCallDriver` 라는 매크로 함수에 의해 동작합니다.

위의 그림을 설명한 4 가지 수행 단계를 통해 `Driver Stack` 을 설명합니다.

2번 순서에서 설명(3,4 에서는 생략함)이 매우 중요한 단서가 됩니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/irp_02.png?raw=true">

"Disk.sys" 드라이버는 하나의 디바이스 오브젝트(`FDO`)와 연결되어 있습니다.

그러나 나머지 세 개의 드라이버들은 각 두 개의 디바이스 오브젝트와 연결되어 있는 것을 확인할 수 있습니다.

이와 같이 I/O Request 에 참여하는 드라이버 순서를 I/O 요청에 대한 `Driver Stack` 이라고 합니다.

즉 어떠한 장치에 사용되는 드라이버들의 체인을 `Driver Stack` 이란 개념으로 설명됩니다.

## [0x03] I/O Stack Location

`IRP` 는 패킷이라는 이름에 맞게 헤더와 바디 부분으로 나뉘는데 각각 불리는 이름은 다릅니다. 다만 고정된 헤더가 존재하고 이에 따른 `Stack Location`(1개 이상) 으로 구성되어 있다는 점은 변하지 않습니다.

헤더에는 요청의 유형과 요청의 크기, 요청이 동기, 비동기적인지에 대한 내용과 `Buffered I/O` 에 대한 포인터, 요청이 진행되며 변경되는 상태 정보 등을 담고 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/irp_03.png?raw=true">

`Stack Location` 은 Major, Minor(`IRP_MJ_XXXX`) 함수 코드와 함수의 인자, 호출자의 `FileObject` 등을 담고 있습니다. 즉 실제로 드라이버에서는 해당 스택의 위치를 이용하여 어떤 루틴을 호출해야 하는지 결정합니다.(`IRP_MJ_XXXX`)

이 때 사용되는 함수가 `IoGetCurrentIrpStackLocation` 이고, `Driver Stack` 에서 다음 드라이버 체인으로 연결 될 때 `IoGetNextIrpStackLocation` 함수를 통해 다음 드라이버의 스택 위치를 결정합니다. 또한 `Stack Location` 에는 특정 조건(`InvokeOnSuccess, InvokeOnError, InvokeOnCancel`) 에 따라 `Completion Routine` 을 설정할 수 있습니다. 이 때 사용되는 함수가 `IoSetCompletionRoutine` 입니다. `IRP` 처리 가 완료된 후 해당 조건에 따라 `Completion Routine` 을 통해 별도의 작업이 가능합니다.

## [0x04] I/O Request

위의 내용들을 이해했다면 I/O 요청에 대한 대략적인 부분을 이해할 수 있습니다.

먼저 `MSDN` 내 공식 문서에 존재하는 `I/O Request Example` 을 통해 학습하겠습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/irp_04.png?raw=true">

현재 그림을 보면 5번과 7번 사이에 존재하는 드라이버 체인을 볼 수 있습니다.

순서대로 설명하면 아래와 같습니다.

1. 하위 시스템에서 파일 오브젝트에 대한 `OPEN`(Create) 을 요청합니다.
2. I/O Manager 는 Object Manager 를 호출하여 `OPEN` 을 요청한 오브젝트의 이름을 찾고(`Symbolic Link`) `Reference Monitor` 를 호출하여 접근 권한을 확인합니다.
3. 해당 과정은 볼륨이 마운트 되지 않았다는 설정으로 볼륨이 마운트 될 때까지 일시 중단하고 루프 진입을 의미합니다.
4. I/O Manager 는 `OPEN` 요청에 대해 `IRP` 를 생성 및 초기화합니다.
5. I/O Manager 는 file system driver 를 호출하여(`IoCallDriver`) 생성 된 `IRP` 를 전달합니다.
   - 이 때 file system driver 는 `Stack Location` 에 접근하여 어떤 작업을 수행해야 하는지 결정하고, 매개변수, 캐싱 여부 확인을 진행합니다. 캐시에 존재하지 않는 경우 `IRP` 에서 드라이버 체인 내 하위 드라이버(`Driver Stack, Device Stack`)를 호출(`IoCallDriver`)하고 `IRP`의 `Stack Location`(Current Location) 이 변경됩니다.
6. 두 드라이버(file system driver, device driver)는 `IRP` 를 처리하고 요청된 I/O 작업을 완료합니다.
7. I/O Manager 는 처리에 대한 I/O 상태 값을 반환받습니다.
8. I/O 관리자는 IRP에서 I/O 상태를 가져와 하위 시스템을 통해 호출자에게 상태 정보를 반환합니다.
9. I/O 관리자는 사용이 완료된 IRP를 메모리에서 해제합니다.
10. I/O 관리자는 성공 여부에 따라 핸들을 반환하거나 `NTSTATUS` 값과 같은 상태 값을 반환합니다.

## [0x05] Conclusion

간략하게 `IRP` 는 I/O Manager 가 요청에 대한 정보를 담은 `IRP` 를 생성하고 이를 드라이버에 전달하고 처리합니다.

이 과정이 조금 상세하게 보면 위와 같이 `Device Stack` 과 `Driver Stack`  개념이 존재하고, `IRP` 가 `Device Stack` 내 `Device Object` 와 연결된 `Driver Object` 에서 현재의 `Stack Location` 에서 처리해야 할 작업을 처리하며 진행되는 것을 알 수 있습니다.

추가적으로 `CompletionRoutine` 에 대해 알 수 있었습니다.

## [0x06] Reference

1. [MSDN I/O](https://docs.microsoft.com/en-us/windows-hardware/drivers/kernel/handling-irps)
2. [MSDN Driver Stacks](https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/driver-stacks)
3. [MSDN Device nodes & device stacks](https://docs.microsoft.com/en-us/windows-hardware/drivers/gettingstarted/device-nodes-and-device-stacks)

