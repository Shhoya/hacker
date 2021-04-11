---
title: Unreal Engine 4 SDK Generator
keywords: documentation, technique, reversing, unreal, game
date: 2021-04-10
tags: [Reversing, Dev]
summary: "Unreal Engine SDK Generator"
sidebar: unreal_sidebar
permalink: ue_generator.html
folder: unreal
---

## [0x00] Overview

UE 4.26.1, 4.25.4 에서 정상 동작을 확인하였습니다. 해당 챕터에서는 SDK를 어떻게 생성하는지 간략한 정리와 예제 소스코드가 포함됩니다.

해당 소스코드는 [여기](https://github.com/Shhoya/Shh0yaUEDumper) 에서 확인할 수 있습니다.

## [0x01] How to generate SDK

이전 챕터와 관련이 깊으므로, `Object Dump` 에 대해 실습 후에 해당 챕터를 읽을 것을 추천합니다.

먼저 제가 이해한 언리얼에서 중요한 오브젝트의 구성은 다음과 같습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/ue_05.png?raw=true">

현재 가장 많이 사용되는 게임 엔진 중 하나인 만큼 구체적이고, 단계적으로 오브젝트에 대한 설계가 잘 되어 있습니다. 지난 챕터에서 `Object Dump` 를 통해 게임에서 사용되고 있는 오브젝트를 모두 구할 수 있었습니다.

SDK 생성, 즉 언리얼 엔진에서 각 오브젝트에 할당 된 정보를 소스코드화 하기 위해서는 최하위 오브젝트 내 정보들을 이용해야 합니다.

이 때 사용되는 함수가 잘 알려진 `IsA` 입니다. 입력된 값이 특정한 데이터 타입인지 확인하는 것으로 알려져 있습니다.

```c++
template<typename T> bool UObject::IsA();
```

해당 함수는 내부적으로 지정된(`T`) `StaticClass` 함수를 호출합니다. 패키지 오브젝트를 확인하기 위해 `GObjObjects` 내 오브젝트를 순회하여 특정 오브젝트 전체 이름을 찾고 이를 반환하면, 최하위 오브젝트의 `SuperStruct`를 순회하고 클래스(`ClassPrivate`) 의 이름과 비교합니다. 

다음은 위에서 말한 내용의 구현입니다.

```c++
UObject* UObject::GetClass()
{
	return Read<UObject*>(&ClassPrivate);
}

UObject* UStruct::GetSuper()
{
	return Read<UObject*>(&SuperStruct);
}

bool UObject::IsA(UObject* CompareObject)
{
	UClass* super = reinterpret_cast<UClass*>(GetClass());
	while (true)
	{
		if (super == CompareObject)
		{
			return true;
		}
		super = reinterpret_cast<UClass*>(super->GetSuper());
		if (!super) { break; }
	}
	return false;
}

UObject* UStruct::StaticClass()
{
	static auto obj = static_cast<UObject*>(ObjObjects.FindObject("Class CoreUObject.Struct"));
	return obj;
}

template<typename T>
bool UObject::IsA()
{
	auto CompareObject = T::StaticClass();
	if (!CompareObject) { return false; }
	return IsA(CompareObject);
}
```

위와 같은 코드를 이용하여, 각 **패키지 별 오브젝트를 분류**하는 작업이 SDK를 생성하기 전 가장 먼저 해야 하는 작업입니다. 이 작업을 이해하고 나면 오히려 SDK 생성의 구현은 단순히 긴 작업이란 걸 알 수 있습니다.

예제 코드에서 출력 등을 통해 실제 오브젝트의 구성과 설명한 내용을 비교하며 보는 것을 권장합니다.

```c++
...
if (Object->IsA<UStruct>() || Object->IsA<UEnum>())
{
	auto PackObj = Object->GetPackageObject();
	PackageObject[PackObj].push_back(Object);		
}
...
```

위의 코드는 `std::unordered_map` 을 이용하여 패키지 오브젝트 별 오브젝트를 저장하는 코드입니다. SDK 생성은 기본적으로 클래스(클래스 멤버 및 함수), 구조체, 열거에 대한 정보를 추출합니다. 

```c++
class UStruct : public UField
{
private:
	BYTE UnknownValue[0x10];
	PVOID SuperStruct;
	PVOID Children;
	FField* ChildProperties;
	DWORD PropertySize;
	DWORD MinAlignment;
	TArray Script;
	FProperty* PropertyLink;
	FProperty* RefLink;
	FProperty* DestructorLink;
	FProperty* PostConstructLink;
	TArray* ScriptAndPropertyObjectReferences;
	PVOID UnresolvedScriptProperties;
	TArray* PropertyWrappers;
	DWORD FieldPathSerialNumber;
public:
	using UField::UField;
	UObject* GetSuper();
	DWORD GetSize();
	FProperty* GetChildProperty();
	UField* GetChild();

	static UObject* StaticClass();
};

UObject* UStruct::GetSuper()
{
	return Read<UObject*>(&SuperStruct);
}

DWORD UStruct::GetSize()
{
	return Read<DWORD>(&PropertySize);
}

FProperty* UStruct::GetChildProperty()
{
	return Read<FProperty*>(&ChildProperties);
}

UField* UStruct::GetChild()
{
	return Read<UField*>(&Children);
}

UObject* UStruct::StaticClass()
{
	static auto obj = static_cast<UObject*>(ObjObjects.FindObject("Class CoreUObject.Struct"));
	return obj;
}
```

위의 코드는 `UStruct` 의 클래스 멤버와 SDK를 생성하기 위해 작성된 멤버 함수들 입니다. `UStruct::SuperStruct` , `UStruct::Children` , `UStruct::ChildProperties` 는 SDK를 생성하기 위한 필수적인 요소이며, `PropertySize` 의 경우 선택된 클래스 또는 구조체의 크기와 `SuperStruct` 의 사이즈의 경우 상속받는 만큼의 크기를 의미하므로, 분석에 매우 도움이 되는 멤버 변수입니다.

다음으로 중요한 내용은 `FProperty` 클래스와 상위의 `FField` 클래스 입니다. 

```c++
class FFieldVariant
{
public:
	union FFieldObjectUnion
	{
		FField* Field;
		PVOID Object;
	} Container;

	bool bIsUObject;
};

class FFieldClass
{
private:
	FName Name;
	DWORD64 Id;
	DWORD64 CastFlags;
	FFieldClass* SuperClass;
	FField* DefaultObject;
public:
	FName GetNameInfo();
};

class FField
{
private:
	PVOID VTable;
	FFieldClass* ClassPrivate;
	FFieldVariant Owner;
	FField* Next;
	FName NamePrivate;
	EObjectFlags FlagsPrivate;

public:
	FField* GetNext();
	FFieldClass* GetClass();
	std::string GetName();
};

class FProperty : public FField
{
private:
	DWORD ArrayDim;
	DWORD ElementSize;
	EPropertyFlags PropertyFlags;
	USHORT RepIndex;
	USHORT BlueprintReplicationCondition;
	DWORD Offset_internal;
	FName RepNotifyFunc;
	FProperty* PropertyLinkNext;
	FProperty* NextRef;
	FProperty* DestructorLinkNext;
	FProperty* PostConstructLinkNext;

public:
	using FField::FField;
	
	DWORD GetSize();
	DWORD GetArrayDim();
	DWORD GetOffset();
	DWORD64 GetPropertyFlags();
	std::pair<PropertyType, std::string> GetType();
};
```

기존의 `UObject` 를 상속받았던 오브젝트들과는 조금 다른 그림을 확인할 수 있습니다.

<img src="https://github.com/Shhoya/shhoya.github.io/blob/master/rsrc/windows/ue_06.png?raw=true">

위와 같은 구조를 가지고 있습니다. 멤버 변수들에 대한 정보는 `ChildProperties` 에서 찾을 수 있습니다. `FProperty::ArrayDim`, `FProperty::ElementSize`, `FProperty::Offset_internal` 등의 멤버를 이용하면 정확한 사이즈까지 계산이 가능합니다.

위의 내용들을 토대로 SDK를 생성하면 아래와 같은 소스코드를 확인할 수 있습니다.

```c++
// Class Engine.GameStateBase
// Size : 0x270 (Inherited : 0x220)
struct AGameStateBase : AInfo {
	class AGameModeBase* GameModeClass; // 0x220(0x8)
	struct AGameModeBase* AuthorityGameMode; // 0x228(0x8)
	class ASpectatorPawn* SpectatorClass; // 0x230(0x8)
	struct TArray<struct APlayerState*> PlayerArray; // 0x238(0x10)
	bool bReplicatedHasBegunPlay; // 0x248(0x1)
	unsigned char UnknownData_249[0x0003]; // 0x249(0x3)
	float ReplicatedWorldTimeSeconds; // 0x24C(0x4)
	float ServerWorldTimeSecondsDelta; // 0x250(0x4)
	float ServerWorldTimeSecondsUpdateFrequency; // 0x254(0x4)
	unsigned char UnknownData_258[0x0018]; // 0x258(0x18)

	void OnRep_SpectatorClass(); // Function Engine.GameStateBase.OnRep_SpectatorClass // (Native|Protected) // Param Size : 0x0, 0x7FF7768838B0
	void OnRep_ReplicatedWorldTimeSeconds(); // Function Engine.GameStateBase.OnRep_ReplicatedWorldTimeSeconds // (Native|Protected) // Param Size : 0x0, 0x7FF776883890
	void OnRep_ReplicatedHasBegunPlay(); // Function Engine.GameStateBase.OnRep_ReplicatedHasBegunPlay // (Native|Protected) // Param Size : 0x0, 0x7FF776883870
	void OnRep_GameModeClass(); // Function Engine.GameStateBase.OnRep_GameModeClass // (Native|Protected) // Param Size : 0x0, 0x7FF77685CCE0
```



## [0x02] Conclusion

이번 챕터에서 가장 하고 싶었던 이야기는 "직접 확인하고 증명해봐야 한다." 입니다. 위에서 얘기한대로 각각의 오브젝트를 직접 확인하고 멤버들에 대한 용도에 대한 이해가 끝 입니다. SDK 생성 시에는 이러한 데이터를 가지고 파싱하는게 끝이라고 볼 수 있습니다.

아래 참조에서 참조한 소스코드를 확인할 수 있으며, 이를 이용해 작성한 코드는 깃헙에서 확인할 수 있습니다.



## [0x03] Reference

1. [Guided Hacking](https://guidedhacking.com)
2. [Feckless SDK Generator](https://www.unknowncheats.me/forum/unreal-engine-3-a/71911-thefeckless-ue3-sdk-generator.html)
3. [UEDumper-4.25](https://github.com/guttir14/UnrealDumper-4.25)