#pragma once
#include <iostream>
using namespace std;

class NameCard
{
	char *name;
	char *phone;
	char *addr;
	char *level;

public:

	NameCard(char*, char*, char*, char*);
	~NameCard();
	void ShowData();
	
};

NameCard::~NameCard()
{
	delete[]name;
	delete[]phone;
	delete[]addr;
	delete[]level;

}

NameCard::NameCard(char *_name, char *_phone, char *_addr, char *_level)
{
	name = new char[strlen(_name) + 1];
	strcpy(name, _name);
	phone = new char[strlen(_phone) + 1];
	strcpy(phone, _phone);
	addr = new char[strlen(_addr) + 1];
	strcpy(addr, _addr);
	level = new char[strlen(_level) + 1];
	strcpy(level, _level);
}

void NameCard::ShowData()
{
	cout << "=====================================================" << endl;
	cout << "이름 : " << name << "\n" << "전화 : " << phone << "\n" << "주소 : " << addr << "\n" << "등급 : " << level << endl;
}

 