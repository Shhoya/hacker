#include <iostream>
#include "NameCard.h"
using namespace std;

const int SIZE = 20;

int main(void)
{
	NameCard *n[3];
	char name[SIZE];
	char phone[SIZE];
	char addr[SIZE];
	char level[SIZE];

	for (int i = 0; i < 3; i++)
	{

		cout << "=========================입력========================" << endl;
		cout << "이름 : "; cin >> name;
		cout << "전화 : "; cin >> phone;
		cout << "주소 : "; cin >> addr;
		cout << "등급 : "; cin >> level;

		n[i] = new NameCard(name, phone, addr, level);
		if (i == 2)
		{
			cout << "\n====================데이터출력=======================" << endl;
		}
	}

	for (int j = 0; j < 3; j++)
	{
		n[j]->ShowData();
	}
}