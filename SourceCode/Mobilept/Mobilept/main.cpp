#pragma once
#include <iostream>
#include "android.h"
#include "ios.h"

using namespace std;

void logo()
{
	cout << " ========================================" << endl;
	cout << "|    ______        __    _____       ___ |" << endl;
	cout << "|   / ____/__  __ / /_  |__  / _____<  / |" << endl;
	cout << "|  / /    / / / // __ \\  /_ < / ___// /  |" << endl;
	cout << "| / /___ / /_/ // /_/ /___/ // /   / /   |" << endl;
	cout << "| \\____/ \\__, //_.___//____//_/   /_/    |" << endl;
	cout << "|       /____/                           |" << endl;
	cout << "|                                        |" << endl;
	cout << "| Made by Shh0ya                         |" << endl;
	cout << " ========================================" << endl;
	cout << endl;
}

/* Only select */
void PrintMenu()
{

	cout << "[1] Android " << endl;
	cout << "[2] iOS " << endl;
	cout << "[3] Exit" << endl;
}

int main(void)
{
	int select;
	Android a;
	iOS o;
	while (1)
	{
		system("cls");
		logo();
		PrintMenu();
		cout << "\n[*] Select Menu: "; cin >> select;
		switch (select)
		{
		case 1:
			system("cls");
			logo();
			a.Android_s();
			break;
			
		case 2:
			system("cls");
			logo();
			o.iOS_s();
			break;

		case 3:
			cout << "Thank you ;)" << endl;
			//system("pause");
			return 0;

		default:
			cout << "[!] INPUT ERROR, Check input number!" << endl;
			system("pause");
			return 0;

		}

	}
}
