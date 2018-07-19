#pragma once
#include <iostream>
#include "ios.h"
using namespace std;

/* iOS App decrypt, download and Data extraction */

void iOS::iOSMenu()
{
	//cout << endl;
	cout << "[1] iOS App decrypt & Download" << endl;
	cout << "[2] App Data Download " << endl;
	cout << "[3] Back" << endl;
	cout << "[4] Exit" << endl;
}

void iOS::iOS_s()
{

	int select;
	while (1)
	{
		iOSMenu();
		cout << "\n[*] Select Menu: "; cin >> select;
		switch (select)
		{
		case 1:
			Decrypt();
			break;

		case 2:
			Data();
			break;

		case 3:
			system("cls");
			return;

		case 4:
			cout << "Thank you ;)" << endl;
			//system("pause");
			exit(0);

		default:
			cout << "[!] INPUT ERROR, Check input number!" << endl;
			return;
		}

	}

}


void iOS::Decrypt()
{
	cout << "Decrypt() Call" << endl;

}

void iOS::Data()
{
	cout << "Data() Call" << endl;
}