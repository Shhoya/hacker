#pragma once
#include <iostream>
#include "android.h"

using namespace std;

/* Android APK Download, Decompile and Data extraction */

void Android::AndroidMenu()
{
	//cout << endl;
	cout << "[1] APK Download & Decompile " << endl;
	cout << "[2] App Data Download " << endl;
	cout << "[3] Back" << endl;
	cout << "[4] Exit" << endl;
}

void Android::Android_s()
{
	int select;
	while (1)
	{
		AndroidMenu();
		cout << "\n[*] Select Menu: "; cin >> select;
		switch (select)
		{
		case 1:
			a_Decompile();
			break;

		case 2:
			a_Data();
			break;

		case 3:
			system("cls");
			return;

		case 4:
			cout << "Thank you ;)" << endl;
			//system("pause");
			exit(0);

		default:
			cout << "\n[!] INPUT ERROR, Check input number!" << endl;
			system("pause");
			exit(0);
			
		}

	}

}

/* APK Download & Decompile */
void Android::a_Decompile()
{
	HINSTANCE shell=ShellExecute(NULL, "find", "adb", NULL, NULL, SW_SHOW);
	string log = "test.txt";

	if (shell==(HINSTANCE)ERROR_FILE_NOT_FOUND)
	{
		cout << endl;
		cout << "[!] Could not found ADB " << endl;
		cout << endl;
		return;
	}

	else
	{
		system("adb devices > ./test.txt");
		ifstream openFile(log.data());
		if (openFile.is_open())
		{
			string line;
			while (getline(openFile, line)) {
				cout << line << endl;
			}
			openFile.close();
		}

		
	}
		

	
}

void Android::a_Data()
{
	cout << "a_Data() Call" << endl;
}