#include <iostream>
using namespace std;

class Point
{
	int x, y;

public:
	Point()
	{
		cout << "Point() Call" << endl;
		x = y = 0;
	}
	Point(int _x, int _y)
	{
		x = _x;
		y = _y;
	}

	int GetX() { return x; }
	int GetY() { return y; }
	void SetX(int _x) { x = _x; }
	void SetY(int _y) { y = _y; }
};

int main()
{
	Point arr[5];

	for (int i = 0; i < 5;i++)
	{
		arr[i].SetX(i * 2);
		arr[i].SetY(i * 3);
	}

	for (int j = 0; j < 5; j++)
	{
		cout << "x: " << arr[j].GetX() << " ";
		cout << "y: " << arr[j].GetY() << endl;
	}
	return 0;
}
