#include <iostream>
#include <stdio.h>
#include "InitSock.h"

#define _WINSOCK_DEPRECATED_NO_WARNINGS

using namespace std;

CInitSock initSock;     // 初始化Winsock库

int main()
{
	SOCKET s = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (s == INVALID_SOCKET)
	{
		cout << " Failed socket!" << endl;
		return 0;
	}

	// 填写远程地址信息
	sockaddr_in servAddr;
	servAddr.sin_family = AF_INET;
	servAddr.sin_port = htons(4567);
	servAddr.sin_addr.S_un.S_addr = inet_addr("127.0.0.1");

	if (connect(s, (sockaddr*)&servAddr, sizeof(servAddr)) == -1)
	{
		cout << " Failed connect!" << endl;
		return 0;
	}

	char buff[128];
	char szText[128];

	while (TRUE)
	{
		//初始化字符串
		for (int i = 0; i < 128; i++)
		{
			buff[i] = ' ';
			szText[i] = ' ';
		}

		//从服务器端接收数据
		int nRecv = ::recv(s, buff, 128, 0);
		if (nRecv > 0)
		{
			buff[nRecv] = '#';
			if (buff[0] == 'Q'&&buff[1] == 'U'&&buff[2] == 'I'&&buff[3] == 'T')
			{
				cout << "服务器端请求断开连接！服务器端已关闭！" << endl;
				closesocket(s);
				return 0;
			}
			cout << "接收到数据：";
			int temp = 0;
			while (buff[temp] != '#')
			{
				cout << buff[temp];
				temp++;
			}
			cout << endl;
		}

		// 向服务器端发送数据
		cout << "请输入你想输入的数据：";
		gets_s(szText, 128);
		if (szText[0] == 'Q'&&szText[1] == 'U'&&szText[2] == 'I'&&szText[3] == 'T')
		{
			cout << "客户端请求断开连接！客户端关闭！" << endl;
			send(s, szText, strlen(szText), 0);
			closesocket(s);
			return 0;
		}
		send(s, szText, strlen(szText), 0);
	}

	// 关闭套节字
	closesocket(s);
	return 0;
}