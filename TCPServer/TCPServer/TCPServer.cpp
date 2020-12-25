#include <iostream>
#include"InitSock.h"
#include <stdio.h>

using namespace std;

CInitSock initsock;

int main()
{
	SOCKET sListen = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);		//创建socket
	if (sListen == INVALID_SOCKET)
	{
		cout << "Failed socket!" << endl;
		return 0;
	}

	sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(4567);
	sin.sin_addr.S_un.S_addr = INADDR_ANY;

	if (bind(sListen, (LPSOCKADDR)&sin, sizeof(sin)) == SOCKET_ERROR)
	{
		cout << "Failed bind!" << endl;
		return 0;
	}

	if (listen(sListen, 2) == SOCKET_ERROR)
	{
		printf("Failed listen() /n");
		return 0;
	}

	sockaddr_in remoteAddr;
	int nAddrLen = sizeof(remoteAddr);
	SOCKET sClient = 0;
	while (sClient == 0)
	{
		// 接受一个新连接
		sClient = accept(sListen, (SOCKADDR*)&remoteAddr, &nAddrLen);
		if (sClient == INVALID_SOCKET)
		{
			cout << "Failed accept!" << endl;
		}
		cout << "接收到一个新连接：" << inet_ntoa(remoteAddr.sin_addr) << endl;
		continue;
	}

	while (TRUE)
	{
		//初始化字符串
		char szText[128];
		char buff[128];
		for (int i = 0; i < 128; i++)
		{
			buff[i] = ' ';
			szText[i] = ' ';
		}

		// 向客户端发送数据
		cout << "请输入想发送的数据：";
		gets_s(szText, 128);
		if (szText[0] == 'Q'&&szText[1] == 'U'&&szText[2] == 'I'&&szText[3] == 'T')
		{
			cout << "服务器端请求断开连接！服务器端已关闭！" << endl;
			send(sClient, szText, strlen(szText), 0);
			closesocket(sClient);
			closesocket(sListen);
			return 0;
		}
		send(sClient, szText, strlen(szText), 0);

		// 从客户端接收数据
		int nRecv = recv(sClient, buff, 128, 0);
		if (nRecv > 0)
		{
			buff[nRecv] = '#';
			if (buff[0] == 'Q'&&buff[1] == 'U'&&buff[2] == 'I'&&buff[3] == 'T')
			{
				cout << "客户端请求断开连接！客户端已关闭！" << endl;
				closesocket(sClient);
				closesocket(sListen);
				return 0;
			}
			cout << "接收到数据："; \
				int temp = 0;
			while (buff[temp] != '#')
			{
				cout << buff[temp];
				temp++;
			}
			cout << endl;
		}
	}
	closesocket(sClient);
	closesocket(sListen);
	return 0;
}