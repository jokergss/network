#include <WinSock2.h>
#include <string.h>
#include <iostream>
#include <stdio.h>
#include <time.h>

using namespace std;

#pragma comment(lib,"ws2_32.lib")

#define SERVER_PORT 8000
#define BUFFER_SIZE 1024
#define FILE_NAME_MAX_SIZE 512

int timeout = 1;

/* 数据报头部 */
typedef struct PackInfo
{
	unsigned short seq;
	unsigned short syn;
	unsigned short ack;
	PackInfo() {
		this->seq = 0;
		this->syn = 0;
		this->ack = 0;
	}
}PackInfo;

/* 数据报 */
typedef struct Packet
{
	PackInfo head;
	unsigned short buf_size;
	unsigned short Checksum;
	time_t send_time;
	bool available;
	char data[BUFFER_SIZE];
	Packet() {
		this->head.seq = 10000;
		this->head.syn = 0;
		this->head.ack = 0;
		this->buf_size = 0;
		this->Checksum = 0;
		this->send_time = 0;
		this->available = true;
		memset(this->data, 0, BUFFER_SIZE);
	}
} Packet;

unsigned short checksum(Packet packet) {
	unsigned long sum = 0;
	sum += packet.head.seq;
	sum += packet.head.ack;
	sum += packet.head.syn;
	sum += packet.buf_size;
	sum += packet.Checksum;

	if (packet.buf_size % 2 == 0) {
		for (int i = 0; i < packet.buf_size; i += 2) {
			sum += (((unsigned short)packet.data[i]) << 8) | (unsigned short)packet.data[i + 1];
			sum = (sum >> 16) + (sum & 0xffff);
		}
	}
	else {
		for (int i = 0; i < packet.buf_size - 1; i += 2) {
			sum += (((unsigned short)packet.data[i]) << 8) | (unsigned short)packet.data[i + 1];
			sum = (sum >> 16) + (sum & 0xffff);
		}
		sum += (((unsigned short)packet.data[packet.buf_size - 1]) << 8);
		sum = (sum >> 16) + (sum & 0xffff);
	}
	if (sum >> 16 != 0)
		sum = (sum >> 16) + (sum & 0xffff);
	return ~sum;
}

SOCKET ShakeHands() {
	WORD wVersionRequested;
	WSAData wsaData;
	wVersionRequested = MAKEWORD(2, 2);
	// 开启服务
	if (WSAStartup(wVersionRequested, &wsaData) != 0) {
		cout << "开启服务失败" << endl;
		exit(1);
	}

	/* 服务端地址 */
	SOCKADDR_IN server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(SERVER_PORT);
	int server_addr_length = sizeof(server_addr);

	/* 创建socket */
	SOCKET client_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (client_socket == -1) {
		cout << "Create Socket Failed:" << endl;
		exit(1);
	}
	srand(time(NULL)); // 产生随机数
	PackInfo serverPackInfo;

	/* 接收建立连接的请求 */
	PackInfo clientPackInfo;
	clientPackInfo.syn = 1;
	clientPackInfo.seq = rand();
	// 发送建立连接的请求
	if (sendto(client_socket, (char*)&clientPackInfo, sizeof(clientPackInfo), 0, (SOCKADDR*)&server_addr, server_addr_length) < 0) {
		cout << "第1次握手，发送建立连接请求失败" << endl;
		exit(1);
	}

	// 接受确认连接
	if (recvfrom(client_socket, (char*)&serverPackInfo, sizeof(serverPackInfo), 0, (SOCKADDR*)&server_addr, &server_addr_length) == -1) {
		cout << "第2次握手，接受确认失败" << endl;
		exit(1);
	}
	if (serverPackInfo.syn == 1 && serverPackInfo.ack == (clientPackInfo.seq + 1)) {
		clientPackInfo.syn = 0;
		clientPackInfo.seq = clientPackInfo.seq + 1;
		clientPackInfo.ack = serverPackInfo.seq + 1;
		if (sendto(client_socket, (char*)&clientPackInfo, sizeof(clientPackInfo), 0, (SOCKADDR*)&server_addr, server_addr_length) < 0) {
			cout << "第3次握手，确认建立连接发送失败" << endl;
			exit(1);
		}
	}
	cout << "3次握手建立连接成功" << endl;
	return client_socket;
}

int main() {
	// 三次握手建立连接，获取连接套接字
	SOCKET client_socket = ShakeHands();

	// 设置文件所在位置，此处设置在E:/目录下，更换目录需手动更改
	char* file_path = new char[FILE_NAME_MAX_SIZE + 1];
	memset(file_path, 0, FILE_NAME_MAX_SIZE + 1);
	strcat(file_path, "D:/test/source1/");
	// 输入文件名
	cout << "Please Input File Name On Server: ";
	char* file_name = new char[100];
	memset(file_name, 0, 100);
	cin >> file_name;
	// 将文件名加入路径
	strcat(file_path, file_name);
	// 将路径拷贝进buffer
	char buffer[BUFFER_SIZE];
	memset(buffer, 0, BUFFER_SIZE);
	strncpy(buffer, file_path, strlen(file_path) > BUFFER_SIZE ? BUFFER_SIZE : strlen(file_path));

	SOCKADDR_IN server_addr;
	memset(&server_addr, 0, sizeof(server_addr));
	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");
	server_addr.sin_port = htons(SERVER_PORT);
	int server_addr_length = sizeof(server_addr);

	// 发送文件路径
	if (sendto(client_socket, buffer, BUFFER_SIZE, 0, (SOCKADDR*)&server_addr, server_addr_length) < 0) {
		perror("Send File Name Failed:");
		exit(1);
	}

	// 设置写入目录，打开文件，准备写入
	char* dest_file = new char[FILE_NAME_MAX_SIZE + 1];
	memset(dest_file, 0, FILE_NAME_MAX_SIZE + 1);
	strcat(dest_file, "D:/test/aim1/");
	strcat(dest_file, file_name);
	FILE* fp = fopen(dest_file, "wb+");
	if (NULL == fp) {
		cout << "File:" << file_path << "Can Not Open To Write" << endl;
		exit(1);
	}

	Packet tpacket; //一个数据报，用于对暂时接受传入数据包进行判断
	Packet packet[2]; //累计确认数据报，大小为2，即收到两个帧之后再进行确认并写入文件
	bool notFinished = true;
	// 从服务器接收数据，并写入文件
	PackInfo packInfo; // 用于发送确认信息，ack=确认帧的seq
	int lastSeq = 0;
	packInfo.seq = 1;
	while (notFinished) {
		while (1) {
			// 接收传入的帧到tpacket
			if (recvfrom(client_socket, (char*)&tpacket, sizeof(tpacket), 0, (SOCKADDR*)&server_addr, &server_addr_length) == -1) {
				cout << "接收错误" << endl;
				continue;
			}
			// 传入帧为空，则说明传输结束，退出接受
			if (!tpacket.available) {
				notFinished = false;
				break;
			}
			// 检查校验和，若错误进行重传
			if (checksum(tpacket) != 0)
				goto retransmit;
			// 传入帧为累计确认的最大序号帧，跳出，判断前1帧是否收到
			if (tpacket.head.seq == packInfo.seq) {
				packet[1] = tpacket;
				break;
			}
			// 传入帧为累计确认的最大序号帧的前一帧，跳出，判断最小序号帧是否收到
			if (tpacket.head.seq == lastSeq) {
				packet[0] = tpacket;
				break;
			}
			// 收到其他序号帧均进行之前最大序号帧的确认，即传输重复ack
		retransmit:
			if (sendto(client_socket, (char*)&packInfo, sizeof(packInfo), 0, (SOCKADDR*)&server_addr, server_addr_length) < 0) {
				cout << "发送信息失败" << endl;
			}
		}
		// 收到最大序号帧及之前的所有帧，发送确认，确认packInfo的ack为收到最大序号帧的seq，packInfo的seq增加，用来确认下一次要接收的帧
		if (packet[1].head.seq == packInfo.seq && packet[0].head.seq == lastSeq) {
			//cout << "已经接受分组" << packet[1].head.seq << "及以前的数据" << endl;
			packInfo.ack = packet[1].head.seq;
			packInfo.seq += 2;
			lastSeq += 2;
			// 发送数据包确认信息
			if (sendto(client_socket, (char*)&packInfo, sizeof(packInfo), 0, (SOCKADDR*)&server_addr, server_addr_length) < 0) {
				cout << "发送信息失败" << endl;
			}
			// 写入文件
			for (int i = 0; i < 2; i++) {
				if (fwrite(packet[i].data, sizeof(char), packet[i].buf_size, fp) < packet[i].buf_size) {
					cout << "写入文件失败" << endl;;
					break;
				}
			}
			continue;
		}
		// 特殊情况，接收的最大序号帧为空，但是其前一帧不为空，即读到最后只剩了一个帧在窗口中的情况，接受并发送确认消息
		if ((!tpacket.available) && packet[0].head.seq == lastSeq && packet[0].available) {
			cout << "全部接收完成" << endl;
			packInfo.ack = packet[0].head.seq + 1;
			packInfo.seq += 2;
			lastSeq += 2;
			// 发送数据包确认信息
			if (sendto(client_socket, (char*)&packInfo, sizeof(packInfo), 0, (SOCKADDR*)&server_addr, server_addr_length) < 0) {
				cout << "发送确认信息失败" << endl;
			}
			if (fwrite(packet[0].data, sizeof(char), packet[0].buf_size, fp) < packet[0].buf_size) {
				cout << "写入文件失败" << endl;;
				break;
			}
			continue;
		}
		if (sendto(client_socket, (char*)&packInfo, sizeof(packInfo), 0, (SOCKADDR*)&server_addr, server_addr_length) < 0) {
			cout << "发送确认信息失败" << endl;
		}
	}

	cout << "从服务器接受文件成功！！！" << endl;
	fclose(fp);
	// 关闭套接字，释放资源
	closesocket(client_socket);
	WSACleanup();
	return 0;
}