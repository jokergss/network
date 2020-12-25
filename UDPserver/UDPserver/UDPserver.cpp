#include <iostream>
#include <WinSock2.h>
#include <string.h>
#include <fstream>
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
	PackInfo head; //伪首部
	unsigned short buf_size;
	unsigned short Checksum; // 校验和
	time_t send_time; // 发送时间
	bool available;
	char data[BUFFER_SIZE]; // 数据缓冲区
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

unsigned short checksum(Packet packet) { // 校验和计算
	// 数据报内字段相加
	unsigned long sum = 0;
	sum += packet.head.seq;
	sum += packet.head.ack;
	sum += packet.head.syn;
	sum += packet.buf_size;
	sum += packet.Checksum;

	if (packet.buf_size % 2 == 0) { // 数据累加
		for (int i = 0; i < packet.buf_size; i += 2) {
			// char型数据左移8位与下一个char相加
			sum += (((unsigned short)packet.data[i]) << 8) | (unsigned short)packet.data[i + 1];
			sum = (sum >> 16) + (sum & 0xffff);
		}
	}
	else {// 补齐缺失的0位
		for (int i = 0; i < packet.buf_size - 1; i += 2) {
			sum += (((unsigned short)packet.data[i]) << 8) | (unsigned short)packet.data[i + 1];
			sum = (sum >> 16) + (sum & 0xffff);
		}
		sum += (((unsigned short)packet.data[packet.buf_size - 1]) << 8);
		sum = (sum >> 16) + (sum & 0xffff);
	}
	// 进位加回末尾
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
	/* 创建UDP套接字 */
	SOCKADDR_IN server_addr;
	memset(&server_addr, 0, sizeof(server_addr));

	server_addr.sin_family = AF_INET;
	server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	server_addr.sin_port = htons(SERVER_PORT);

	/* 创建socket */
	SOCKET server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (server_socket == -1) {
		perror("Create Socket Failed:");
		exit(1);
	}

	/* 绑定套接字 */
	if (-1 == (bind(server_socket, (SOCKADDR*)&server_addr, sizeof(server_addr)))) {
		cout << "Server Bind Failed:" << endl;
		exit(1);
	}

	srand(time(NULL)); // 产生随机数
	PackInfo serverPackInfo;

	SOCKADDR_IN client_addr;
	int client_addr_length = sizeof(client_addr);
	/* 接收建立连接的请求 */
	PackInfo clientPackInfo;
	if (recvfrom(server_socket, (char*)&clientPackInfo, sizeof(clientPackInfo), 0, (SOCKADDR*)&client_addr, &client_addr_length) == -1) {
		cout << "第1次握手，建立连接失败" << endl;
		exit(1);
	}
	serverPackInfo.syn = clientPackInfo.syn;
	serverPackInfo.seq = rand();
	serverPackInfo.ack = clientPackInfo.seq + 1;
	if (sendto(server_socket, (char*)&serverPackInfo, sizeof(serverPackInfo), 0, (SOCKADDR*)&client_addr, client_addr_length) < 0) {
		cout << "第2次握手，发送确认失败" << endl;
		exit(1);
	}
	if (recvfrom(server_socket, (char*)&clientPackInfo, sizeof(clientPackInfo), 0, (SOCKADDR*)&client_addr, &client_addr_length) == -1) {
		cout << "第3次握手，接受确认失败" << endl;
		exit(1);
	}
	if (clientPackInfo.syn == 0 && clientPackInfo.seq == serverPackInfo.ack && clientPackInfo.ack == (serverPackInfo.seq + 1))
		cout << "3次握手建立连接成功" << endl;

	return server_socket;
}

int main() {
	// 建立连接，获取套接字
	SOCKET server_socket = ShakeHands();

	// 定义一个地址，用于捕获客户端地址
	SOCKADDR_IN client_addr;
	int client_addr_length = sizeof(client_addr);

	// 定义接收数据缓冲区
	char buffer[BUFFER_SIZE];
	memset(buffer, 0, BUFFER_SIZE); // 初始化缓冲区

	// 设置接收文件路径延时为30s
	int WaitTime = 30000;
	setsockopt(server_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&WaitTime, sizeof(int));
	// 接收文件路径到buffer
	if (recvfrom(server_socket, buffer, BUFFER_SIZE, 0, (SOCKADDR*)&client_addr, &client_addr_length) == -1) {
		cout << "等待超时" << endl;
		exit(1);
	}

	// 从buffer中拷贝出file_path
	char file_path[FILE_NAME_MAX_SIZE + 1];
	memset(file_path, 0, FILE_NAME_MAX_SIZE + 1);
	strncpy(file_path, buffer, strlen(buffer) > FILE_NAME_MAX_SIZE ? FILE_NAME_MAX_SIZE : strlen(buffer));
	cout << file_path << endl;

	// 打开文件
	FILE* fp = fopen(file_path, "rb+");
	if (NULL == fp) {
		cout << "文件：" << file_path << "没有找到" << endl;
		return 0;
	}

	int len = 0; // 用于接收读取一段内容的长度，字节数
	PackInfo packInfo; // 用于接收客户端
	Packet packet[3]; // 定义一个大小为3个帧的窗口，用于发送
	// 设置recvfrom函数接收超时为1ms，用于取消阻塞，计算窗口发送的时间
	setsockopt(server_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(int));
	// 从文件读出一个窗口所有帧的数据
	for (int i = 0; i < 3; i++) {
		if ((len = fread(packet[i].data, 1, BUFFER_SIZE, fp)) > 0) {
			packet[i].buf_size = len;
			packet[i].head.seq = i;
			packet[i].Checksum = 0;
			packet[i].Checksum = checksum(packet[i]);
		}
	}
	// 第一次发送一个窗口的所有帧
	for (int i = 0; i < 3; i++) {
		if (sendto(server_socket, (char*)&packet[i], sizeof(packet[i]), 0, (SOCKADDR*)&client_addr, client_addr_length) < 0) {
			cout << "发送错误" << endl;
			return 0;
		}
		// 记录确认帧的发送时间
		if (i == 1)
			packet[i].send_time = time(NULL);
	}

	bool notFinished = true;
	while (notFinished) {
		// 接受确认超时，进行重传
		if ((time(NULL) - packet[1].send_time) >= 1) {
			cout << "超时重传" << endl;
			for (int i = 0; i < 3; i++) {
				if (sendto(server_socket, (char*)&packet[i], sizeof(packet[i]), 0, (SOCKADDR*)&client_addr, client_addr_length) < 0) {
					cout << "发送错误" << endl;
					return 0;
				}
				if (i == 1)
					packet[i].send_time = time(NULL);
				// 窗口中的某些帧发送完毕，继续监听是否收到所有的确认
				if (!packet[i].available) {
					if (!packet[0].available) {
						notFinished = false;
					}
					break;
				}
			}
		}
		// 不断监听客户端返回的确认
		if (recvfrom(server_socket, (char*)&packInfo, sizeof(packInfo), 0, (SOCKADDR*)&client_addr, &client_addr_length) == -1)
			continue;
		// 当收到累计确认最大帧号的确认时，窗口后移，继续发送，收到其他帧号（即重复ack）全部忽略
		if (packInfo.ack == packet[1].head.seq) {
			//cout << "分组" << packInfo.ack << "及之前传输完成" << endl;
			packet[0] = packet[2]; // 后移窗口，即将后续数据报移入窗口数据的前端
			if (!packet[0].available) { // 窗口首帧数据为空，（即数据全部发送完毕），继续发送一个空帧，用于客户端结束接受
				if (sendto(server_socket, (char*)&packet[0], sizeof(packet[0]), 0, (SOCKADDR*)&client_addr, client_addr_length) < 0) {
					cout << "发送错误" << endl;
					return 0;
				}
				cout << "全部发送完成" << endl;
				break;
			}// 窗口后移，读入数据并发送
			for (int i = 1; i < 3; i++) {
				// 数据未读完，正常读入
				if ((len = fread(packet[i].data, 1, BUFFER_SIZE, fp)) > 0) {
					packet[i].buf_size = len;
					packet[i].head.seq = packet[i - 1].head.seq + 1;
					packet[i].Checksum = 0;
					packet[i].Checksum = checksum(packet[i]);
					if (sendto(server_socket, (char*)&packet[i], sizeof(packet[i]), 0, (SOCKADDR*)&client_addr, client_addr_length) < 0) {
						cout << "发送错误" << endl;
						return 0;
					}
					if (i == 1)
						packet[i].send_time = time(NULL);
				}
				else {// 数据已读完，将数据包置为空，递增序号用于客户端结束接受
					packet[i].available = false;
					packet[i].buf_size = len;
					packet[i].head.seq = packet[i - 1].head.seq + 1;
				}
			}
		}
	}
	fclose(fp);
	closesocket(server_socket);
	WSACleanup();
	return 0;
}