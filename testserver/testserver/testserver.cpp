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

int timeout = 3000;

/* 包头 */
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

/* 接收包 */
typedef struct Packet
{
	PackInfo head;
	unsigned short buf_size;
	unsigned short Checksum;
	unsigned short retransmit_time;
	char data[BUFFER_SIZE];
	Packet() {
		this->head.seq = 0;
		this->head.syn = 0;
		this->head.ack = 0;
		this->buf_size = 0;
		this->Checksum = 0;
		this->retransmit_time = 0;
		memset(this->data, 0, BUFFER_SIZE);
	}
	Packet(unsigned short seq,
		unsigned short syn,
		unsigned short ack,
		unsigned short buf_size) {
		this->head.seq = seq;
		this->head.syn = syn;
		this->head.ack = ack;
		this->buf_size = buf_size;
		this->Checksum = 0;
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
	sum += packet.retransmit_time;
	//int wordNum = packet.buf_size / 2;

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
	WSAStartup(wVersionRequested, &wsaData);

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
		perror("Server Bind Failed:");
		exit(1);
	}

	srand(time(NULL)); // 产生随机数
	PackInfo serverPackInfo;

	SOCKADDR_IN client_addr;
	int client_addr_length = sizeof(client_addr);
	/* 接收建立连接的请求 */
	PackInfo clientPackInfo;
	if (recvfrom(server_socket, (char *)&clientPackInfo, sizeof(clientPackInfo), 0, (SOCKADDR*)&client_addr, &client_addr_length) == -1) {
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
	SOCKET server_socket = ShakeHands();
	Packet packet;

	/* 发送id */
	int send_id = 0;

	/* 接收id */
	int receive_id = 0;

	/* 数据传输 */
	while (1) {
		/* 定义一个地址，用于捕获客户端地址 */
		SOCKADDR_IN client_addr;
		int client_addr_length = sizeof(client_addr);

		/* 接收数据 */
		char buffer[BUFFER_SIZE];
		memset(buffer, 0, BUFFER_SIZE);

		int WaitTime = 30000;
		setsockopt(server_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&WaitTime, sizeof(int));
		if (recvfrom(server_socket, buffer, BUFFER_SIZE, 0, (SOCKADDR*)& client_addr, &client_addr_length) == -1) {
			cout << "等待超时" << endl;
			exit(1);
		}

		/* 从buffer中拷贝出file_name */
		char file_path[FILE_NAME_MAX_SIZE + 1];
		memset(file_path, 0, FILE_NAME_MAX_SIZE + 1);

		strncpy(file_path, buffer, strlen(buffer) > FILE_NAME_MAX_SIZE ? FILE_NAME_MAX_SIZE : strlen(buffer));
		cout << file_path << endl;

		setsockopt(server_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(int));
		/* 打开文件 */
		FILE* fp = fopen(file_path, "rb+");
		if (NULL == fp) {
			printf("File:%s Not Found.\n", file_path);
		}
		else {
			int len = 0;
			/* 每读取一段数据，便将其发给客户端 */
			while (1) {
				PackInfo pack_info;

				if (receive_id == send_id) {
					++send_id;
					if ((len = fread(packet.data, sizeof(char), BUFFER_SIZE, fp)) > 0) {
						packet.head.seq = send_id; /* 发送id放进包头,用于标记顺序 */
						packet.buf_size = len; /* 记录数据长度 */
						packet.Checksum = 0;
						packet.Checksum = checksum(packet);
						if (sendto(server_socket, (char*)&packet, sizeof(packet), 0, (SOCKADDR*)& client_addr, client_addr_length) < 0) {
							perror("Send File Failed:");
							break;
						}
						/* 接收确认消息，超时进行重传 */
						if (recvfrom(server_socket, (char*)&pack_info, sizeof(pack_info), 0, (SOCKADDR*)&client_addr, &client_addr_length) == -1)
							cout << "超时重传" << endl;
						else
							receive_id = pack_info.seq;
					}
					else {// 传输完毕
						packet.Checksum = checksum(packet);
						sendto(server_socket, (char*)NULL, 0, 0, (SOCKADDR*)&client_addr, client_addr_length);
						break;
					}
				}
				else {
					if (packet.retransmit_time > 2) {
						cout << "重传失败，停止传输" << endl;
						break;
					}
					/* 如果接收的id和发送的id不相同,重新发送 */
					if (sendto(server_socket, (char*)&packet, sizeof(packet), 0, (SOCKADDR*)&client_addr, client_addr_length) < 0) {
						perror("Send File Failed:");
						break;
					}
					packet.retransmit_time++;
					/* 接收确认消息，超时进行重传 */
					if (recvfrom(server_socket, (char*)&pack_info, sizeof(pack_info), 0, (SOCKADDR*)&client_addr, &client_addr_length) == -1)
						cout << "超时重传" << endl;
					else {
						receive_id = pack_info.seq;
						packet.retransmit_time = 0;
					}
				}
			}
			/* 关闭文件 */
			fclose(fp);
			printf("File:%s Transmission finished!\n", file_path);
		}
	}
	closesocket(server_socket);
	WSACleanup();
	return 0;
}