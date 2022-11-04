#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#pragma comment(lib, "Ws2_32.lib")
using namespace std;

const int MSS = 512;
unsigned short seq = 0, ack = 0;
unsigned short seqBase = 0;
unsigned short ackBase = 0;
SOCKADDR_IN addrSrv;
SOCKADDR_IN addrClt;
SOCKET sockSrv;

struct stop_wait_package
{
	unsigned short seq;
	unsigned short ack;
	char flags;		//倒数第二位为SYN，最后一位为FIN(MSVC按两字节对齐，此处flags占用两字节)
	unsigned short checkSum;
	char data[MSS];
	void reset(unsigned short SEQ, unsigned short ACK_n, bool ACK, bool SYN, bool FIN, char _data[], int dataLen)
	{
		seq = SEQ;
		ack = ACK_n;
		flags = 0;
		if (ACK) {
			setACK();
		}
		if (SYN) {
			setSYN();
		}
		else if (FIN) {
			setFIN();
		}
		if (dataLen) {
			memcpy_s(data, MSS, _data, dataLen);
		}
		checkSum = 0;
		setCheckSum();
	}
	bool getACK()
	{
		return flags & 0x40;
	}
	void setACK()
	{
		flags |= 0x40;
	}
	bool getSYN()
	{
		return flags & 0x02;
	}
	void setSYN()
	{
		flags |= 0x02;
	}
	bool getFIN()
	{
		return flags & 0x01;
	}
	void setFIN()
	{
		flags &= 0x01;
	}
	void setCheckSum()
	{
		char pseudo[12];
		//源IP
		pseudo[11] = addrSrv.sin_addr.S_un.S_un_b.s_b1;
		pseudo[10] = addrSrv.sin_addr.S_un.S_un_b.s_b2;
		pseudo[9] = addrSrv.sin_addr.S_un.S_un_b.s_b3;
		pseudo[8] = addrSrv.sin_addr.S_un.S_un_b.s_b4;
		//目的IP
		pseudo[7] = addrClt.sin_addr.S_un.S_un_b.s_b1;
		pseudo[6] = addrClt.sin_addr.S_un.S_un_b.s_b2;
		pseudo[5] = addrClt.sin_addr.S_un.S_un_b.s_b3;
		pseudo[4] = addrClt.sin_addr.S_un.S_un_b.s_b4;
		pseudo[3] = 0;
		pseudo[2] = 6;//tcp协议编号
		//TCP长度
		pseudo[1] = sizeof(stop_wait_package) >> 8;
		pseudo[0] = sizeof(stop_wait_package);
		unsigned short sum = 0;
		for (int i = 0; i < 12; i += 2)
		{
			sum = sum + *((unsigned short*)(pseudo + i));
		}
		for (int i = 0; i < sizeof(stop_wait_package); i += 2)
		{
			sum = sum + *((unsigned short*)((char*)this + i));
		}
		checkSum = ~sum;
	}
	bool valid()
	{
		char pseudo[12];
		//源IP
		pseudo[11] = addrClt.sin_addr.S_un.S_un_b.s_b1;
		pseudo[10] = addrClt.sin_addr.S_un.S_un_b.s_b2;
		pseudo[9] = addrClt.sin_addr.S_un.S_un_b.s_b3;
		pseudo[8] = addrClt.sin_addr.S_un.S_un_b.s_b4;
		//目的IP
		pseudo[7] = addrSrv.sin_addr.S_un.S_un_b.s_b1;
		pseudo[6] = addrSrv.sin_addr.S_un.S_un_b.s_b2;
		pseudo[5] = addrSrv.sin_addr.S_un.S_un_b.s_b3;
		pseudo[4] = addrSrv.sin_addr.S_un.S_un_b.s_b4;
		pseudo[3] = 0;
		pseudo[2] = 6;//tcp协议编号
		//TCP长度
		pseudo[1] = sizeof(stop_wait_package) >> 8;
		pseudo[0] = sizeof(stop_wait_package);
		unsigned short sum = 0;
		for (int i = 0; i < 12; i += 2)
		{
			sum = sum + *((unsigned short*)(pseudo + i));
		}
		for (int i = 0; i < sizeof(stop_wait_package); i += 2)
		{
			sum = sum + *((unsigned short*)((char*)this + i));
		}
		return sum == 0xFFFF;
	}
}sendBuf, recvBuf;

sockaddr_in getLocalIP()
{
	char name[255];
	if (gethostname(name, sizeof(name)) == -1) {
		cout << "无法获取主机名！" << endl;
		return { 0 };//出错，返回全0
	}

	struct addrinfo hints;
	struct addrinfo* res, * cur;
	struct sockaddr_in addr;

	memset(&hints, 0, sizeof(addrinfo));
	hints.ai_family = AF_INET;	//IPv4
	hints.ai_flags = AI_PASSIVE; //匹配所有 IP 地址
	hints.ai_protocol = 0;       //匹配所有协议

	int ret = getaddrinfo(name, NULL, &hints, &res);
	if (ret == -1 || res == NULL)
	{
		return { 0 };//出错，返回全0
	}

	//输出获取的信息
	for (cur = res; cur->ai_next != NULL; cur = cur->ai_next);//找到最后一个IP地址
	addr = *((struct sockaddr_in*)cur->ai_addr); //获取当前 address
	cout << "使用服务器IP地址：";
	printf("%d.%d.%d.%d\n", addr.sin_addr.S_un.S_un_b.s_b1,
		addr.sin_addr.S_un.S_un_b.s_b2,
		addr.sin_addr.S_un.S_un_b.s_b3,
		addr.sin_addr.S_un.S_un_b.s_b4);
	return addr;
}

bool establish()
{
	int len = sizeof(SOCKADDR);
	int recvNum = recvfrom(sockSrv, (char*)&recvBuf, sizeof(stop_wait_package), 0, (SOCKADDR*)&addrClt, &len);
	if (recvNum < 0) {
		cout << "接收建联请求失败，错误码：" << WSAGetLastError() << endl;
		return false;
	}
	else if (!recvBuf.valid()) {//校验
		cout << "接收消息有误！" << endl;
		return false;
	}
	if (recvBuf.getSYN()) {
		cout << "收到用户建联请求！ISN: " << recvBuf.seq << endl;
		ack = ackBase = recvBuf.seq;
		return true;
	}
	else return false;
}

bool sendPackage()
{
	while (true)
	{
		int status = sendto(sockSrv, (char*)&sendBuf, sizeof(stop_wait_package), 0, (SOCKADDR*)&addrClt, sizeof(SOCKADDR));
		if (status == SOCKET_ERROR) {
			cout << "发送消息失败，即将重传！错误码：" << WSAGetLastError() << endl;
			continue;
		}
		for (int i = 0; i < 10; Sleep(200), i++)
		{
			int len = sizeof(SOCKADDR);
			int recvNum = recvfrom(sockSrv, (char*)&recvBuf, sizeof(stop_wait_package), 0, (SOCKADDR*)&addrClt, &len);
			if (recvNum < 0) {
				continue;
			}
			if (!recvBuf.valid()) {//校验
				cout << "接收消息有误！即将重传..." << endl;
				break;
			}
			if (recvBuf.getACK() && recvBuf.ack==seq) {
				cout << "收到来自客户端的确认！ACK: " << recvBuf.ack - seqBase<< endl;
				ack = recvBuf.seq;
				return true;
			}
		}
		cout << "2s未收到相应，即将超时重传..." << endl;
	}
}

int main()
{
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData;
	int connectState = WSAStartup(wVersionRequested, &wsaData);
	if (connectState != 0) {
		cout << "WSA启动失败！错误码：" << WSAGetLastError() << endl;
		return -1;
	}

	sockSrv = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if (sockSrv == INVALID_SOCKET) {
		cout << "socket创建失败！错误码：" << WSAGetLastError() << endl;
		return -1;
	}

	addrSrv = getLocalIP();
	if (addrSrv.sin_addr.S_un.S_un_b.s_b1 == 0) {
		cout << "自动获取服务器IP地址失败！请手动输入：" << WSAGetLastError() << endl;
		int a(127), b(0), c(0), d(1);
		cin >> a >> b >> c >> d;
		addrSrv.sin_addr.S_un.S_un_b.s_b1 = a;
		addrSrv.sin_addr.S_un.S_un_b.s_b2 = b;
		addrSrv.sin_addr.S_un.S_un_b.s_b3 = c;
		addrSrv.sin_addr.S_un.S_un_b.s_b4 = d;
	}
	addrSrv.sin_family = AF_INET;
	int port = 10086;
	cout << "请输入欲使用的网络端口号：";
	cin >> port;
	addrSrv.sin_port = htons(port);
	connectState = bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	if (connectState != 0) {
		cout << "bind失败！错误码：" << WSAGetLastError() << endl;
		return -1;
	}
	else cout << "bind成功！" << endl;

	srand((unsigned)time(NULL));

	cout << "服务器已启动，等待连接请求中..." << endl;
	//LISTEN
	//第一次握手
	while (!establish())//循环监听直至收到请求
	{
		Sleep(200);
	}
	//设置套接字为非阻塞模式 
	int iMode = 1; //1：非阻塞，0：阻塞 
	ioctlsocket(sockSrv, FIONBIO, (u_long FAR*) & iMode);
	seq = seqBase = rand();
	sendBuf.reset(seq, ack, true, true, false, nullptr, 0);
	//SYN-RCVD
	//第二次、第三次握手
	sendPackage();
	cout << "连接已建立！" << endl;
	//ESTABLISHED

	cout << "会话已结束" << endl;
	system("pause");
	return 0;
}