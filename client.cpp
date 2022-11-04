#include <iostream>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <time.h> 
#pragma comment(lib, "Ws2_32.lib")
using namespace std;
SOCKADDR_IN addrSrv;
SOCKADDR_IN addrClt;
SOCKET sockClient;

const int MSS = 512;
unsigned short seq = 0;
unsigned short ack = 0;
unsigned short seqBase = 0;
unsigned short ackBase = 0;

sockaddr_in getLocalIP()
{
	SOCKADDR_IN nulladr = {0};
	char name[255];
	if (gethostname(name, sizeof(name)) == -1) {
		cout << "无法获取主机名！" << endl;
		return nulladr;//出错，返回全0
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
		return nulladr;//出错，返回全0
	}

	//输出获取的信息
	for (cur = res; cur->ai_next != NULL; cur = cur->ai_next);//找到最后一个IP地址
	addr = *((struct sockaddr_in*)cur->ai_addr); //获取当前 address
	cout << "客户端IP地址：";
	printf("%d.%d.%d.%d\n", addr.sin_addr.S_un.S_un_b.s_b1,
		addr.sin_addr.S_un.S_un_b.s_b2,
		addr.sin_addr.S_un.S_un_b.s_b3,
		addr.sin_addr.S_un.S_un_b.s_b4);
	return addr;
}

struct stop_wait_package
{
	unsigned short seq;
	unsigned short ack;
	char flags;		//第二位为ack，倒数第二位为SYN，最后一位为FIN(MSVC按两字节对齐，此处flags占用两字节)
	unsigned short checkSum;
	char data[MSS];
	void reset(unsigned short SEQ, unsigned short ACK_n, bool ACK, bool SYN, bool FIN, char _data[], int dataLen)
	{
		seq = SEQ;
		ack = ACK_n;
		flags = 0;
		if(ACK){
			setACK();
		}
		if(SYN){
			setSYN();
		}
		else if(FIN){
			setFIN();
		}
		if(dataLen){
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
		flags |= 0x01;
	}
	void setCheckSum()
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
		pseudo[1] = sizeof(stop_wait_package)>>8;
		pseudo[0] = sizeof(stop_wait_package);
		unsigned short sum = 0;
		for(int i = 0;i<12;i+=2)
		{
			sum = sum + *((unsigned short*)(pseudo + i));
		}
		for(int i = 0;i<sizeof(stop_wait_package);i+=2)
		{
			sum = sum + *((unsigned short*)((char*)this+i));
		}
		checkSum = ~sum;
	}
	bool valid()
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
		pseudo[1] = sizeof(stop_wait_package)>>8;
		pseudo[0] = sizeof(stop_wait_package);
		unsigned short sum = 0;
		for(int i = 0;i<12;i+=2)
		{
			sum = sum + *((unsigned short*)(pseudo + i));
		}
		for(int i = 0;i<sizeof(stop_wait_package);i+=2)
		{
			sum = sum + *((unsigned short*)((char*)this+i));
		}
		return sum == 0xFFFF;
	}
}sendBuf, recvBuf;

bool establish()
{
	seq = seqBase = rand();
	sendBuf.reset(seq, 0, false, true, false, nullptr, 0);
	sendto(sockClient, (char*)&sendBuf, sizeof(stop_wait_package), 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	int addrLen = sizeof(SOCKADDR);
	int recvNum = recvfrom(sockClient, (char*)&recvBuf, sizeof(stop_wait_package), 0, (SOCKADDR*)&addrSrv, &addrLen);
	if (recvNum<0) {
		cout << "建立连接失败：未收到服务器确认消息！错误码：" << WSAGetLastError() << endl;
		return false;
	}
	while(!recvBuf.valid()){//校验
		cout << "接收消息有误！等待重传。。。" << endl;
		int recvNum = recvfrom(sockClient, (char*)&recvBuf, sizeof(stop_wait_package), 0, (SOCKADDR*)&addrSrv, &addrLen);
		if (recvNum<0) {
			cout << "建立连接失败：未收到服务器确认消息！错误码：" << WSAGetLastError() << endl;
			return false;
		}
	}
	if(recvBuf.getSYN()){
		cout<<"建立连接成功！服务器端ISN: "<<recvBuf.seq<<"; ACK: "<<recvBuf.ack - seq<<endl;
		ack = recvBuf.seq;
		sendBuf.reset(++seq, ack, true, false, false, nullptr, 0);
		sendto(sockClient, (char*)&sendBuf, sizeof(stop_wait_package), 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
		return true;
	}
	else{
		cout << "建立连接失败：服务器忙！" << endl;
		return false;
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

	sockClient = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockClient == INVALID_SOCKET) {
		cout << "socket创建失败！错误码：" << WSAGetLastError() << endl;
		return -1;
	}

	addrClt = getLocalIP();
	if (addrClt.sin_addr.S_un.S_un_b.s_b1 == 0) {
		cout << "自动获取本机IP地址失败！请手动输入：" << WSAGetLastError() << endl;
		int a(127), b(0), c(0), d(1);
		cin >> a >> b >> c >> d;
		addrSrv.sin_addr.S_un.S_un_b.s_b1 = a;
		addrSrv.sin_addr.S_un.S_un_b.s_b2 = b;
		addrSrv.sin_addr.S_un.S_un_b.s_b3 = c;
		addrSrv.sin_addr.S_un.S_un_b.s_b4 = d;
	}
	addrSrv.sin_family = AF_INET;

	int a(127), b(0), c(0), d(1);
	cout << "请依次输入服务器四字节IPv4地址：";
	scanf("%d.%d.%d.%d", &a, &b, &c, &d);
	addrSrv.sin_addr.S_un.S_un_b.s_b1 = a;
	addrSrv.sin_addr.S_un.S_un_b.s_b2 = b;
	addrSrv.sin_addr.S_un.S_un_b.s_b3 = c;
	addrSrv.sin_addr.S_un.S_un_b.s_b4 = d;
	int port = 10086;
	cout << "请输入欲连接的网络端口号：" ;
	cin >> port;
	addrSrv.sin_port = htons(port);
	srand((unsigned)time(NULL));
	//SYN-SENT
	while(!establish())//循环发送连接请求直至服务器接收
	{
		Sleep(200);
	}


	cout << "会话已结束" << endl;
	system("pause");
	return 0;
}