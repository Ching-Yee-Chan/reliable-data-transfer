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
		cout << "�޷���ȡ��������" << endl;
		return nulladr;//����������ȫ0
	}

	struct addrinfo hints;
	struct addrinfo* res, * cur;
	struct sockaddr_in addr;

	memset(&hints, 0, sizeof(addrinfo));
	hints.ai_family = AF_INET;	//IPv4
	hints.ai_flags = AI_PASSIVE; //ƥ������ IP ��ַ
	hints.ai_protocol = 0;       //ƥ������Э��

	int ret = getaddrinfo(name, NULL, &hints, &res);
	if (ret == -1 || res == NULL)
	{
		return nulladr;//����������ȫ0
	}

	//�����ȡ����Ϣ
	for (cur = res; cur->ai_next != NULL; cur = cur->ai_next);//�ҵ����һ��IP��ַ
	addr = *((struct sockaddr_in*)cur->ai_addr); //��ȡ��ǰ address
	cout << "�ͻ���IP��ַ��";
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
	char flags;		//�ڶ�λΪack�������ڶ�λΪSYN�����һλΪFIN(MSVC�����ֽڶ��룬�˴�flagsռ�����ֽ�)
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
		//ԴIP
		pseudo[11] = addrClt.sin_addr.S_un.S_un_b.s_b1;
		pseudo[10] = addrClt.sin_addr.S_un.S_un_b.s_b2;
		pseudo[9] = addrClt.sin_addr.S_un.S_un_b.s_b3;
		pseudo[8] = addrClt.sin_addr.S_un.S_un_b.s_b4;
		//Ŀ��IP
		pseudo[7] = addrSrv.sin_addr.S_un.S_un_b.s_b1;
		pseudo[6] = addrSrv.sin_addr.S_un.S_un_b.s_b2;
		pseudo[5] = addrSrv.sin_addr.S_un.S_un_b.s_b3;
		pseudo[4] = addrSrv.sin_addr.S_un.S_un_b.s_b4;
		pseudo[3] = 0;
		pseudo[2] = 6;//tcpЭ����
		//TCP����
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
		//ԴIP
		pseudo[11] = addrSrv.sin_addr.S_un.S_un_b.s_b1;
		pseudo[10] = addrSrv.sin_addr.S_un.S_un_b.s_b2;
		pseudo[9] = addrSrv.sin_addr.S_un.S_un_b.s_b3;
		pseudo[8] = addrSrv.sin_addr.S_un.S_un_b.s_b4;
		//Ŀ��IP
		pseudo[7] = addrClt.sin_addr.S_un.S_un_b.s_b1;
		pseudo[6] = addrClt.sin_addr.S_un.S_un_b.s_b2;
		pseudo[5] = addrClt.sin_addr.S_un.S_un_b.s_b3;
		pseudo[4] = addrClt.sin_addr.S_un.S_un_b.s_b4;
		pseudo[3] = 0;
		pseudo[2] = 6;//tcpЭ����
		//TCP����
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
		cout << "��������ʧ�ܣ�δ�յ�������ȷ����Ϣ�������룺" << WSAGetLastError() << endl;
		return false;
	}
	while(!recvBuf.valid()){//У��
		cout << "������Ϣ���󣡵ȴ��ش�������" << endl;
		int recvNum = recvfrom(sockClient, (char*)&recvBuf, sizeof(stop_wait_package), 0, (SOCKADDR*)&addrSrv, &addrLen);
		if (recvNum<0) {
			cout << "��������ʧ�ܣ�δ�յ�������ȷ����Ϣ�������룺" << WSAGetLastError() << endl;
			return false;
		}
	}
	if(recvBuf.getSYN()){
		cout<<"�������ӳɹ�����������ISN: "<<recvBuf.seq<<"; ACK: "<<recvBuf.ack - seq<<endl;
		ack = recvBuf.seq;
		sendBuf.reset(++seq, ack, true, false, false, nullptr, 0);
		sendto(sockClient, (char*)&sendBuf, sizeof(stop_wait_package), 0, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
		return true;
	}
	else{
		cout << "��������ʧ�ܣ�������æ��" << endl;
		return false;
	}
}

int main()
{
	WORD wVersionRequested = MAKEWORD(2, 2);
	WSADATA wsaData;
	int connectState = WSAStartup(wVersionRequested, &wsaData);
	if (connectState != 0) {
		cout << "WSA����ʧ�ܣ������룺" << WSAGetLastError() << endl;
		return -1;
	}

	sockClient = socket(AF_INET, SOCK_DGRAM, 0);
	if (sockClient == INVALID_SOCKET) {
		cout << "socket����ʧ�ܣ������룺" << WSAGetLastError() << endl;
		return -1;
	}

	addrClt = getLocalIP();
	if (addrClt.sin_addr.S_un.S_un_b.s_b1 == 0) {
		cout << "�Զ���ȡ����IP��ַʧ�ܣ����ֶ����룺" << WSAGetLastError() << endl;
		int a(127), b(0), c(0), d(1);
		cin >> a >> b >> c >> d;
		addrSrv.sin_addr.S_un.S_un_b.s_b1 = a;
		addrSrv.sin_addr.S_un.S_un_b.s_b2 = b;
		addrSrv.sin_addr.S_un.S_un_b.s_b3 = c;
		addrSrv.sin_addr.S_un.S_un_b.s_b4 = d;
	}
	addrSrv.sin_family = AF_INET;

	int a(127), b(0), c(0), d(1);
	cout << "������������������ֽ�IPv4��ַ��";
	scanf("%d.%d.%d.%d", &a, &b, &c, &d);
	addrSrv.sin_addr.S_un.S_un_b.s_b1 = a;
	addrSrv.sin_addr.S_un.S_un_b.s_b2 = b;
	addrSrv.sin_addr.S_un.S_un_b.s_b3 = c;
	addrSrv.sin_addr.S_un.S_un_b.s_b4 = d;
	int port = 10086;
	cout << "�����������ӵ�����˿ںţ�" ;
	cin >> port;
	addrSrv.sin_port = htons(port);
	srand((unsigned)time(NULL));
	//SYN-SENT
	while(!establish())//ѭ��������������ֱ������������
	{
		Sleep(200);
	}


	cout << "�Ự�ѽ���" << endl;
	system("pause");
	return 0;
}