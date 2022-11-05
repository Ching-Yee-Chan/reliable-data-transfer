#include <iostream>
#include <fstream>
#include <io.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <vector>
#define FILEPATH "D:\\数据\\作业\\寄网\\Lab3\\server\\data"
#pragma comment(lib, "Ws2_32.lib")
using namespace std;

const int MSS = 2048;
const int WINDOW = 64;
const double LOSSRATE = 0.1;
unsigned short seq = 0, ack = 0;
unsigned short seqBase = 0;//服务器发送消息序列号的基准编号，用于计算基准序列号（ISN）
unsigned short ackBase = 0;//ack基准（客户端ISN）
unsigned short sendBase = 1;//发送窗口基址，0号为第二次握手使用
bool over = false;//用于传输结束时停止接收进程
bool retransmitting = false;//当接收线程正在重传时，为缓冲区上锁
SOCKADDR_IN addrSrv;
SOCKADDR_IN addrClt;
SOCKET sockSrv;

//模拟丢包
bool randomLoss()
{
	int lossBound = (int)(LOSSRATE * 100);
	int r = rand() % 100;
	if (r < lossBound) {
		return true;
	}
	return false;
}

struct package
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
		flags |= 0x01;
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
		pseudo[1] = sizeof(package) >> 8;
		pseudo[0] = sizeof(package);
		unsigned short sum = 0;
		for (int i = 0; i < 12; i += 2)
		{
			sum = sum + *((unsigned short*)(pseudo + i));
		}
		for (int i = 0; i < sizeof(package); i += 2)
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
		pseudo[1] = sizeof(package) >> 8;
		pseudo[0] = sizeof(package);
		unsigned short sum = 0;
		for (int i = 0; i < 12; i += 2)
		{
			sum = sum + *((unsigned short*)(pseudo + i));
		}
		for (int i = 0; i < sizeof(package); i += 2)
		{
			sum = sum + *((unsigned short*)((char*)this + i));
		}
		return sum == 0xFFFF;
	}
}sendBuf[WINDOW], recvBuf;

//文件头结构
struct fileHead {
	char name[20];
	int length;
};

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
	int recvNum = recvfrom(sockSrv, (char*)&recvBuf, sizeof(package), 0, (SOCKADDR*)&addrClt, &len);
	if (recvNum < 0) {
		cout << "[error]接收建联请求失败，错误码：" << WSAGetLastError() << endl;
		return false;
	}
	else if (!recvBuf.valid()) {//校验
		cout << "[error]接收消息有误！" << endl;
		return false;
	}
	if (recvBuf.getSYN()) {
		ack = ackBase = recvBuf.seq;
		cout << "第一次握手" << "	" << "R" << "	" << recvBuf.seq - ackBase << "	" << recvBuf.ack - seqBase << "	" << recvBuf.checkSum << endl;
		return true;
	}
	else return false;
}

//停等收发函数，仅在连接建立和释放时调用
bool sendAndWait()
{
	while (true)
	{
		cout << "发     送" << "	" << "S" << "	" << sendBuf[seq % WINDOW].seq - seqBase << "	" << sendBuf[seq % WINDOW].ack - ackBase << "	" << sendBuf[seq % WINDOW].checkSum << endl;
		if (!randomLoss()) {//模拟丢包
			int status = sendto(sockSrv, (char*)&sendBuf[seq % WINDOW], sizeof(package), 0, (SOCKADDR*)&addrClt, sizeof(SOCKADDR));
			if (status == SOCKET_ERROR) {
				cout << "[error]发送消息失败，即将重传！错误码：" << WSAGetLastError() << endl;
				continue;
			}
		}
		for (int i = 0; i < 10; Sleep(5), i++)
		{
			int len = sizeof(SOCKADDR);
			int recvNum = recvfrom(sockSrv, (char*)&recvBuf, sizeof(package), 0, (SOCKADDR*)&addrClt, &len);
			if (recvNum < 0) {
				continue;
			}
			if (!recvBuf.valid()) {//校验
				cout << "[error]接收消息有误！即将重传..." << endl;
				break;
			}
			if (recvBuf.getACK() && recvBuf.ack == seq) {
				cout << "收     到" << "	" << "R" << "	" << recvBuf.seq - ackBase << "	" << recvBuf.ack - seqBase << "	" << recvBuf.checkSum << endl;
				ack = recvBuf.seq;
				return true;
			}
		}
		cout << "50ms未收到响应，即将超时重传..." << endl;
	}
}

bool sendFile(string fileName)
{
	string path;
	path.assign(FILEPATH).append("\\").append(fileName);
	ifstream infile(path, ios::binary);
	if (!infile.is_open()) {
		cout << "文件" << fileName << "打开失败！" << endl;
		return false;
	}
	//读取文件总大小
	infile.seekg(0, ios::end);
	int length = infile.tellg();
	int packNum = ceil((double)length / MSS);
	cout << "文件" << fileName << "已读取！大小为" << length << "Bytes，共计" << packNum << "个数据包" << endl;
	//发送文件头
	fileHead head;
	strcpy_s(head.name, fileName.c_str());
	head.length = length;
	sendBuf[(++seq) % WINDOW].reset(seq, ack, true, false, false, (char*)&head, sizeof(head));
	sendAndWait();
	cout << "文件头发送成功！开始传输数据..." << endl;
	infile.seekg(0, std::ios_base::beg);  //将文件流指针重新定位到流的开始
	//传输文件
	double time = 0;
	while (length > 0) {
		if (retransmitting || (seq-sendBase>=WINDOW-1)) {//缓冲区上锁，正在重传，或缓冲区已满，等待
			Sleep(10);
			continue;
		}
		infile.read(sendBuf[(seq + 1) % WINDOW].data, min(length, MSS));//此处序列号前移
		length -= MSS;
		sendBuf[(seq + 1) %WINDOW].reset(seq + 1, ack, true, false, false, nullptr, 0);//由于已经设置过data域，此处不再设置
		cout << "发    送" << "	" << "S" << "	" << sendBuf[(seq + 1) % WINDOW].seq - seqBase << "	" << sendBuf[(seq + 1) % WINDOW].ack - ackBase << "	" << sendBuf[(seq + 1) % WINDOW].checkSum << "	" << sendBase - seqBase << "	" << seq - seqBase << endl;
		if (!randomLoss()) {
			sendto(sockSrv, (char*)&sendBuf[(seq + 1) % WINDOW], sizeof(package), 0, (SOCKADDR*)&addrClt, sizeof(package));
		}
		seq++;
	}
	cout << "文件" << fileName << "传输完成！" << endl;
}

DWORD WINAPI recvACK(LPVOID lparam)
{
	while (true)
	{
		for (int i = 0; i < 10;i++)
		{
			int len = sizeof(SOCKADDR);
			int recvNum = recvfrom(sockSrv, (char*)&recvBuf, sizeof(package), 0, (SOCKADDR*)&addrClt, &len);
			if (recvNum < 0 || !recvBuf.valid()) {//缓冲区为空或校验失败，继续计时
				Sleep(5);
			}
			else if (sendBase==seq+1) {//缓冲区为空，重新开始计时
				if (over) return 1;//传输过程已结束，线程终止
				i = 0;
				Sleep(5);
			}
			else if (recvBuf.getACK() && recvBuf.ack >= sendBase) {
				cout << "收   到ACK" << "	" << "R" << "	" << recvBuf.seq - ackBase << "	" << recvBuf.ack - seqBase << "	" << recvBuf.checkSum << "	" << sendBase - seqBase << "	" << seq - seqBase << endl;
				sendBase = recvBuf.ack + 1;
				i = 0;//计时器重新开始计时
			}
		}
		cout << "50ms未收到响应，即将超时重传..." << endl;
		retransmitting = true;//缓冲区上锁
		for(int i = sendBase % WINDOW;i != seq % WINDOW;i = (i+1)%WINDOW){//遍历sendBase-seq之间的所有缓冲块并发送之
			cout << "重    传" << "	" << "S" << "	" << sendBuf[i].seq - seqBase << "	" << sendBuf[i].ack - ackBase << "	" << sendBuf[i].checkSum << "	" << sendBase - seqBase << "	" << seq - seqBase << endl;
			if (!randomLoss()) {//模拟丢包
				sendto(sockSrv, (char*)&sendBuf[i], sizeof(package), 0, (SOCKADDR*)&addrClt, sizeof(package));
			}
		}
		retransmitting = false;//缓冲区解锁
	}
}

int main()
{
	//======================================================STEP0: 文件读取=============================================================
	vector<string> files;
	intptr_t handle;
	struct _finddata_t fileInfo;
	string p;
	string path = FILEPATH;
	if ((handle = _findfirst(p.assign(path).append("\\*").c_str(), &fileInfo)) == -1) {
		cout << "未找到待发送文件！请确认文件位于" << path << "后重试！";
		return -1;
	}
	else {
		do {
			if (strcmp(fileInfo.name, ".") && strcmp(fileInfo.name, "..")) {//过滤"."和".."
				cout << "找到文件：" << fileInfo.name << endl;
				files.push_back(fileInfo.name);
			}
		} while (_findnext(handle, &fileInfo) == 0);
		_findclose(handle);
	}
	//=====================================================STEP1: 建立连接==============================================================
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
	//cout << "请输入欲使用的网络端口号：";
	//cin >> port;
	addrSrv.sin_port = htons(port);
	connectState = bind(sockSrv, (SOCKADDR*)&addrSrv, sizeof(SOCKADDR));
	if (connectState != 0) {
		cout << "bind失败！错误码：" << WSAGetLastError() << endl;
		return -1;
	}
	else cout << "bind成功！" << endl;

	srand((unsigned)time(NULL));

	cout << "服务器已启动，等待连接请求中..." << endl;
	cout << "动     作" << "	" << "S/R" << "	" << "SEQ" << "	" << "ACK" << "	" << "校验和" << endl;
	//LISTEN
	//第一次握手
	while (!establish())//循环监听直至收到请求
	{
		Sleep(200);
	}
	//设置套接字为非阻塞模式 
	int iMode = 1; //1：非阻塞，0：阻塞 
	ioctlsocket(sockSrv, FIONBIO, (u_long FAR*) & iMode);
	seq = seqBase = sendBase = rand();
	sendBuf[seq%WINDOW].reset(seq, ack, true, true, false, nullptr, 0);
	//SYN-RCVD
	//第二次、第三次握手
	sendAndWait();
	cout << "连接已建立！" << endl;
	//ESTABLISHED
	//=====================================================STEP2: 发送文件==============================================================
	for (auto filename : files) {
		over = false;
		DWORD dwThreadId;
		HANDLE recvThread = CreateThread(NULL, NULL, recvACK, LPVOID(0), 0, &dwThreadId);
		sendFile(filename);
		over = true;
	}
	//=====================================================STEP3: 断开连接==============================================================
	sendBuf[(++seq) % WINDOW].reset(seq, ack, true, false, true, nullptr, 0);
	cout << "数据传输完毕，即将向客户端发送断连请求..." << endl;
	//第一、二次挥手
	sendAndWait();
	//FIN-WAIT2
	int addrLen = sizeof(SOCKADDR);
	int time = 0;
	while (true)
	{
		int recvNum = recvfrom(sockSrv, (char*)&recvBuf, sizeof(package), 0, (SOCKADDR*)&addrClt, &addrLen);
		if (recvNum < 0) {//用户端下线
			Sleep(500);
			time++;
			if (time > 30) {
				break;
			}
			else continue;
		}
		if (!recvBuf.valid()) {//校验
			cout << "接收消息有误！等待重传..." << endl;
			continue;
		}
		if (recvBuf.getFIN()) {
			cout << "第三次握手" << "	" << "R" << "	" << recvBuf.seq - ackBase << "	" << recvBuf.ack - seqBase << "	" << recvBuf.checkSum << endl;
			ack = recvBuf.seq;
			sendBuf[(++seq) % WINDOW].reset(seq, ack, true, false, false, nullptr, 0);
			if (!randomLoss()) {
				sendto(sockSrv, (char*)&sendBuf, sizeof(package), 0, (SOCKADDR*)&addrClt, addrLen);
			}
			cout << "第四次挥手" << "	" << "S" << "	" << sendBuf[seq % WINDOW].seq - seqBase << "	" << sendBuf[seq % WINDOW].ack - ackBase << "	" << sendBuf[seq % WINDOW].checkSum << endl;
			time = 0;
		}

	}
	cout << "会话已结束" << endl;
	closesocket(sockSrv);
	WSACleanup();
	system("pause");
	return 0;
}