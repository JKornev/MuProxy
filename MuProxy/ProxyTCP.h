#pragma  once

#define WIN32_LEAN_AND_MEAN

#include <Windows.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <map>
#include <list>

#pragma comment(lib, "ws2_32.lib")

#define PROXY_DBG_MSG

#ifdef PROXY_DBG_MSG
#define _DBG_OUTPUT(msg)	EnterCriticalSection(&_csect_dbg); \
							std::cout << msg << std::endl; \
							LeaveCriticalSection(&_csect_dbg)
#else
#define _DBG_OUTPUT(msg)
#endif

#define INVALID_CONN_ID (unsigned int)-1

typedef bool (*tcp_proxy_connect_filter)(unsigned int id, sockaddr_in *addr, void *param);
typedef void (*tcp_proxy_close_filter)(unsigned int id, void *param);
typedef int (*tcp_proxy_traffic_filter)(unsigned int id, char *buf, unsigned int size, unsigned int max_size, void *param);

class CProxyTCP {
private:
	typedef struct _Proxy_Client {
		unsigned int id;
		volatile bool started;
		bool client_init;
		bool server_init;
		HANDLE hevent_init;
		HANDLE hevent_sync;
		SOCKET client;
		SOCKET server;
	} Proxy_Client, *PProxy_Client;

	volatile bool _started;

	unsigned int _guid;

	CRITICAL_SECTION _csect;
	CRITICAL_SECTION _csect_dbg;

	SOCKET _serv_sock;

	sockaddr_in _serv_addr;

	HANDLE _hevent_start;
	HANDLE _hevent_stop;

	std::list<PProxy_Client> _conn;
	std::list<unsigned int> _removed_conn;

	std::map<unsigned int, std::pair<HANDLE, HANDLE>> _hthr_pool;

	tcp_proxy_connect_filter _connect_callback;
	void *_connect_param;

	tcp_proxy_close_filter _close_callback;
	void *_close_param;

	tcp_proxy_traffic_filter _send_callback;
	void *_send_param;

	tcp_proxy_traffic_filter _recv_callback;
	void *_recv_param;

	unsigned int GenGuid() { return _guid++; }

	inline bool CreateSockAddr(const char *addr, unsigned short port, sockaddr_in *psaddr);

	unsigned int AddConnInfo(SOCKET client);
	PProxy_Client GetFreeClientConnInfo();
	PProxy_Client GetFreeServerConnInfo();
	bool RemoveConnInfo(unsigned int conn_id);
	void RemoveAllConnInfo();

	void ClearClosedResources();

	inline void ConnectionCtrl();
	inline void SendCtrl(PProxy_Client client);
	inline void RecvCtrl(PProxy_Client client);

	static unsigned int __stdcall proxy_conn_gate(void *param);
	static unsigned int __stdcall proxy_send_gate(void *param);
	static unsigned int __stdcall proxy_recv_gate(void *param);

public:
	CProxyTCP();
	~CProxyTCP();

	bool Start(const char *src_addr, unsigned short src_port, const char *dest_addr, unsigned short dest_port);
	void Stop();

	bool IsStarted();

	void RegConnectFilter(tcp_proxy_connect_filter callback, void *param);
	void UnregConnectFilter();

	void RegCloseFilter(tcp_proxy_close_filter callback, void *param);
	void UnregCloseFilter();

	void RegSendFilter(tcp_proxy_traffic_filter callback, void *param);
	void UnregSendFilter();

	void RegRecvFilter(tcp_proxy_traffic_filter callback, void *param);
	void UnregRecvFilter();
};