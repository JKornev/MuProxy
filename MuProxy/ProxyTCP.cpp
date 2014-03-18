#include "ProxyTCP.h"
#include <process.h>

using namespace std;


CProxyTCP::CProxyTCP() : 
	_guid(0),
	_started(false), 
	_hevent_start(NULL),
	_hevent_stop(NULL),
	_serv_sock(INVALID_SOCKET),
	_connect_callback(NULL),
	_connect_param(NULL),
	_close_callback(NULL),
	_close_param(NULL),
	_send_callback(NULL),
	_send_param(NULL),
	_recv_callback(NULL),
	_recv_param(NULL)
{
	InitializeCriticalSection(&_csect);
	InitializeCriticalSection(&_csect_dbg);
}

CProxyTCP::~CProxyTCP()
{
	Stop();
	DeleteCriticalSection(&_csect);
	DeleteCriticalSection(&_csect_dbg);
}

bool CProxyTCP::Start(const char *src_addr, unsigned short src_port, const char *dest_addr, unsigned short dest_port)
{
	sockaddr_in addr = {};
	int res;

	if (_started) {
		_DBG_OUTPUT("Error, server already started!");
		return false;
	}

	RemoveAllConnInfo();
	_removed_conn.clear();
	_hthr_pool.clear();

	if (!CreateSockAddr(src_addr, src_port, &addr)) {
		_DBG_OUTPUT("Error, incorrect source address");
		return false;
	}
	if (!dest_addr || !CreateSockAddr(dest_addr, dest_port, &_serv_addr)) {
		_DBG_OUTPUT("Error, incorrect destination address");
		return false;
	}

	_serv_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (_serv_sock == INVALID_SOCKET) {
		_DBG_OUTPUT("Error, socket() failed with code " << WSAGetLastError());
		return false;
	}

	res = bind(_serv_sock, (sockaddr *)&addr, sizeof(addr));
	if (res == SOCKET_ERROR) {
		_DBG_OUTPUT("Error, bind() failed with code " << WSAGetLastError());
		closesocket(_serv_sock);
		return false;
	}

	_hevent_start = CreateEvent(NULL, true, false, NULL);
	if (!_hevent_start) {
		_DBG_OUTPUT("Error, CreateEvent() failed with code " << GetLastError());
		closesocket(_serv_sock);
		return false;
	}

	_hevent_stop = CreateEvent(NULL, true, true, NULL);
	if (!_hevent_start) {
		_DBG_OUTPUT("Error, CreateEvent() failed with code " << GetLastError());
		CloseHandle(_hevent_start);
		closesocket(_serv_sock);
		return false;
	}

	_started = true;

	_beginthreadex(NULL, 0, proxy_conn_gate, this, 0, NULL);

	if (WaitForSingleObject(_hevent_start, 10000) != WAIT_OBJECT_0) {
		_DBG_OUTPUT("Error, WaitForSingleObject() failed");
		Stop();
		return false;
	}

	return true;
}

void CProxyTCP::Stop()
{
	bool retn = false;
	HANDLE *pthr_pool;
	unsigned int count;

	EnterCriticalSection(&_csect);
	if (!_started) {
		retn = true;
	} else {
		_started = false;
	}
	LeaveCriticalSection(&_csect);
	if (retn) {
		return;
	}

	if (_serv_sock != INVALID_SOCKET) {
		closesocket(_serv_sock);
		_serv_sock = INVALID_SOCKET;
	}

	WaitForSingleObject(_hevent_stop, INFINITE);

	EnterCriticalSection(&_csect);
	count = _hthr_pool.size() * 2;
	if (count != 0) {
		try {
			pthr_pool = new HANDLE[count];
		} catch (...) {
			pthr_pool = NULL;
		}

		map<unsigned int, std::pair<HANDLE, HANDLE>>::iterator it = _hthr_pool.begin();
		for (unsigned int i = 0; i < count; i += 2, it++) {
			pthr_pool[i] = it->second.first;
			pthr_pool[i + 1] = it->second.second;
		}

		list<PProxy_Client>::iterator it_conn = _conn.begin();
		PProxy_Client pelem;
		for (unsigned int i = 0; i < _conn.size(); i++, it_conn++) {
			pelem = *it_conn;
			closesocket(pelem->client);
			closesocket(pelem->server);
		}
	}
	LeaveCriticalSection(&_csect);

	if (count == 0) {
		return;
	}

	if (pthr_pool == NULL) {
		Sleep(2000); //hmm...
	} else {
		WaitForMultipleObjects(count, pthr_pool, true, 2000);
	}

	RemoveAllConnInfo();
}

bool CProxyTCP::IsStarted()
{
	return _started;
}

void CProxyTCP::RegConnectFilter(tcp_proxy_connect_filter callback, void *param)
{
	_connect_callback = callback;
	_connect_param = param;
}

void CProxyTCP::UnregConnectFilter()
{
	_connect_callback = NULL;
	_connect_param = NULL;
}

void CProxyTCP::RegCloseFilter(tcp_proxy_close_filter callback, void *param)
{
	_close_callback = callback;
	_close_param = param;
}

void CProxyTCP::UnregCloseFilter()
{
	_close_callback = NULL;
	_close_param = NULL;
}

void CProxyTCP::RegSendFilter(tcp_proxy_traffic_filter callback, void *param)
{
	_send_callback = callback;
	_send_param = param;
}

void CProxyTCP::UnregSendFilter()
{
	_send_callback = NULL;
	_send_param = NULL;
}

void CProxyTCP::RegRecvFilter(tcp_proxy_traffic_filter callback, void *param)
{
	_recv_callback = callback;
	_recv_param = param;
}

void CProxyTCP::UnregRecvFilter()
{
	_recv_callback = NULL;
	_recv_param = NULL;
}

bool CProxyTCP::CreateSockAddr(const char *addr, unsigned short port, sockaddr_in *psaddr)
{
	psaddr->sin_family = AF_INET;
	psaddr->sin_port = htons(port);

	if (!addr) {
		psaddr->sin_addr.s_addr = 0;
	} else {
		psaddr->sin_addr.s_addr = inet_addr(addr);
		if (psaddr->sin_addr.s_addr == INADDR_NONE) {
			HOSTENT *host;
			host = gethostbyname(addr);
			if (!host) {
				return false;
			}
			psaddr->sin_addr.s_addr = host->h_addr[0];
		}
	}

	return true;
}

unsigned int CProxyTCP::AddConnInfo(SOCKET client)
{
	PProxy_Client pelem = new Proxy_Client;

	EnterCriticalSection(&_csect);

	__try {
		pelem->id = GenGuid();
		pelem->client = client;
		pelem->server = INVALID_SOCKET;
		pelem->client_init = false;
		pelem->server_init = false;
		pelem->started = false;

		pelem->hevent_init = CreateEvent(NULL, false, false, NULL);
		if (!pelem->hevent_init) {
			delete pelem;
			return INVALID_CONN_ID;
		}

		pelem->hevent_sync = CreateEvent(NULL, false, false, NULL);
		if (!pelem->hevent_sync) {
			CloseHandle(pelem->hevent_init);
			delete pelem;
			return INVALID_CONN_ID;
		}

		_conn.push_back(pelem);

	} __finally {
		LeaveCriticalSection(&_csect);
	}

	return pelem->id;
}

CProxyTCP::PProxy_Client CProxyTCP::GetFreeClientConnInfo()
{
	list<PProxy_Client>::iterator it;
	PProxy_Client pelem = NULL;

	EnterCriticalSection(&_csect);

	it = _conn.begin();
	while (it != _conn.end()) {
		if ((*it)->client_init == false) {
			pelem = (*it);
			pelem->client_init = true;
			break;
		}
		it++;
	}

	LeaveCriticalSection(&_csect);

	return pelem;
}

CProxyTCP::PProxy_Client CProxyTCP::GetFreeServerConnInfo()
{
	list<PProxy_Client>::iterator it;
	PProxy_Client pelem = NULL;

	EnterCriticalSection(&_csect);

	it = _conn.begin();
	while (it != _conn.end()) {
		if ((*it)->server_init == false) {
			pelem = (*it);
			pelem->server_init = true;
			break;
		}
		it++;
	}

	LeaveCriticalSection(&_csect);

	return pelem;
}

bool CProxyTCP::RemoveConnInfo(unsigned int conn_id)
{
	list<PProxy_Client>::iterator it;
	bool res = false;

	EnterCriticalSection(&_csect);

	it = _conn.begin();
	while (it != _conn.end()) {
		if ((*it)->id == conn_id) {
			(*it)->started = false;

			if ((*it)->client) {
				closesocket((*it)->client);
			}
			if ((*it)->server) {
				closesocket((*it)->server);
			}
			if ((*it)->hevent_sync) {
				SetEvent((*it)->hevent_sync);
				CloseHandle((*it)->hevent_sync);
			}
			if ((*it)->hevent_init) {
				SetEvent((*it)->hevent_init);
				CloseHandle((*it)->hevent_init);
			}

			_conn.erase(it);
			res = true;
			break;
		}
		it++;
	}

	LeaveCriticalSection(&_csect);

	return res;
}

void CProxyTCP::RemoveAllConnInfo()
{
	list<PProxy_Client>::iterator it;

	EnterCriticalSection(&_csect);

	it = _conn.begin();
	while (it != _conn.end()) {
		(*it)->started = false;

		if ((*it)->client) {
			closesocket((*it)->client);
		}
		if ((*it)->server) {
			closesocket((*it)->server);
		}
		if ((*it)->hevent_sync) {
			SetEvent((*it)->hevent_sync);
			CloseHandle((*it)->hevent_sync);
		}
		if ((*it)->hevent_init) {
			SetEvent((*it)->hevent_init);
			CloseHandle((*it)->hevent_init);
		}

		it++;
	}

	LeaveCriticalSection(&_csect);
}

void CProxyTCP::ClearClosedResources()
{
	list<unsigned int>::iterator it;

	EnterCriticalSection(&_csect);
	it = _removed_conn.begin();
	while (it != _removed_conn.end()) {
		_hthr_pool.erase(*it);
		it++;
	}
	LeaveCriticalSection(&_csect);
}

void CProxyTCP::ConnectionCtrl()
{
	SOCKET client_sock = INVALID_SOCKET;
	HANDLE hthr_client, hthr_server;
	sockaddr_in saddr;
	unsigned int id;
	int res;

	ResetEvent(_hevent_stop);
	SetEvent(_hevent_start);

	while (_started) {
		res = listen(_serv_sock, SOMAXCONN);
		if (res == SOCKET_ERROR) {
			_DBG_OUTPUT("Error, ConnectionCtrl::listen() failed with code " << res);
			break;
		}

		client_sock = accept(_serv_sock, (sockaddr *)&saddr, NULL);
		if (client_sock == INVALID_SOCKET) {
			continue;
		}

		id = AddConnInfo(client_sock);
		if (id == INVALID_CONN_ID) {
			_DBG_OUTPUT("Error, ConnectionCtrl::AddConnInfo() failed");
			continue;
		}

		if (_connect_callback) {
			if (!_connect_callback(id, &saddr, _connect_param)) {
				RemoveConnInfo(id);
				closesocket(client_sock);
				continue;
			}
		}

		//_DBG_OUTPUT(">>>> Client #" << id << " connected");

		EnterCriticalSection(&_csect);

		hthr_client = (HANDLE)_beginthreadex(NULL, 0, proxy_send_gate, this, 0, NULL);
		hthr_server = (HANDLE)_beginthreadex(NULL, 0, proxy_recv_gate, this, 0, NULL);

		_hthr_pool.insert(
			pair<unsigned int, pair<HANDLE, HANDLE>>(
				id, pair<HANDLE, HANDLE>(hthr_client, hthr_server)
			)
		);

		LeaveCriticalSection(&_csect);

		ClearClosedResources();
	}

	SetEvent(_hevent_stop);
}

void CProxyTCP::SendCtrl(PProxy_Client client)
{
	enum { MAX_BUF_LEN = 2048 };
	char recvbuf[MAX_BUF_LEN];
	int res;

	res = WaitForSingleObject(client->hevent_sync, 10000);
	if (res != WAIT_OBJECT_0) {
		_DBG_OUTPUT("Error, SendCtrl::WaitForSingleObject() failed with code " << GetLastError());
		return;
	}

	//init
	/*for(ptr = _serv_addr; ptr != NULL; ptr = ptr->ai_next) {
		client->server = socket(_serv_addr->ai_family, _serv_addr->ai_socktype, _serv_addr->ai_protocol);
		if (client->server == INVALID_SOCKET) {
			_DBG_OUTPUT("Error, SendCtrl::socket() failed with code " << WSAGetLastError());
			return;
		}

		res = connect(client->server, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (res == SOCKET_ERROR) {
			closesocket(client->server);
			client->server = INVALID_SOCKET;
			continue;
		}

		break;
	}
	if (client->server == INVALID_SOCKET) {
		return;
	}*/
	client->server = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (client->server == INVALID_SOCKET) {
		_DBG_OUTPUT("Error, SendCtrl::socket() failed with code " << WSAGetLastError());
		return;
	}

	res = connect(client->server, (sockaddr *)&_serv_addr, sizeof(_serv_addr));
	if (res == SOCKET_ERROR) {
		_DBG_OUTPUT("Error, SendCtrl::connect() failed with code " << WSAGetLastError());
		closesocket(client->server);
		client->server = INVALID_SOCKET;
		return;
	}

	client->started = true;
	SetEvent(client->hevent_init);

	//worked cycle
	while (client->started && _started) {
		res = recv(client->client, recvbuf, MAX_BUF_LEN, 0);
		if (res == 0) {
			break;
		} else if (res < 0) {
			break;
		}

		if (_send_callback) {
			res = _send_callback(client->id, recvbuf, res, MAX_BUF_LEN, _send_param);
			if (res == 0) {
				break;
			} else if (res < 0) {
				break;
			}
		}

		res = send(client->server, recvbuf, res, 0);
		if (res == SOCKET_ERROR) {
			break;
		}
	}

	client->started = false;
	closesocket(client->client);
	closesocket(client->server);

	WaitForSingleObject(client->hevent_sync, 10000);

	if (_close_callback) {
		_close_callback(client->id, _close_param);
	}

	EnterCriticalSection(&_csect);
	_removed_conn.insert(_removed_conn.begin(), client->id);
	LeaveCriticalSection(&_csect);

	//_DBG_OUTPUT("<<<< Client #" << client->id << " closed");
}

void CProxyTCP::RecvCtrl(PProxy_Client client)
{
	enum { MAX_BUF_LEN = 2048 };
	char recvbuf[MAX_BUF_LEN];
	int res;

	SetEvent(client->hevent_sync);

	res = WaitForSingleObject(client->hevent_init, 10000);
	if (res != WAIT_OBJECT_0) {
		_DBG_OUTPUT("Error, RecvCtrl::WaitForSingleObject() failed with code " << GetLastError());
		return;
	}

	//worked cycle
	while (client->started && _started) {
		res = recv(client->server, recvbuf, MAX_BUF_LEN, 0);
		if (res == 0) {
			break;
		} else if (res < 0) {
			break;
		}

		if (_recv_callback) {
			res = _recv_callback(client->id, recvbuf, res, MAX_BUF_LEN, _recv_param);
			if (res == 0) {
				break;
			} else if (res < 0) {
				break;
			}
		}

		res = send(client->client, recvbuf, res, 0);
		if (res == SOCKET_ERROR) {
			break;
		}
	}

	client->started = false;

	SetEvent(client->hevent_sync);
}

unsigned int __stdcall CProxyTCP::proxy_conn_gate(void *param)
{
	CProxyTCP *pthis = (CProxyTCP *)param;

	pthis->ConnectionCtrl();
	pthis->Stop();

	_endthreadex(0);
	return 0;
}

unsigned int __stdcall CProxyTCP::proxy_send_gate(void *param)
{
	CProxyTCP *pthis = (CProxyTCP *)param;
	PProxy_Client client;

	client = pthis->GetFreeServerConnInfo();
	if (!client) {
		_endthreadex(1);
		return 1;
	}

	pthis->SendCtrl(client);
	pthis->RemoveConnInfo(client->id);

	_endthreadex(0);
	return 0;
}

unsigned int __stdcall CProxyTCP::proxy_recv_gate(void *param)
{
	CProxyTCP *pthis = (CProxyTCP *)param;
	PProxy_Client client;

	client = pthis->GetFreeClientConnInfo();
	if (!client) {
		_endthreadex(1);
		return 1;
	}

	pthis->RecvCtrl(client);

	_endthreadex(0);
	return 0;
}
