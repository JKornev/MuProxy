#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <iostream>
#include <vector>
#include <map>
#include <Windows.h>
#include "ProxyTCP.h"
#include "Encrypt.h"

using namespace std;

#define CONFIG_DIR "proxy"
#define CONFIG_FILE ".\\muproxy.ini"

#define output(msg)	EnterCriticalSection(&_csect_dump); \
					std::cout << msg << std::endl; \
					LeaveCriticalSection(&_csect_dump)

#pragma pack(push, 1)

typedef struct _C1_Packet_Header {
	unsigned char type;
	unsigned char size;
	unsigned char subtype;
	unsigned char data[1];
} C1_Packet_Header, *PC1_Packet_Header;

typedef struct _C2_Packet_Header {
	unsigned char type;
	unsigned short size;
	unsigned char subtype;
	unsigned char data[1];
} C2_Packet_Header, *PC2_Packet_Header;

#pragma pack(pop)

typedef struct _MUProxy_Info {
	CProxyTCP proxy;
	string src_ip;
	unsigned short src_port;
	string dest_ip;
	unsigned short dest_port;
} MUProxy_Info, *PMUProxy_Info;

enum Crypt_Key_Type {
	CKT_SEND,
	CKT_RECV
};

list<PMUProxy_Info> _cs_proxy;
list<PMUProxy_Info> _gs_proxy;

bool _cs_proxy_enable = false;
bool _gs_proxy_enable = false;
bool _dump_enable = false;
bool _recrypt_enable = false;

CRITICAL_SECTION _csect_dump;

CSimpleModulus _crypt_orig_enc,
			   _crypt_orig_dec,
			   _crypt_proxy_serv_enc,
			   _crypt_proxy_serv_dec,
			   _crypt_proxy_client_enc,
			   _crypt_proxy_client_dec;

typedef struct _Packet_Append_Context {
	enum { MAX_PACHET_SIZE = 2048 };
	char buf[MAX_PACHET_SIZE];
	unsigned int current_size;
	unsigned int packet_size;
} Packet_Append_Context, *PPacket_Append_Context;

vector< map<unsigned int, Packet_Append_Context> > _gs_append;

int get_input_string_line(char *buffer, unsigned int buf_size)
{// Read line from stdin
	unsigned int readed = 0, 
		i = 0;
	do {
		if (i >= buf_size ) {
			return 0;
		}

		buffer[i] = getchar();
		if (buffer[i] == '\n') {
			break;
		}
		readed++;
	} while (++i);
	buffer[i] = NULL;
	return readed;
}

void hex_dump(char *buf, int size)
{
	for (int i = 0; i < size; i++) {
		printf("%02hX ", (unsigned char)buf[i]);
	}
	printf("\n");
}

HANDLE _hcons = INVALID_HANDLE_VALUE;
WORD _console_default = 0;

inline void set_console_color(WORD color)
{
	SetConsoleTextAttribute(_hcons, color);
}

inline void restore_console_color()
{
	SetConsoleTextAttribute(_hcons, _console_default);
}

void init_console_color(WORD default_color)
{
	_hcons = GetStdHandle(STD_OUTPUT_HANDLE);
	_console_default = default_color;
	restore_console_color();
}

inline void dump(unsigned short color, char *buf, unsigned int size, int num, const char *name, const char *type)
{
	EnterCriticalSection(&_csect_dump);
	set_console_color(color);
	cout << name << "[" << num << "]::" << type << " ";
	hex_dump(buf, size);
	restore_console_color();
	LeaveCriticalSection(&_csect_dump);
}

void redirect_cs_info_packet(char *buf, unsigned int size)
{
	list<PMUProxy_Info>::iterator it;
	PMUProxy_Info pinfo;
	char *addr;
	unsigned short port;
	bool found = false;

	if (!_gs_proxy_enable || size < 0x16 || (unsigned char)buf[0] != 0xC1 || (unsigned char)buf[2] != 0xF4) {
		return;
	}

	addr = &buf[4];
	port = *(unsigned short *)&buf[20];

	it = _gs_proxy.begin();
	while (it != _gs_proxy.end()) {
		pinfo = *it;
		if (!strcmp(pinfo->dest_ip.c_str(), addr) && pinfo->dest_port == port) {
			found = true;
			break;
		}
		it++;
	}
	if (!found) {
		output("CS redirect failed");
		return;
	}

	output("CS redirect from " << addr << ":" << port << " to " << pinfo->src_ip.c_str() << ":" << pinfo->src_port);

	strcpy(addr, pinfo->src_ip.c_str());
	memcpy(&buf[20], &pinfo->src_port, sizeof(short));

	return;
}

void redirect_gs_servmove_packet(char *buf, unsigned int size)
{
	list<PMUProxy_Info>::iterator it;
	PMUProxy_Info pinfo;
	char *addr;
	unsigned short port;
	bool found = false;

	if (!_gs_proxy_enable || size != 39 || (unsigned char)buf[1] != 0xB1 || (unsigned char)buf[2] != 0x00) {
		return;
	}

	addr = &buf[3];
	port = *(unsigned short *)&buf[19];

	it = _gs_proxy.begin();
	while (it != _gs_proxy.end()) {
		pinfo = *it;
		if (!strcmp(pinfo->dest_ip.c_str(), addr) && pinfo->dest_port == port) {
			found = true;
			break;
		}
		it++;
	}
	if (!found) {
		output("GS redirect failed");
		return;
	}

	output("GS redirect from " << addr << ":" << port << " to " << pinfo->src_ip.c_str() << ":" << pinfo->src_port);

	strcpy(addr, pinfo->src_ip.c_str());
	memcpy(&buf[19], &pinfo->src_port, sizeof(short));
}

inline void init_append_context()
{
	if (_gs_proxy.size() > 0) {
		_gs_append.insert(_gs_append.begin(), _gs_proxy.size(), map<unsigned int, Packet_Append_Context>());
	}
}

inline bool append_packet(unsigned int id, char *buf, unsigned int &size, unsigned int max_size, int num, 
	unsigned int *packet_size, Crypt_Key_Type key_type) 
{
	map<unsigned int, Packet_Append_Context>::iterator it = _gs_append[num].find(id);
	PPacket_Append_Context context;
	unsigned char header, head_buf[16];
	PC1_Packet_Header pC1;
	PC2_Packet_Header pC2;
	unsigned short curr_size;

	if (it == _gs_append[num].end()) {
		output("Error, append context not found");
		return false;
	}

	context = &it->second;
	*packet_size = 0;

	if (context->current_size == 0) {
		header = (unsigned char)buf[0];

		if (header < 0xC1 || header > 0xC4) {
			output("Incorrect packet header");
			return false;
		}

		//too small header fragment
		if (header == 0xC3 && size == 1) {
			context->buf[0] = header;
			context->current_size = size;
			return false;
		} else if (header == 0xC4 && size < 3) {
			memcpy(context->buf, buf, size);
			output("Packet fragment [" << size << "-unk]");
			context->current_size = size;
			return false;
		}

		//calc packet size
		if (header == 0xC1 || header == 0xC3) {
			pC1 = (PC1_Packet_Header)buf;
			curr_size = pC1->size;
		} else {
			pC2 = (PC2_Packet_Header)buf;
			curr_size = (pC2->size << 8) | (pC2->size >> 8);
		}

		if (curr_size > size) {
			memcpy(context->buf, buf, size);
			context->current_size = size;
			output("Packet fragment [" << size << "-" << curr_size << "]");
			return false;
		}

		*packet_size = curr_size;
	} else {
		//need calc size
		if (context->packet_size == 0) {
			if (context->buf[0] == 0xC1 || context->buf[0] == 0xC3) {
				context->buf[1] = buf[0];
				context->packet_size = buf[0];
			} else {
				unsigned int i, a;
				for (i = context->current_size, a = 0; i < 3 && a < size; i++, a++) {
					context->buf[i] = buf[a];
				}

				if (i <= 2) {
					context->current_size = i;
					return false;
				}

				curr_size = *(unsigned short *)&context->buf[1];
				context->packet_size = ((curr_size << 8) & 0xFFFF) | (curr_size >> 8);
			}
		}

		curr_size = context->packet_size - context->current_size;
		if (curr_size > size) {
			memcpy(&context->buf[context->current_size], buf, size);
			context->current_size += size;
			return false;
		}

		memmove((void *)((uintptr_t)buf + context->current_size), buf, size);
		memcpy(buf, context->buf, context->current_size);

		size += context->current_size;
		*packet_size = context->packet_size;

		context->current_size = 0;
		context->packet_size = 0;
	}

	return true;
}

unsigned int gs_encdec_recryptor(unsigned int id, char *buf, unsigned int size, unsigned int max_size, 
	int num, Crypt_Key_Type key_type)
{
	unsigned int offset = 0,
		retn_size = 0,
		packet_size;
	char temp[Packet_Append_Context::MAX_PACHET_SIZE], temp2[Packet_Append_Context::MAX_PACHET_SIZE];

	while (append_packet(id, &buf[offset], size, max_size, num, &packet_size, key_type)) {
		//recrypt packet
		if ((unsigned char)buf[offset] == 0xC3 || (unsigned char)buf[offset] == 0xC4) {
			unsigned int crypt_offset, crypt_size;

			crypt_offset = ((unsigned char)buf[offset] == 0xC3 ? 2 : 3);
			crypt_size = packet_size - crypt_offset;
			crypt_offset += offset;

			if (crypt_size > 0) {
				int new_size;

				if (key_type == CKT_RECV) {
					new_size = _crypt_orig_dec.Decrypt(NULL, &buf[crypt_offset], crypt_size);
					new_size = _crypt_orig_dec.Decrypt(temp, &buf[crypt_offset], crypt_size);
					if (new_size == -1) {
						output("Error, can't unpack packet");
					}

					redirect_gs_servmove_packet(temp, new_size);

					new_size = _crypt_proxy_serv_enc.Encrypt(NULL, temp, new_size);
					new_size = _crypt_proxy_serv_enc.Encrypt(temp2, temp, crypt_size);
					if (new_size == -1) {
						output("Error, can't pack packet");
					}
				} else {
					new_size = _crypt_proxy_serv_dec.Decrypt(NULL, &buf[crypt_offset], crypt_size);
					new_size = _crypt_proxy_serv_dec.Decrypt(temp, &buf[crypt_offset], crypt_size);
					if (new_size == -1) {
						output("Error, can't unpack packet");
					}

					redirect_gs_servmove_packet(temp, new_size);

					new_size = _crypt_orig_enc.Encrypt(NULL, temp, new_size);
					new_size = _crypt_orig_enc.Encrypt(temp2, temp, crypt_size);
					if (new_size == -1) {
						output("Error, can't pack packet");
					}
				}

				memcpy(&buf[crypt_offset], temp2, crypt_size);
			}
		}

		size -= packet_size;
		max_size -= packet_size;
		retn_size += packet_size;
		offset += packet_size;

		if (size == 0) {
			break;
		}
	}

	return retn_size;
}

int cs_recv_proxy_filter(unsigned int id, char *buf, unsigned int size, unsigned int, void *param)
{
	int num = (int)param;

	redirect_cs_info_packet(buf, size);

	if (_dump_enable) {
		dump(FOREGROUND_RED, buf, size, num, "CS", "RECV");
	}

	return size;
}

int cs_send_proxy_filter(unsigned int id, char *buf, unsigned int size, unsigned int, void *param)
{
	int num = (int)param;

	if (_dump_enable) {
		dump(FOREGROUND_GREEN, buf, size, num, "CS", "SEND");
	}

	return size;
}

int gs_recv_proxy_filter(unsigned int id, char *buf, unsigned int size, unsigned int max_size, void *param)
{
	int num = (int)param;

	if (_dump_enable) {
		dump(FOREGROUND_RED, buf, size, num, "GS", "RECV");
	}
	
	if (_recrypt_enable) {
		size = gs_encdec_recryptor(id, buf, size, max_size, num, CKT_RECV);
	}

	return size;
}

int gs_send_proxy_filter(unsigned int id, char *buf, unsigned int size, unsigned int max_size, void *param)
{
	int num = (int)param;

	if (_dump_enable) {
		dump(FOREGROUND_GREEN, buf, size, num, "GS", "SEND");
	}

	if (_recrypt_enable) {
		size = gs_encdec_recryptor(id, buf, size, max_size, num, CKT_SEND);
	}

	return size;
}

bool gs_proxy_connect_filter(unsigned int id, sockaddr_in *addr, void *param)
{
	int num = (int)param;
	Packet_Append_Context context = {};
	
	output("GS[" << num << "] open connection #" << id);
	_gs_append[num].insert(pair<unsigned int, Packet_Append_Context>(id, context));

	return true;
}

void gs_proxy_close_filter(unsigned int id, void *param)
{
	int num = (int)param;
	output("GS[" << num << "] close connection #" << id);
	_gs_append[num].erase(id);
}

bool cs_proxy_connect_filter(unsigned int id, sockaddr_in *addr, void *param)
{
	int num = (int)param;
	output("CS[" << num << "] open connection #" << id);
	return true;
}

void cs_proxy_close_filter(unsigned int id, void *param)
{
	int num = (int)param;
	output("CS[" << num << "] close connection #" << id);
}

PMUProxy_Info create_proxy_info(char *conf)
{
	char src_addr[MAX_PATH], dest_addr[MAX_PATH];
	unsigned short src_port, dest_port;
	PMUProxy_Info pinfo;

	if (sscanf(conf, "%s %hu %s %hu", &src_addr, &src_port, &dest_addr, &dest_port) < 4) {
		return NULL;
	}

	try {
		pinfo = new MUProxy_Info;
	} catch (...) {
		return NULL;
	}

	pinfo->src_ip = src_addr;
	pinfo->src_port = src_port;
	pinfo->dest_ip = dest_addr;
	pinfo->dest_port = dest_port;

	return pinfo;
}

int load_proxy_config(char *arr_name, list<PMUProxy_Info> &conf_list)
{
	char key_name[MAX_PATH], input[MAX_PATH] = {};
	PMUProxy_Info pinfo;
	int count = 0;
	DWORD retn_size;

	while (count < 100) {
		sprintf_s(key_name, "%s%02d", arr_name, count);
		count++;

		retn_size = GetPrivateProfileStringA(CONFIG_DIR, key_name, "", input, MAX_PATH, CONFIG_FILE);
		if (retn_size < 20) {
			continue;
		}

		pinfo = create_proxy_info(input);
		if (!pinfo) {
			continue;
		}

		conf_list.push_back(pinfo);
	}

	return count;
}

bool load_crypt_keys()
{
	char format[MAX_PATH],  key_path[MAX_PATH];
	DWORD retn_size;

	retn_size = GetPrivateProfileStringA(CONFIG_DIR, "encdec_key_proxy", "", format, MAX_PATH, CONFIG_FILE);
	if (!retn_size) {
		return false;
	}

	sprintf_s(key_path, format, "enc1");
	if (!_crypt_proxy_client_enc.LoadEncryptionKey(key_path)) {
		return false;
	}

	sprintf_s(key_path, format, "dec2");
	if (!_crypt_proxy_client_dec.LoadDecryptionKey(key_path)) {
		return false;
	}

	sprintf_s(key_path, format, "enc2");
	if (!_crypt_proxy_serv_enc.LoadEncryptionKey(key_path)) {
		return false;
	}

	sprintf_s(key_path, format, "dec1");
	if (!_crypt_proxy_serv_dec.LoadDecryptionKey(key_path)) {
		return false;
	}

	retn_size = GetPrivateProfileStringA(CONFIG_DIR, "encdec_key_orig", "", format, MAX_PATH, CONFIG_FILE);
	if (!retn_size) {
		return false;
	}

	sprintf_s(key_path, format, "enc1");
	if (!_crypt_orig_enc.LoadEncryptionKey(key_path)) {
		return false;
	}

	sprintf_s(key_path, format, "dec2");
	if (!_crypt_orig_dec.LoadDecryptionKey(key_path)) {
		return false;
	}

	return true;
}

void release_proxy_config(list<PMUProxy_Info> &conf_list)
{
	list<PMUProxy_Info>::iterator it = conf_list.begin();
	while (it != conf_list.end()) {
		delete *it;
		it++;
	}
	conf_list.clear();
}

void enum_connect_details(char *arr_name, list<PMUProxy_Info> &conf_list)
{
	list<PMUProxy_Info>::iterator it = conf_list.begin();
	PMUProxy_Info pinfo;
	int num = 0;

	while (it != conf_list.end()) {
		pinfo = *it;
		cout << " " << arr_name << " #" << num << ":" << endl
			 << "  Listen from " << pinfo->src_ip.c_str() << ":" << pinfo->src_port << endl
			 << "  Redirect to " << pinfo->dest_ip.c_str() << ":" << pinfo->dest_port << endl;

		it++, num++;
	}
}

bool startup_proxy_list(char *arr_name, list<PMUProxy_Info> &conf_list, 
	tcp_proxy_connect_filter connect_filter, tcp_proxy_close_filter close_filter,
	tcp_proxy_traffic_filter send_filter, tcp_proxy_traffic_filter recv_filter) 
{
	list<PMUProxy_Info>::iterator it = conf_list.begin();
	PMUProxy_Info pinfo;
	int num = 0;

	while (it != conf_list.end()) {
		pinfo = *it;
		
		cout << "Startup " << arr_name << " #" << num << " ..." << endl;

		pinfo->proxy.RegConnectFilter(connect_filter, (void *)num);
		pinfo->proxy.RegCloseFilter(close_filter, (void *)num);
		pinfo->proxy.RegSendFilter(send_filter, (void *)num);
		pinfo->proxy.RegRecvFilter(recv_filter, (void *)num);

		if (!pinfo->proxy.Start(NULL, pinfo->src_port, pinfo->dest_ip.c_str(), pinfo->dest_port)) {
			cout << "Fail!" << endl;
			return false;
		} else {
			cout << "Successful!" << endl;
		}

		it++, num++;
	}

	return true;
}

int main()
{
	int res;
	WSADATA wsa_data;
	char cmd_line[MAX_PATH];

	_gs_append.reserve(100);

	InitializeCriticalSection(&_csect_dump);
	init_console_color(7);

	cout << "===================================================" << endl
		 << "   Welcome to Mu Encrypt Bypass Proxy Module v1.0" << endl
		 << "           http://armored.pro <c> 2014" << endl
		 << "===================================================" << endl;

	res = WSAStartup(MAKEWORD(2,2), &wsa_data);
	if (res != 0) {
		cout << "Error, WSAStartup() failed with code: " << res << "!" << endl;
		return 1;
	}

	_dump_enable = (GetPrivateProfileIntA(CONFIG_DIR, "dump_hex", 0, CONFIG_FILE) == 0 ? false : true);
	_recrypt_enable = (GetPrivateProfileIntA(CONFIG_DIR, "encdec", 0, CONFIG_FILE) == 0 ? false : true);
	_cs_proxy_enable = (load_proxy_config("connectserver", _cs_proxy) > 0 ? true : false);
	_gs_proxy_enable = (load_proxy_config("gameserver", _gs_proxy) > 0 ? true : false);

	__try {
		if (!_cs_proxy_enable && !_gs_proxy_enable) {
			cout << "Error, all proxy modules are disabled" << endl;
			return 1;
		}

		if (_recrypt_enable && !load_crypt_keys()) {
			cout << "Error, can't load crypt keys" << endl;
			return 1;
		}

		cout << "Configuration details:" << endl;

		if (_cs_proxy_enable) {
			enum_connect_details("Connect Server", _cs_proxy);
		} else {
			cout << "Connect Server proxy is disabled" << endl;
		}

		if (_gs_proxy_enable) {
			enum_connect_details("Game Server", _gs_proxy);
			init_append_context();
		} else {
			cout << "Game Server proxy is disabled" << endl;
		}

		cout << " Encryption bypass: " << (_recrypt_enable ? "Enable" : "Disable") << endl;
		cout << " Display traffic: " << (_dump_enable ? "Enable" : "Disable") << endl;

		if (_cs_proxy_enable && !startup_proxy_list("Connect Server", _cs_proxy, cs_proxy_connect_filter,
			cs_proxy_close_filter, cs_send_proxy_filter, cs_recv_proxy_filter)) {
			return 1;
		}
		if (_gs_proxy_enable && !startup_proxy_list("Game Server", _gs_proxy, gs_proxy_connect_filter,
			gs_proxy_close_filter, gs_send_proxy_filter, gs_recv_proxy_filter)) {
			return 1;
		}

		cout << "Command list: stop, dumpon, dumpoff" << endl;
		while (true) {
			cout << "Type command:" << endl;

			get_input_string_line(cmd_line, MAX_PATH);

			if (!strcmp(cmd_line, "stop")) {
				cout << "Aborting ..." << endl;
				break;
			} else if (!strcmp(cmd_line, "dumpon")) {
				cout << "Display traffic dump: ON" << endl;
				_dump_enable = true;
			} else if (!strcmp(cmd_line, "dumpoff")) {
				cout << "Display traffic dump: OFF" << endl;
				_dump_enable = false;
			}
		}
	} __finally {
		release_proxy_config(_cs_proxy);
		release_proxy_config(_gs_proxy);
		WSACleanup();
	}
	
	cout << "Proxy module terminated" << endl;

	DeleteCriticalSection(&_csect_dump);
	return 0;
}