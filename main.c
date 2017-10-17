#include "main.h"
#include <stdlib.h>

#define EXPORT __declspec(dllexport)
#define uint64 unsigned long long

EXPORT uint64 gofw_log_len()
{
    return GetLastestLogIndex();
}

EXPORT uint64 gofw_log_read(uint64 idx, char *buf)
{
    return ReadLog(idx, buf);
}

EXPORT void gofw_log_delete_since(uint64 idx)
{
    return DeleteLogSince(idx);
}

EXPORT int gofw_start(g_callback created,
    char *log_level, char *china_list, char *upstream, char *localaddr, char *auth, char *key, char *domain, int partial, int dns_size, int udp_port, int udp_tcp)
{
    return StartServer(created, log_level, china_list, upstream, localaddr, auth, key, domain, partial, dns_size, udp_port, udp_tcp);
}

EXPORT void gofw_stop()
{
    StopServer();
}

EXPORT void gofw_nickname(char *buf)
{
    GetNickname(buf);
}

EXPORT int gofw_switch(int type)
{
    return SwitchProxyType(type);
}

EXPORT void gofw_mitm(int enabled)
{
    ManInTheMiddle(enabled);
}

int main(int argc, char const *argv[])
{
    // gofw_start("dbg", "", callback, callback, ":8100", ":8100", "", "0123456789abcdef", 1, 1024, 8731, 3);
    // while(1){}
    return 0;
}