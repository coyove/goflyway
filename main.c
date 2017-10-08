#include "main.h"

void callback(unsigned long long ts, char* msg)
{
    printf("%s zzz\n", msg);
}

#define EXPORT __declspec(dllexport) 

EXPORT int gofw_start(
    char* log_level, char* china_list, g_callback log_callback, g_callback err_callback, 
    char* upstream, char* localaddr, char* auth, char* key, int partial, int dns_size, int udp_port, int udp_tcp)
{
    return StartServer(log_level, china_list, log_callback, err_callback, upstream, localaddr, auth, key, partial, dns_size, udp_port, udp_tcp);
}

EXPORT void gofw_stop()
{
    StopServer();
}

EXPORT char* gofw_nickname()
{
    return GetNickname();
}

EXPORT void gofw_switch(int type)
{
    SwitchProxyType(type);
}

int main(int argc, char const *argv[])
{
    gofw_start("dbg", "", callback, callback, "128.wipe.pw:8100", ":8200", "", "01234567890abcdef",
            1, 1024, 8731, 3);
    printf("%s", gofw_nickname());
    while(1){}
    return 0;
}