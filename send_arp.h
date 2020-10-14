#pragma once

Mac GetMacFromIP(pcap_t* handle, const char* ipAddr);
void ArpAttack(pcap_t* handle, const Mac my_Mac, const char* send_Ip, const char* tar_Ip);

