#include "main.h"

int main(void)
{
	if (sendRawEthernet() == false)
	{
		return 1;
	}
	else
	{
		return 0;
	}
}

bool sendRawEthernet()
{
	pcap_if_t* allDevices = nullptr;
	pcap_if_t* device = nullptr;

	char errbuf[PCAP_ERRBUF_SIZE];

	if (pcap_findalldevs(&allDevices, errbuf) == -1 || allDevices == nullptr)
	{
		printError(__func__, __LINE__, errbuf);
		return false;
	}

	int i = 0;
	for (device = allDevices; device != nullptr; device = device->next)
	{
		printf("%d. %s", i++, device->name);
		if (device->description)
			printf(" (%s)\n", device->description);
		else
			printf(" (No description available)\n");
	}
	if (i == 0)
	{
		printError(__func__, __LINE__, "No interfaces found");
	}

	const int select = 6;
	/*
	// If you want to choose device yourself
	int select = -1;
	do{
		std::cout << "Device: #";
		std::cin >> select;
		if (std::cin.fail()) {
			std::cin.clear();
			std::cin.ignore();
			select = -1;
		}
	} while (select == -1);
	*/
	i = 0;
	for (device = allDevices; device != nullptr; device = device->next)
	{
		if (i == select) {
			break;
		}
		i++;
	}

	if (device == nullptr)
	{
		printError(__func__, __LINE__, "Failed to get device");
		return false;
	}

	pcap_t* pcap;
	pcap = pcap_open_live(device->name,
		260,	// capture size
		1,		// 1: capture all packet
		1000, // Timeout ms
		errbuf);
	
	if (pcap == nullptr)
	{
		printError(__func__, __LINE__, "Failed to open the adapter");
		return false;
	}

	std::vector<unsigned char> packet(std::begin(packetQuery), std::end(packetQuery));
	if (pcap_sendpacket(pcap, packet.data(), packet.size()) != 0)
	{
		printError(__func__, __LINE__, "");
		return false;
	}

	return true;
}

void printError(const char* func, int line, const char* err)
{
	std::cerr << func << "@" << line << ":" << err << std::endl;
}
