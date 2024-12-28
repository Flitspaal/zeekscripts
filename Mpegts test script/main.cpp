#include <iostream>
#include <list>

#include "MPEGTS.h"


int main()
{
	std::string check1 = "Y";
	while (check1 == "Y" || check1 == "y")
	{
		std::cerr << "enter an IP: ";
		std::string ip;
		std::cin >> ip;
		MPEGTS newPCKT(5555, ip);
		newPCKT.sentMPEGTSPacket();
		std::cout << "test more ip's? Y/N: ";
		std::cin >> check1;
	}
	std::cout << "exiting program";
}