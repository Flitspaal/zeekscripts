#include "MPEGTS.h"

#include <iostream>
#include <cstring>
#include <winsock2.h>
#include <WS2tcpip.h>
#pragma comment(lib, "ws2_32.lib")  // Link with ws2_32.lib

// Constructor: Initialize port and IP
MPEGTS::MPEGTS(int p, std::string ip)
{
    this->port_ = p;
    this->ip_ = ip;
}

// Function to send a UDP packet as MPEG-TS
int MPEGTS::sentMPEGTSPacket()
{
    // Step 1: Init Winsock
    WSADATA wsaData;
    int wsResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsResult != 0) {
        std::cerr << "WSAStartup failed: " << wsResult << std::endl;
        return 1;
    }

    // Step 2: Create a UDP socket
    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        std::cerr << "Socket creation failed: " << WSAGetLastError() << std::endl;
        WSACleanup();
        return 1;
    }

    // Step 3: Define the server address and port using the member variables
    sockaddr_in serverAddr{};
    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(port_);  // Use the port from the constructor
    inet_pton(AF_INET, ip_.c_str(), &serverAddr.sin_addr);  // Use the IP address from the constructor

    // Step 4: Construct the MPEG-TS packet
    unsigned char packet[188];  // MPEG-TS packets are 188 bytes in size
    packet[0] = 0x47;  // Sync byte (0x47 is the standard sync byte in MPEG-TS packets)

    // Set the PID (Packet Identifier) in the packet. Here we use 0x0100 (for video stream).
    packet[1] = 0x10;  // This byte includes part of the PID
    packet[2] = 0x00;  // This byte includes the rest of the PID

    // Adaptation field and scrambling control (not needed for basic packets)
    packet[3] = 0x10;  // Adaptation field control (no adaptation field, payload only)

    // Remaining part of the packet (you can add your actual stream data here)
    const char* payload = "MPEG-TS Data!";
    std::memset(&packet[4], 0x00, 184);  // Fill the payload space with zeros or actual data
    std::memcpy(&packet[4], payload, strlen(payload));  // Copy the payload data into the packet

    // Step 5: Send the packet
    int bytesSent = sendto(sock, reinterpret_cast<const char*>(packet), 188, 0,
        (struct sockaddr*)&serverAddr, sizeof(serverAddr));
    if (bytesSent == SOCKET_ERROR) {
        std::cerr << "Error sending packet: " << WSAGetLastError() << std::endl;
    }
    else {
        std::cout << "Packet sent (" << bytesSent << " bytes).\n";
    }

    // Step 6: Close the socket
    closesocket(sock);

    // Step 7: Cleanup Winsock
    WSACleanup();
    std::cout << "Finished!" << std::endl;
    return 0;
}
