#ifndef FLTS_H
#define FLTS_H

#include <string>

class MPEGTS
{
public:
	explicit MPEGTS(int, std::string);
	virtual int sentMPEGTSPacket();
private:
	std::string ip_;
	int port_;

};

#endif // !FLTS_H