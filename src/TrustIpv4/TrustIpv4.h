/*
 * TrustIpv4.h
 *
 *  Created on: Apr 30, 2026
 *      Author: hemzakareche
 */

#ifndef TRUSTIPV4_TRUSTIPV4_H_
#define TRUSTIPV4_TRUSTIPV4_H_

#include "inet/networklayer/ipv4/Ipv4.h"

namespace inet {

class INET_API TrustIpv4 : public Ipv4 {

    protected:

        double dropProbability;
        bool isMalicious;

        long receivedDataPackets;
        long forwardedDataPackets;
        long droppedDataPackets;

        virtual void initialize(int stage) override;

        virtual void sendDatagramToOutput(Packet *packet) override;
        virtual void routeUnicastPacket(Packet *packet) override;

        virtual void finish() override;

}; // TrustIpv4

} // namespace inet;



#endif /* TRUSTIPV4_TRUSTIPV4_H_ */
