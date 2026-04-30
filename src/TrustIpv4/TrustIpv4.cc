/*
 * TrustIpv4.cc
 *
 *  Created on: Apr 30, 2026
 *      Author: hemzakareche
 */

#include "TrustIpv4.h"
#include "inet/networklayer/common/NextHopAddressTag_m.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/linklayer/common/InterfaceTag_m.h"
#include "inet/linklayer/common/MacAddressTag_m.h"

#include "inet/transportlayer/udp/UdpHeader_m.h"

namespace inet {

Define_Module(TrustIpv4);

void TrustIpv4::initialize(int stage) {
    Ipv4::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {

        dropProbability = par("dropProbability");
        isMalicious = par("isMalicious");

        receivedDataPackets = par("receivedDataPackets");
        forwardedDataPackets = par("forwardedDataPackets");
        droppedDataPackets = par("droppedDataPackets");

        if(isMalicious) {
            EV << "[MaliciousIpv4] Initialized."<< endl;
        }

        EV << "[TrustIpv4] Initialized."<< endl;
    }
}

void TrustIpv4::sendDatagramToOutput(Packet *packet) {
    const NetworkInterface *ie = ift->getInterfaceById(packet->getTag<InterfaceReq>()->getInterfaceId());
    auto nextHopAddressReq = packet->findTag<NextHopAddressReq>();
    Ipv4Address nextHopAddr = nextHopAddressReq->getNextHopAddress().toIpv4();
    if (!ie->isBroadcast() || ie->getMacAddress().isUnspecified()) // we can't do ARP
        sendPacketToNIC(packet);
    else {
        MacAddress nextHopMacAddr = resolveNextHopMacAddress(packet, nextHopAddr, ie);
        if (nextHopMacAddr.isUnspecified()) {
            EV_INFO << "Pending " << packet << " to ARP resolution.\n";
            pendingPackets[nextHopAddr].insert(packet);
        }
        else {
            ASSERT2(!containsKey(pendingPackets, nextHopAddr), "Ipv4-ARP error: nextHopAddr found in ARP table, but Ipv4 queue for nextHopAddr not empty");
            packet->addTagIfAbsent<MacAddressReq>()->setDestAddress(nextHopMacAddr);
            sendPacketToNIC(packet);
        }
    }
}

void TrustIpv4::routeUnicastPacket(Packet *packet) {

    const auto& ipHeader = packet->peekAtFront<Ipv4Header>();
    if(ipHeader->getProtocolId() == IP_PROT_UDP) {
        const auto& udpHeader = packet->peekDataAt<UdpHeader>(ipHeader->getChunkLength());
        if(udpHeader->getDestPort() == 654 || udpHeader->getSrcPort() == 654) {
            Ipv4::routeUnicastPacket(packet);
            return;
        }
    }

    receivedDataPackets++;
    if(isMalicious) {
        double r =  getRNG(1)->doubleRand();
        if(r < dropProbability) {
            EV_WARN << "[ATTACK] Selectively DROPPING."<< endl;

            droppedDataPackets++;
            delete packet;
            return;
        }
    }

    forwardedDataPackets++;
    Ipv4::routeUnicastPacket(packet);
}

void TrustIpv4::finish() {
    recordScalar("receivedDataPackets", receivedDataPackets);
    recordScalar("forwardedDataPackets", forwardedDataPackets);
    recordScalar("droppedDataPackets", droppedDataPackets);
}
}


