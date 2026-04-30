/*
 * PromiscuousCsmaCaMac.cc
 *
 *  Created on: Apr 30, 2026
 *      Author: hemzakareche
 */

#include "../PromiscuousCsmaCaMac/PromiscuousCsmaCaMac.h"

#include "inet/common/ModuleAccess.h"
#include "inet/linklayer/csmaca/CsmaCaMacHeader_m.h"
#include "inet/linklayer/common/MacAddressTag_m.h"
#include "inet/networklayer/common/NextHopAddressTag_m.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "inet/common/packet/printer/PacketPrinter.h"
#include "inet/networklayer/common/L3Address_m.h"

namespace inet {

Define_Module(PromiscuousCsmaCaMac);

simsignal_t PromiscuousCsmaCaMac::frameOverheardSignal =
        registerSignal("frameOverheard");

simsignal_t PromiscuousCsmaCaMac::frameSentToNextHopSignal =
        registerSignal("frameSentToNextHop");

void PromiscuousCsmaCaMac::initialize(int stage)
{
    CsmaCaMac::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        promiscuousMode = par("promiscuousMode");


        EV_INFO << "[PromiscuousCsmaCaMac] Initialized. "
                << "promiscuousMode=" << (promiscuousMode ? "true" : "false") << "\n";
    }
}

void PromiscuousCsmaCaMac::handleUpperPacket(Packet *packet)
{
    auto nextHopReq = packet->findTag<NextHopAddressReq>();
    auto macAddressReq = packet->findTag<MacAddressReq>();

    if (macAddressReq != nullptr && nextHopReq != nullptr) {
        MacAddress nextHop = macAddressReq->getDestAddress();
        L3Address nextHopIP = nextHopReq->getNextHopAddress();

        if (!nextHop.isUnspecified() && !nextHop.isBroadcast() && !nextHop.isMulticast()) {

            L3Address srcIP, dstIP;
            int ipID = -1;
            bool hasIP = extractCorrelationFields(packet, srcIP, dstIP, ipID);

            if (hasIP) {
                if(dstIP == nextHopIP) {
                    CsmaCaMac::handleUpperPacket(packet);
                    return;
                }

                OutgoingFrameEvent *event = new OutgoingFrameEvent();
                event->setNextHopMac(nextHop);
                event->setSenderMac(networkInterface->getMacAddress());
                event->setNextHopIP(nextHopIP);
                event->setSrcIP(srcIP);
                event->setDstIP(dstIP);
                event->setIpID(ipID);
                event->setByteLength(packet->getByteLength());
                event->setSentAt(simTime());

                EV_INFO << "[PromiscuousCsmaCaMac] OUTGOING via nextHop=" << nextHop
                        << "  key=" << srcIP << "->" << dstIP << "[id=" << ipID << "]\n";

                emit(frameSentToNextHopSignal, event);
                delete event;
            }
        }
    }

    CsmaCaMac::handleUpperPacket(packet);
}

bool PromiscuousCsmaCaMac::extractCorrelationFields(Packet *packet,
                                                     L3Address &srcIP,
                                                     L3Address &dstIP,
                                                     int       &ipID) const
{

    auto ipHeader = packet->peekAtFront<Ipv4Header>(b(-1), Chunk::PF_ALLOW_NULLPTR | Chunk::PF_ALLOW_INCOMPLETE | Chunk::PF_ALLOW_REINTERPRETATION);

    if (ipHeader == nullptr)
        return false;

    srcIP = ipHeader->getSrcAddress();
    dstIP = ipHeader->getDestAddress();
    ipID  = ipHeader->getIdentification();
    return true;
}

void PromiscuousCsmaCaMac::handleLowerPacket(Packet *packet)
{
    if (!promiscuousMode) {
        CsmaCaMac::handleWithFsm(packet);
        return;
    }

    if (CsmaCaMac::isForUs(packet) || CsmaCaMac::isBroadcast(packet)) {
        CsmaCaMac::handleWithFsm(packet);
    }
    else {
        const Ptr<const CsmaCaMacHeader> macHeader =
                packet->peekAtFront<CsmaCaMacHeader>();

        EV_INFO << "[PromiscuousCsmaCaMac] OVERHEARD FRAME"
                << "  time="        << simTime()
                << "  type="        << frameTypeToString(macHeader)
                << "  transmitter=" << macHeader->getTransmitterAddress()
                << "  receiver="    << macHeader->getReceiverAddress()
                << "\n";

        OverhearingEvent *event = buildOverhearingEvent(packet, macHeader);
        emit(frameOverheardSignal, event);
        delete event;
        CsmaCaMac::handleWithFsm(packet);
    }
}

void PromiscuousCsmaCaMac::onFrameOverheard(Packet *packet)
{
    const Ptr<const CsmaCaMacHeader> macHeader =
            packet->peekAtFront<CsmaCaMacHeader>();

    EV_INFO << "[PromiscuousCsmaCaMac] OVERHEARD FRAME"
            << "  time="        << simTime()
            << "  type="        << frameTypeToString(macHeader)
            << "  transmitter=" << macHeader->getTransmitterAddress()
            << "  receiver="    << macHeader->getReceiverAddress()
            << "\n";

    OverhearingEvent *event = buildOverhearingEvent(packet, macHeader);
    emit(frameOverheardSignal, event);
    delete event;
    delete packet;
}

OverhearingEvent *PromiscuousCsmaCaMac::buildOverhearingEvent(
        Packet *packet,
        const Ptr<const CsmaCaMacHeader>& macHeader)
{
    OverhearingEvent *event = new OverhearingEvent();

    event->setTransmitterAddress(macHeader->getTransmitterAddress());
    event->setReceiverAddress(macHeader->getReceiverAddress());
    event->setObserverAddress(networkInterface->getMacAddress());
    event->setFrameType(frameTypeToString(macHeader).c_str());
    event->setByteLength(packet->getByteLength());
    event->setObservationTime(simTime());

    Packet *copy = packet->dup();
        if(dynamicPtrCast<const CsmaCaMacDataHeader>(macHeader)) {


        copy->popAtFront<CsmaCaMacDataHeader>();
        copy->popAtBack<CsmaCaMacTrailer>(B(4));


        const auto& ipHeader = copy->peekAtFront<Ipv4Header>();
        if(ipHeader != nullptr) {
            event->setSrcIP(ipHeader->getSrcAddress());
            event->setDstIP(ipHeader->getDestAddress());
            event->setIpID(ipHeader->getIdentification());
            EV <<"DEBUG IP ID = " << ipHeader->getIdentification()
            <<"  DEBUG SRC IP = " << ipHeader->getSrcAddress()
            << " Transmitter = " << macHeader->getTransmitterAddress() << "\n";
        }
        }

    delete copy;
    copy = nullptr;

    return event;
}

bool PromiscuousCsmaCaMac::frameIsForUs(Packet *packet) const
{
    const Ptr<const CsmaCaMacHeader> macHeader =
            packet->peekAtFront<CsmaCaMacHeader>();
    MacAddress dest    = macHeader->getReceiverAddress();
    MacAddress ourAddr = networkInterface->getMacAddress();
    return dest == ourAddr || dest.isBroadcast() || dest.isMulticast();
}

std::string PromiscuousCsmaCaMac::frameTypeToString(
        const Ptr<const CsmaCaMacHeader>& header) const
{
    if (dynamicPtrCast<const CsmaCaMacDataHeader>(header)) return "DATA";
    if (dynamicPtrCast<const CsmaCaMacAckHeader>(header))  return "ACK";
    return "UNKNOWN";
}

} // namespace inet;


