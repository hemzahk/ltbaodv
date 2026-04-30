/*
 * TrustRecommendation.cc
 *
 *  Created on: Apr 30, 2026
 *      Author: hemzakareche
 */

#include "TrustRecommendation.h"

#include "inet/common/ModuleAccess.h"
#include "inet/networklayer/common/L3AddressTag_m.h"
#include "inet/transportlayer/common/L4PortTag_m.h"
#include "inet/linklayer/common/InterfaceTag_m.h"

namespace inet {

Define_Module(TrustRecommendation);

void TrustRecommendation::initialize(int stage) {
    ApplicationBase::initialize(stage);

    if (stage == INITSTAGE_LOCAL) {
        trustRecommendationInterval = par("trustRecommendationInterval");
        trustRecommendationPort     = par("trustRecommendationPort");
        recommendationTimer         = new cMessage("recommendationTimer");

        interfaceTable.reference(this, "interfaceTableModule", true);
        trustManager.reference(this, "trustManagerModule", true);
        arp.reference(this, "arpModule", true);
    } else if (stage == INITSTAGE_APPLICATION_LAYER) {
        EV_INFO << "[TrustRecommendation] Initialized."
                << "  trustRecommendation=" << trustRecommendationInterval << "s"
                << "  trustRecommendation="     << trustRecommendationPort << "\n";
    }
}

void TrustRecommendation::handleMessageWhenUp(cMessage *msg)
{
    if (msg->isSelfMessage()) {
        if (msg == recommendationTimer) {
            trustManager->resetAllIndirectTrust();
            broadcastTrustPacket();
            scheduleAfter(trustRecommendationInterval, recommendationTimer);
        }
        else
            throw cRuntimeError("[TrustRecommendation] Unknown self message: %s",
                                 msg->getName());
    }
    else {
        recommendationSocket.processMessage(msg);
    }
}

void TrustRecommendation::handleStartOperation(LifecycleOperation *operation)
{

    myIP = resolveMyIP();

    recommendationSocket.setOutputGate(gate("socketOut"));
    recommendationSocket.setCallback(this);
    recommendationSocket.bind(L3Address(), trustRecommendationPort);
    recommendationSocket.setBroadcast(true);

    scheduleAfter(trustRecommendationInterval, recommendationTimer);

    EV_INFO << "[TrustRecommendation] Started."
            << "  myIP=" << myIP
            << "  port=" << trustRecommendationPort << "\n";
}

void TrustRecommendation::handleStopOperation(LifecycleOperation *operation)
{
    recommendationSocket.close();
    cancelEvent(recommendationTimer);
}

void TrustRecommendation::handleCrashOperation(LifecycleOperation *operation)
{
    recommendationSocket.destroy();
    cancelEvent(recommendationTimer);
}

void TrustRecommendation::broadcastTrustPacket()
{
    const auto& trustTable   = trustManager->getTrustTable();

    if (trustTable.empty()) {
        EV_INFO << "[TrustRecommendation] Trust table empty — skipping broadcast.\n";
        return;
    }

    // Build TrustPacket
    auto trustPkt = makeShared<TrustPacket>();
    trustPkt->setSenderIP(myIP);
    trustPkt->setEntriesArraySize(trustTable.size());

    int idx = 0;
    for (const auto& kv : trustTable) {
        L3Address neighborIP = arp->getL3AddressFor(kv.first);
        if (neighborIP.isUnspecified()) {
            EV_DEBUG << "[TrustRecommendation] No IP for MAC " << kv.first
                     << " — skipping.\n";
            continue;
        }

        TrustEntry entry;
        entry.neighborIP = neighborIP;
        entry.trustScore = kv.second.computeTrustScore();
        trustPkt->setEntries(idx, entry);
        idx++;
    }

    if (idx == 0) {
        EV_INFO << "[TrustRecommendation] No resolvable entries — skipping broadcast.\n";
        return;
    }

    trustPkt->setEntriesArraySize(idx);
    // 4 bytes senderIP + idx * (4 bytes IP + 8 bytes double)
    trustPkt->setChunkLength(B(4 + idx * 12));

    int interfaceId = CHK(interfaceTable->findInterfaceByName(par("interface")))->getInterfaceId(); // TODO Implement: support for multiple interfaces

    auto packet = new Packet("TrustPacket",trustPkt);
    packet->addTag<InterfaceReq>()->setInterfaceId(interfaceId);
    packet->addTag<L3AddressReq>()->setDestAddress(
            Ipv4Address::ALLONES_ADDRESS);
    packet->addTag<L4PortReq>()->setDestPort(trustRecommendationPort);

    recommendationSocket.send(packet);

    EV_INFO << "[TrustRecommendation] Broadcast TrustPacket: "
            << idx << " entries from " << myIP << "\n";
}

void TrustRecommendation::processTrustPacket(Packet *packet)
{
    const auto& trustPkt = packet->peekAtFront<TrustPacket>();
    if (trustPkt == nullptr) {
        EV_WARN << "[TrustRecommendation] Failed to peek TrustPacket.\n";
        delete packet;
        return;
    }

    L3Address senderIP = trustPkt->getSenderIP();

    if (senderIP == myIP) {
        delete packet;
        return;
    }

    int processed = 0;

    for (unsigned int i = 0; i < trustPkt->getEntriesArraySize(); i++) {
        const TrustEntry& entry = trustPkt->getEntries(i);

        if (entry.neighborIP == myIP)
            continue;

        if (entry.trustScore < 0.0 || entry.trustScore > 1.0) {
            EV_WARN << "[TrustRecommendation] Invalid score " << entry.trustScore
                    << " from " << senderIP << " — discarding.\n";
            continue;
        }

        MacAddress subjectMac = arp->resolveL3Address(entry.neighborIP, nullptr);
        if (subjectMac.isUnspecified()) {
            EV_DEBUG << "[TrustRecommendation] Unknown subject IP "
                     << entry.neighborIP << " — skipping.\n";
            continue;
        }

        trustManager->updateIndirectTrust(subjectMac, entry.trustScore);
        processed++;
    }

    EV_INFO << "[TrustRecommendation] Processed TRUST packet from " << senderIP
            << "  entries=" << processed << "\n";

    delete packet;
}

L3Address TrustRecommendation::resolveMyIP() const
{
    auto *ift = check_and_cast<IInterfaceTable *>(
            getParentModule()->getSubmodule("interfaceTable"));

    for (int i = 0; i < ift->getNumInterfaces(); i++) {
        NetworkInterface *ie = ift->getInterface(i);
        if (!ie->isLoopback()) {
            auto *ipData = ie->findProtocolData<Ipv4InterfaceData>();
            if (ipData && !ipData->getIPAddress().isUnspecified())
                return L3Address(ipData->getIPAddress());
        }
    }
    throw cRuntimeError("[TrustRecommendation] Could not resolve own IP address.");
}

void TrustRecommendation::socketDataArrived(UdpSocket *socket, Packet *packet)
{

    processTrustPacket(packet);
}

void TrustRecommendation::socketErrorArrived(UdpSocket *socket, Indication *indication)
{
    EV_WARN << "[TrustRecommendation] UDP error: " << indication->getName() << "\n";
    delete indication;
}

void TrustRecommendation::socketClosed(UdpSocket *socket)
{
    if (operationalState == State::STOPPING_OPERATION)
        startActiveOperationExtraTimeOrFinish(par("stopOperationExtraTime"));
}

}


