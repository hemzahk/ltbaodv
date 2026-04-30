/*
 * TrustManager.cc
 *
 *  Created on: Apr 30, 2026
 *      Author: hemzakareche
 */

#include "TrustManager.h"

namespace inet {

Define_Module(TrustManager);

simsignal_t TrustManager::frameOverheardSignal =
        registerSignal("frameOverheard");
simsignal_t TrustManager::frameSentToNextHopSignal =
        registerSignal("frameSentToNextHop");

void TrustManager::initialize() {
    nodeTrustUpdateInterval = par("nodeTrustUpdateInterval");
    windowCount             = par("windowCount");
    windowCapacity          = par("windowCapacity");
    sourceExpireTime        = par("sourceExpireTime");
    alpha                   = par("alpha");

    getParentModule()->subscribe(frameOverheardSignal,     this);
    getParentModule()->subscribe(frameSentToNextHopSignal, this);

    arp.reference(this, "arpModule", true);

    trustUpdateTimer = new cMessage("trustUpdateTimer");
    scheduleAt(simTime() + nodeTrustUpdateInterval, trustUpdateTimer);

    EV_INFO << "[TrustManager] Initialized."
            << "  nodeTrustUpdateInterval="<< nodeTrustUpdateInterval << "s"
            << "  N="                      << windowCount
            << "  M="                      << windowCapacity
            << "  sourceExpireTime="       << sourceExpireTime << "s"
            << "  alpha="                  << alpha
            << "\n";
}

void TrustManager::handleMessage(cMessage *msg) {
    if (msg == trustUpdateTimer) {
        cleanAllSourcelists();       // paper: SourceExpireTime maintenance
        refreshAllTrustCaches();     // paper: NodeTrustUpdates
        scheduleAt(simTime() + nodeTrustUpdateInterval, trustUpdateTimer);
        return;
    }

    EV_WARN << "[TrustManager] Unexpected message: " << msg->getName() << "\n";
    delete msg;
}

void TrustManager::refreshAllTrustCaches() {
    simtime_t now = simTime();
    for(auto& kv  : trustTable) {
        kv.second.refreshCachedTrust(alpha, now);
        getOrCreateVector(kv.first)->recordWithTimestamp(now, kv.second.cachedTrust);
    }
    EV_INFO << "[TrustManager] NodeTrustUpdate: "
            << trustTable.size() << " neighbors at t=" << now << "\n";
}

void TrustManager::cleanAllSourcelists() {
    simtime_t now = simTime();
    for (auto& kv : trustTable)
        kv.second.cleanExpiredSourcelist(now);
}

void TrustManager::receiveSignal(cComponent *source,
                                simsignal_t signalID,
                                cObject    *obj,
                                cObject    *details) {
    if (signalID == frameOverheardSignal) {
        auto *event = dynamic_cast<OverhearingEvent *>(obj);
        if (!event) {
            EV_WARN << "[TrustManager] frameOverheard: unexpected type\n";
            return;
        }
        totalOverheardFrames++;
        if (event->getFrameType() == std::string("DATA")) {
            overheardDataFrames++;
            tryResolveForward(event);
        }
        else if (event->getFrameType() == std::string("ACK")) {
            overheardAckFrames++;
        }
        return;
    }

    if (signalID == frameSentToNextHopSignal) {
        auto *event = dynamic_cast<OutgoingFrameEvent *>(obj);
        if (!event) {
            EV_WARN << "[TrustManager] frameSentToNextHop: unexpected type\n";
            return;
        }
        onOutgoingFrame(event);
        return;
    }
}

void TrustManager::onOutgoingFrame(const OutgoingFrameEvent *event)
{
    L3Address srcIP = event->getSrcIP();
    L3Address dstIP = event->getDstIP();
    int       ipID  = event->getIpID();

    if (srcIP.isUnspecified() || dstIP.isUnspecified() || ipID == -1)
        return;

    MacAddress nextHop = event->getNextHopMac();
    if (nextHop.isUnspecified() || nextHop.isBroadcast())
        return;

    L3Address nextHopIP = arp->getL3AddressFor(nextHop);
    if (!nextHopIP.isUnspecified() && nextHopIP == dstIP)
        return;

    NeighborRecord& rec = getOrCreateRecord(nextHop);

    if (rec.isInSourcelist(srcIP, simTime())) {
        EV_DEBUG << "[TrustManager] Retransmission — skipping duplicate ToForward for "
                 << nextHop << "\n";
        return;
    }

    rec.recordForwardExpected(srcIP, simTime());
    totalForwardExpected++;

    EV_INFO << "[TrustManager] ToForward+1 for " << nextHop
            << "  src=" << srcIP << "  dst=" << dstIP
            << "  ipID=" << ipID << "\n";
}

void TrustManager::tryResolveForward(const OverhearingEvent *event)
{
    MacAddress transmitter = event->getTransmitterAddress();
    if (transmitter.isUnspecified() ||
        transmitter == event->getObserverAddress())
        return;

    L3Address srcIP = event->getSrcIP();
    if (srcIP.isUnspecified()) return;

    auto it = trustTable.find(transmitter);
    if (it == trustTable.end()) return;

    NeighborRecord& rec = it->second;

    if (!rec.isInSourcelist(srcIP, simTime())) {
        EV_DEBUG << "[TrustManager] Overheard forward from " << transmitter
                 << " but srcIP=" << srcIP << " not in sourcelist — ignored\n";
        return;
    }

    rec.recordForwardObserved(srcIP, simTime());
    totalForwardObserved++;

    EV_INFO << "[TrustManager] Forwarded+1 for " << transmitter
            << "  src=" << srcIP
            << "  score=" << rec.cachedTrust << "\n";
}

NeighborRecord& TrustManager::getOrCreateRecord(const MacAddress& addr)
{
    auto it = trustTable.find(addr);
    if (it == trustTable.end()) {
        NeighborRecord rec;
        rec.configure(windowCount, windowCapacity,
                      sourceExpireTime);
        trustTable[addr] = rec;
    }
    return trustTable[addr];
}

double TrustManager::getTrustScore(const MacAddress& neighbor) const
{
    auto it = trustTable.find(neighbor);
    if (it == trustTable.end()) return 1.0;
    return it->second.cachedTrust;
}

double TrustManager::getTrustScore(const L3Address& neighborIP) const
{
    MacAddress mac = arp->resolveL3Address(neighborIP, nullptr);
    if (mac.isUnspecified()) return 1.0;
    return getTrustScore(mac);
}

void TrustManager::updateIndirectTrust(const MacAddress& neighborMAC,
                                      double reportedScore)
{
    if (reportedScore < 0.0 || reportedScore > 1.0) {
        EV_WARN << "[TrustManager] Invalid indirect score "
                << reportedScore << " for " << neighborMAC << "\n";
        return;
    }
    auto it = trustTable.find(neighborMAC);
    if (it == trustTable.end()) return;
    it->second.updateIndirectTrust(reportedScore);

    EV_INFO << "[TrustManager] Indirect trust update: " << neighborMAC
            << "  reported=" << reportedScore
            << "  nbAvg="    << it->second.nbAvgTrust
            << "  nbCount="  << it->second.nbCountNeighbor << "\n";
}

void TrustManager::resetAllIndirectTrust()
{
    for (auto& kv : trustTable)
        kv.second.resetIndirectTrust();
    EV_INFO << "[TrustManager] Indirect trust accumulators reset.\n";
}

void TrustManager::dumpTrustTable() const
{
    EV_INFO << "[TrustManager] ===== Trust Table t=" << simTime()
            << "  alpha="     << alpha
            << "  neighbors=" << trustTable.size()
            << " =====\n";
    for (const auto& kv : trustTable)
        EV_INFO << "[TrustManager]   " << kv.first
                << "  " << kv.second.str()
                << "\n";
}

cOutVector* TrustManager::getOrCreateVector(const MacAddress& mac) const {

    auto it = trustVectors.find(mac);
    if(it != trustVectors.end())
        return it->second;

    std::string name = "trustScore_" + mac.str();
    std::replace(name.begin(), name.end(), ':', '_');

    cOutVector *vec = new cOutVector(name.c_str());
    trustVectors[mac] = vec;
    return vec;

}

void TrustManager::finish() {
    cancelAndDelete(trustUpdateTimer); trustUpdateTimer = nullptr;
    cancelAndDelete(periodicTimer);    periodicTimer    = nullptr;

    recordScalar("alpha",                   alpha);
    recordScalar("nodeTrustUpdateInterval", nodeTrustUpdateInterval.dbl());
    recordScalar("totalOverheardFrames",    totalOverheardFrames);
    recordScalar("overheardDataFrames",     overheardDataFrames);
    recordScalar("overheardAckFrames",      overheardAckFrames);
    recordScalar("totalForwardExpected",    totalForwardExpected);
    recordScalar("totalForwardObserved",    totalForwardObserved);

    for (const auto& kv : trustTable) {
        std::string p = "neighbor_" + kv.first.str();
        std::replace(p.begin(), p.end(), ':', '_');
        const NeighborRecord& r = kv.second;
        recordScalar((p+".cachedTrust").c_str(),        r.cachedTrust);
        recordScalar((p+".selfTrust").c_str(),          r.computeTrustScore());
        recordScalar((p+".nbAvgTrust").c_str(),         r.nbAvgTrust);
        recordScalar((p+".nbCountNeighbor").c_str(),    (long)r.nbCountNeighbor);
        recordScalar((p+".totalExpForwards").c_str(),   r.totalExpectedForwards);
        recordScalar((p+".totalObsForwards").c_str(),   r.totalObservedForwards);
        recordScalar((p+".sourclistSize").c_str(),      (long)r.sourcelist.size());
        recordScalar((p+".lastTrustUpdate").c_str(),    r.lastTrustUpdate.dbl());
    }

    for(auto& kv : trustVectors) {
        delete kv.second;
    }

    trustVectors.clear();

    dumpTrustTable();
}

} // namespace inet;



