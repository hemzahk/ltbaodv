/*
 * TrustManager.h
 *
 *  Created on: Apr 30, 2026
 *      Author: hemzakareche
 */

#ifndef TRUSTMANAGER_TRUSTMANAGER_H_
#define TRUSTMANAGER_TRUSTMANAGER_H_

#include <map>
#include <omnetpp.h>

#include "inet/common/INETDefs.h"
#include "inet/linklayer/common/MacAddress.h"
#include "inet/networklayer/common/L3Address.h"
#include "inet/common/ModuleRefByPar.h"
#include "inet/networklayer/contract/IArp.h"

#include "NeighborRecord.h"
#include "../msg/OverhearingEvent_m.h"
#include "../msg/OutgoingFrameEvent_m.h"

using namespace omnetpp;

namespace inet {

class INET_API TrustManager : public cSimpleModule, public cListener{
    public:
        double getTrustScore(const MacAddress& neighbor)  const;
        double getTrustScore(const L3Address& neighborIP) const;

        const std::map<MacAddress, NeighborRecord>& getTrustTable() const
        { return trustTable; }

        void updateIndirectTrust(const MacAddress& neighborMAC, double score);
        void resetAllIndirectTrust();

    protected:
        simtime_t nodeTrustUpdateInterval = 1.0;
        int       windowCount           = 20;
        int       windowCapacity        = 5;
        double    sourceExpireTime      = 20.0;
        double    alpha                 = 1.0;

        std::map<MacAddress, NeighborRecord> trustTable;

        mutable std::map<MacAddress, cOutVector *> trustVectors;

        static simsignal_t frameOverheardSignal;
        static simsignal_t frameSentToNextHopSignal;

        cMessage *trustUpdateTimer = nullptr;
        cMessage *periodicTimer    = nullptr;

        ModuleRefByPar<IArp> arp;

        long totalOverheardFrames   = 0;
        long overheardDataFrames    = 0;
        long overheardAckFrames     = 0;
        long totalForwardExpected   = 0;
        long totalForwardObserved   = 0;

        virtual void initialize()    override;
        virtual void handleMessage(cMessage *msg) override;
        virtual void finish()        override;

        virtual void receiveSignal(cComponent *src, simsignal_t sig,
                                   cObject *obj, cObject *details) override;

        void onOutgoingFrame   (const OutgoingFrameEvent *event);
        void tryResolveForward (const OverhearingEvent   *event);

        void refreshAllTrustCaches();
        void cleanAllSourcelists();

        NeighborRecord& getOrCreateRecord(const MacAddress& addr);
        cOutVector* getOrCreateVector(const MacAddress& mac) const;
        void dumpTrustTable() const;
};
} // namespace inet;



#endif /* TRUSTMANAGER_TRUSTMANAGER_H_ */
