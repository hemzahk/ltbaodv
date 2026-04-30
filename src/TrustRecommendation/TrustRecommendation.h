/*
 * TrustRecommendation.h
 *
 *  Created on: Apr 30, 2026
 *      Author: hemzakareche
 */

#ifndef TRUSTRECOMMENDATION_TRUSTRECOMMENDATION_H_
#define TRUSTRECOMMENDATION_TRUSTRECOMMENDATION_H_

#include <omnetpp.h>

#include "inet/applications/base/ApplicationBase.h"
#include "inet/common/ModuleRefByPar.h"
#include "inet/networklayer/contract/IInterfaceTable.h"
#include "inet/networklayer/ipv4/Ipv4InterfaceData.h"
#include "inet/networklayer/contract/IArp.h"
#include "inet/transportlayer/contract/udp/UdpSocket.h"
#include "../TrustManager/TrustManager.h"
#include "../msg/TrustPacket_m.h"

namespace inet {

class INET_API TrustRecommendation : public ApplicationBase, public UdpSocket::ICallback {
    protected:
        simtime_t trustRecommendationInterval = 1.0;
        int       trustRecommendationPort     = 655;

        L3Address myIP;

        UdpSocket recommendationSocket;

        cMessage *recommendationTimer = nullptr;

        ModuleRefByPar<IInterfaceTable> interfaceTable;
        ModuleRefByPar<TrustManager> trustManager;
        ModuleRefByPar<IArp> arp;

        virtual void initialize(int stage) override;
        virtual int  numInitStages() const override { return NUM_INIT_STAGES;}

        virtual void handleMessageWhenUp(cMessage *msg) override;

        virtual void handleStartOperation(LifecycleOperation *operation) override;
        virtual void handleStopOperation(LifecycleOperation *operation) override;
        virtual void handleCrashOperation(LifecycleOperation *operation) override;

        void broadcastTrustPacket();
        void processTrustPacket(Packet *packet);
        L3Address resolveMyIP() const;

        virtual void socketDataArrived(UdpSocket *socket, Packet *packet) override;
        virtual void socketErrorArrived(UdpSocket *socket, Indication *indication) override;
        virtual void socketClosed(UdpSocket *socket) override;
};
} // namespace inet;



#endif /* TRUSTRECOMMENDATION_TRUSTRECOMMENDATION_H_ */
