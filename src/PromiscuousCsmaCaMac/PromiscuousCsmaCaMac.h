/*
 * PromiscuousCsmaCaMac.h
 *
 *  Created on: Apr 30, 2026
 *      Author: hemzakareche
 */

#ifndef PROMISCUOUSCSMACAMAC_PROMISCUOUSCSMACAMAC_H_
#define PROMISCUOUSCSMACAMAC_PROMISCUOUSCSMACAMAC_H_

#include "inet/linklayer/csmaca/CsmaCaMac.h"
#include "inet/linklayer/csmaca/CsmaCaMacHeader_m.h"
#include "inet/networklayer/ipv4/Ipv4Header_m.h"
#include "../msg/OverhearingEvent_m.h"
#include "../msg/OutgoingFrameEvent_m.h"

namespace inet {

class INET_API PromiscuousCsmaCaMac : public CsmaCaMac {

    protected:

        bool promiscuousMode = true;

        static simsignal_t frameOverheardSignal;
        static simsignal_t frameSentToNextHopSignal;

        virtual void initialize(int stage) override;

        virtual void handleUpperPacket(Packet *packet) override;
        virtual void handleLowerPacket(Packet *packet) override;

        bool extractCorrelationFields(Packet *packet,
                                      L3Address &srcIP,
                                      L3Address &dstIP,
                                      int       &ipID) const;
        virtual void onFrameOverheard(Packet *packet);

        OverhearingEvent *buildOverhearingEvent(Packet *packet,
                const Ptr<const CsmaCaMacHeader>& macHeader);
        bool frameIsForUs(Packet *packet) const;
        std::string frameTypeToString(const Ptr<const CsmaCaMacHeader>& header) const;
};

} // namespace inet



#endif /* PROMISCUOUSCSMACAMAC_PROMISCUOUSCSMACAMAC_H_ */
