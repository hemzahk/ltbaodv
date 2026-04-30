/*
 * PendingExpectation.h
 *
 *  Created on: Apr 30, 2026
 *      Author: hemzakareche
 */

#ifndef TRUSTMANAGER_PENDINGEXPECTATION_H_
#define TRUSTMANAGER_PENDINGEXPECTATION_H_

#include <omnetpp.h>
#include "inet/linklayer/common/MacAddress.h"
#include "inet/networklayer/common/L3Address.h"

using namespace omnetpp;

namespace inet {

struct CorrelationKey {

    L3Address srcIP;
    L3Address dstIP;
    int       ipID;

    bool operator<(const CorrelationKey& other) const {
        if (srcIP != other.srcIP) return srcIP < other.srcIP;
        if (dstIP != other.dstIP) return dstIP < other.dstIP;
        return ipID < other.ipID;
    }

    bool operator==(const CorrelationKey& other) const {
        return srcIP == other.srcIP &&
               dstIP == other.dstIP &&
               ipID  == other.ipID;
    }

    std::string str() const {
        std::ostringstream oss;
        oss << srcIP << "->" << dstIP << "[id=" << ipID << "]";
        return oss.str();
    }
};

struct PendingExpectation {

    MacAddress nextHopMac;
    CorrelationKey key;

    bool resolved = false;

    std::string str() const {
        std::ostringstream oss;
        oss << "nextHop=" << nextHopMac
            << "  key="   << key.str()
            << (resolved ? "  [RESOLVED]" : "  [PENDING]");
        return oss.str();
    }
};

} // namespace inet;



#endif /* TRUSTMANAGER_PENDINGEXPECTATION_H_ */
