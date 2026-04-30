/*
 * NeighborRecord.h
 *
 *  Created on: Apr 30, 2026
 *      Author: hemzakareche
 */

#ifndef TRUSTMANAGER_NEIGHBORRECORD_H_
#define TRUSTMANAGER_NEIGHBORRECORD_H_

#include <vector>
#include <map>
#include <sstream>
#include <omnetpp.h>
#include "inet/networklayer/common/L3Address.h"

using namespace omnetpp;

namespace inet {

struct NeighborRecord {

    std::vector<int> toForwardWindows;
    std::vector<int> forwardedWindows;
    int              currentWindow = 0;

    int    N               = 20;
    int    M               = 5;
    double sourceExpireTime = 20.0;

    std::map<L3Address, simtime_t> sourcelist;

    double nbAvgTrust      = 0.0;
    int    nbCountNeighbor = 0;

    double    cachedTrust     = 0.5;
    simtime_t lastTrustUpdate = -1;

    long      totalExpectedForwards      = 0;
    long      totalObservedForwards      = 0;

    void configure(int numWindows, int windowCap,
                   double srcExpireTime)
    {
        N                      = numWindows;
        M                      = windowCap;
        sourceExpireTime       = srcExpireTime;
        toForwardWindows.assign(N, 0);
        forwardedWindows.assign(N, 0);
        currentWindow = 0;
    }

    void addToSourcelist(const L3Address& srcIP, simtime_t now)
    {
        sourcelist[srcIP] = now + sourceExpireTime;
    }

    bool isInSourcelist(const L3Address& srcIP, simtime_t now) const
    {
        auto it = sourcelist.find(srcIP);
        if (it == sourcelist.end()) return false;
        return now <= it->second;
    }

    void removeFromSourcelist(const L3Address& srcIP)
    {
        sourcelist.erase(srcIP);
    }

    void cleanExpiredSourcelist(simtime_t now)
    {
        for (auto it = sourcelist.begin(); it != sourcelist.end(); )
            it = (now > it->second) ? sourcelist.erase(it) : ++it;
    }

    void recordForwardExpected(const L3Address& srcIP, simtime_t now)
    {
        totalExpectedForwards++;

        toForwardWindows[currentWindow]++;
        addToSourcelist(srcIP, now);
        checkAndAdvanceWindow();
    }

    void recordForwardObserved(const L3Address& srcIP, simtime_t now)
    {
        totalObservedForwards++;

        forwardedWindows[currentWindow]++;
        removeFromSourcelist(srcIP);
        checkAndAdvanceWindow();

    }

    double computeTrustScore() const
    {
        int sumToForward = 0, sumForwarded = 0;
        for (int k = 0; k < N; ++k) {
            sumToForward += toForwardWindows[k];
            sumForwarded += forwardedWindows[k];
        }
        if (sumToForward == 0)  return 0.5;
        //if (sumToForward < M)   return 0.5;
        double score = static_cast<double>(sumForwarded) /
                       static_cast<double>(sumToForward);
        return score > 1.0 ? 1.0 : score;
    }

    void updateIndirectTrust(double reportedScore)
    {
        nbAvgTrust = (nbAvgTrust * nbCountNeighbor + reportedScore)
                     / (nbCountNeighbor + 1);
        nbCountNeighbor++;
    }

    void resetIndirectTrust()
    {
        nbAvgTrust      = 0.0;
        nbCountNeighbor = 0;
    }

    double computeCombinedTrust(double alpha) const
    {
        double selfTrust = computeTrustScore();
        if (nbCountNeighbor == 0) return selfTrust;
        double combined = alpha * selfTrust + (1.0 - alpha) * nbAvgTrust;
        return combined < 0.0 ? 0.0 : (combined > 1.0 ? 1.0 : combined);
    }

    void refreshCachedTrust(double alpha, simtime_t now)
    {
        cachedTrust     = computeCombinedTrust(alpha);
        lastTrustUpdate = now;
        EV_DEBUG << "[NeighborRecord] NodeTrustUpdate:"
                 << " cached="   << cachedTrust
                 << " self="     << computeTrustScore()
                 << " nbAvg="    << nbAvgTrust
                 << " alpha="    << alpha
                 << " t="        << now << "\n";
    }

    std::string str() const
    {
        int sumTF = 0, sumFwd = 0;
        for (int k = 0; k < N; ++k) {
            sumTF  += toForwardWindows[k];
            sumFwd += forwardedWindows[k];
        }
        std::ostringstream oss;
        oss << "cached="      << cachedTrust
            << " self="       << computeTrustScore()
            << " nbAvg="      << nbAvgTrust
            << " nbCount="    << nbCountNeighbor
            << " sumTF="      << sumTF
            << " sumFwd="     << sumFwd
            << " curWin="     << currentWindow
            << " srclist="    << sourcelist.size()
            << " lifeTF="     << totalExpectedForwards
            << " lifeFwd="    << totalObservedForwards
            << " lastUpd="    << lastTrustUpdate;
        return oss.str();
    }

    private:

        void checkAndAdvanceWindow()
        {
            if (toForwardWindows[currentWindow] >= M ||
                forwardedWindows[currentWindow] >= M)
            {
                currentWindow = (currentWindow + 1) % N;
                toForwardWindows[currentWindow] = 0;
                forwardedWindows[currentWindow] = 0;
                EV_DEBUG << "[NeighborRecord] Window → " << currentWindow << "\n";
            }
        }

};

} // namespace inet;



#endif /* TRUSTMANAGER_NEIGHBORRECORD_H_ */
