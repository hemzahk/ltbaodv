//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with this program.  If not, see http://www.gnu.org/licenses/.
//

package ltbaodv.TrustManager;

simple TrustManager
{
    parameters:

        @class(inet::TrustManager);
        // Routing decision threshold — nodes below this are avoided
        double trustThreshold = default(0.5);

        // Paper Eq. 1 weight: 1.0 = direct trust only (Section 4.1)
        //                     0.5 = equal direct+indirect (Section 4.2)
        double alpha = default(1.0);

        // Paper Section 3 / Section 5: NodeTrustUpdate interval
        // How often Nb_Trust (cachedTrust) is recomputed. Paper: 1s.
        double nodeTrustUpdateInterval @unit(s) = default(1s);

        // Paper Section 3: N — number of circular windows. Paper: 20.
        int windowCount = default(20);

        // Paper Section 3: M — capacity per window. Paper: 5.
        int windowCapacity = default(5);

        // Paper Section 3: SourceExpireTime. Paper: 20s.
        double sourceExpireTime @unit(s) = default(20s);

        // FANET mobility extension: silence duration (seconds) after which
        // a neighbor is considered out of radio range.
        // Rule of thumb: 2 × helloInterval.
        double neighborAbsenceTimeout @unit(s) = default(4s);

        // Table dump interval (diagnostics only — not part of algorithm)
        double tableDumpInterval @unit(s) = default(10s);
        bool   enableTableDump = default(true);

        string arpModule = default("^.ipv4.arp");

        @signal[trustValue*](type=double);
        @statisticTemplate[trustValue](
        	title="trust value";
        	record=vector;
        	interpolationmode=linear
        );
}