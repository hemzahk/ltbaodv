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

package ltbaodv.TrustIpv4;

import inet.networklayer.ipv4.Ipv4;

module TrustIpv4 extends Ipv4 {
    parameters:
		@class(inet::TrustIpv4);
		
		double dropProbability = default(0.25);
		bool isMalicious = default(false);
	
		int  receivedDataPackets = default(0);
		int forwardedDataPackets = default(0);
		int droppedDataPackets = default(0);
}