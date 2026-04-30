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

package ltbaodv.TrustRecommendation;

import inet.applications.contract.IApp;

simple TrustRecommendation like IApp {
    parameters:
		@class(inet::TrustRecommendation);
	
		string interfaceTableModule = default("^.interfaceTable");
    	string trustManagerModule = default("^.trustManager");
    	string interface = default("wlan0");
    	string arpModule = default("^.ipv4.arp");
    	
    	double trustRecommendationInterval @unit(s) = default(30s);
    	
    	int trustRecommendationPort = default(655);
    	
	    double stopOperationExtraTime @unit(s) = default(-1s);
	
	gates:
        input  socketIn;
        output socketOut;

}