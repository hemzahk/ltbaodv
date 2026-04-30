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

package ltbaodv.simulations;

import inet.node.contract.INetworkNode;
import inet.physicallayer.wireless.common.contract.packetlevel.IRadioMedium;
import inet.networklayer.configurator.ipv4.Ipv4NetworkConfigurator;
import inet.visualizer.contract.IIntegratedVisualizer;

network Fanet {
	parameters:
	    @display("bgb=1200,1200;bgg=100,1,grey95");
	    @figure[title](type=label; pos=0,-1; anchor=sw; color=darkblue);

        @figure[sentPkText](type=indicatorText; pos=1100,350; anchor=w; font=,18; textFormat="packets sent: %g"; initialValue=0);
        @statistic[packetSent](source=uav[0].app[0].packetSent; record=figure(count); targetFigure=sentPkText);

        @figure[rcvdPkText](type=indicatorText; pos=1100,400; anchor=w; font=,18; textFormat="packets received: %g"; initialValue=0);
        @statistic[packetReceived](source=uav[5].app[0].packetReceived; record=figure(count); targetFigure=rcvdPkText);

	    int numUavs = default(15);
	
	submodules:
		visualizer: <default(firstAvailableOrEmpty("IntegratedCanvasVisualizer"))> like IIntegratedVisualizer if typename != "" {
            @display("p=1150,50");
        }
        configurator: Ipv4NetworkConfigurator {
           @display("p=1150,150");
        }
        radioMedium: <default("UnitDiskRadioMedium")> like IRadioMedium {
            @display("p=1150,250");
        }

        uav[numUavs]: <default("ManetRouter")> like INetworkNode {
            @display("i=misc/drone");
        }
}