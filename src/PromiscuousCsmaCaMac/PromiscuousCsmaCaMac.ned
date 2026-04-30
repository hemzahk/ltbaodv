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

package ltbaodv.PromiscuousCsmaCaMac;

import inet.linklayer.csmaca.CsmaCaMac;

module PromiscuousCsmaCaMac extends CsmaCaMac
{
    parameters:
        bool promiscuousMode = default(true);

		
        @signal[frameOverheard](type=cObject);
        @signal[frameSentToNextHop](type=cObject);

        @statistic[frameOverheard](
            title="Overheard frames";
            source=frameOverheard;
            record=count);

        @statistic[frameSentToNextHop](
            title="Frames sent to next-hop (unicast)";
            source=frameSentToNextHop;
            record=count);

        @class(inet::PromiscuousCsmaCaMac);
        @display("i=block/rxtx;bgb=,,white");
}
