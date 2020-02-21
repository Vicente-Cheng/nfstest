#===============================================================================
# Copyright 2018 NetApp, Inc. All Rights Reserved,
# contribution by Jorge Mora <mora@netapp.com>
#
# This program is free software; you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation; either version 2 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
#===============================================================================
"""
VLAN module

Decode Virtual LAN IEEE 802.1Q/802.1ad layer
"""
import nfstest_config as c
from baseobj import BaseObj
from ethernet_const import *

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2018 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

def vlan_layers(pktt):
    """Get all nested (stacked VLANs or QinQ) VLAN layers
       A Packet layer attribute is created for each VLAN layer:
       vlan1, vlan2, ..., and vlan. The last packet attribute
       is always vlan.
    """
    vlan_list = []
    while True:
        vlan = VLAN(pktt)
        if vlan.etype == 0x8100 or vlan.etype == 0x88A8:
            # VLAN layer could be 802.1Q or 802.1ad
            vlan_list.append(vlan)
        else:
            # Done with all VLAN layers, add them to the packet as:
            # vlan1, vlan2, ..., vlan
            for i in range(len(vlan_list)):
                pktt.pkt.add_layer("vlan"+str(i+1), vlan_list.pop(0))
            # Add last VLAN layer
            pktt.pkt.add_layer("vlan", vlan)
            break

class VLAN(BaseObj):
    """VLAN object

       Usage:
           from packet.link.vlan import VLAN

           x = VLAN(pktt)

       Object definition:

       VLAN(
           pcp   = int,  # Priority Point Code
           dei   = int,  # Drop Eligible Indicator
           vid   = int,  # VLAN Identifier
           etype = int,  # Payload Type
           psize = int,  # Payload Data Size
       )
    """
    # Class attributes
    _attrlist = ("pcp", "dei", "vid", "etype", "psize")
    _strname = "VLAN"

    def __init__(self, pktt):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
        """
        unpack = pktt.unpack
        ulist = unpack.unpack(4, "!2H")
        self.pcp   = ulist[0] >> 13
        self.dei   = (ulist[0] >> 12) & 0x01
        self.vid   = ulist[0] & 0x0FFF
        self.etype = ulist[1]
        self.psize = unpack.size()

    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of the object is condensed:
               '802.1Q VLAN pcp: 4, dei: 0, vid: 2704 '

           If set to 2 the representation of the object also includes the type
           of payload:
               '802.1Q Virtual LAN, pcp: 4, dei: 0, vid: 2704, etype: 0x0800(IPv4)'
        """
        rdebug = self.debug_repr()
        if rdebug == 1:
            out = "802.1Q VLAN pcp: %d, dei: %d, vid: %d" % (self.pcp, self.dei, self.vid)
        elif rdebug == 2:
            etype = ETHERTYPES.get(self.etype)
            etype = "" if etype is None else "(%s)" % etype
            out = "802.1Q Virtual LAN, pcp: %d, dei: %d, vid: %d, etype: 0x%04x%s" % \
                  (self.pcp, self.dei, self.vid, self.etype, etype)
        else:
            out = BaseObj.__str__(self)
        return out
