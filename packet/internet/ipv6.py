#===============================================================================
# Copyright 2012 NetApp, Inc. All Rights Reserved,
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
IPv6 module

Decode IP version 6 layer.
Extension headers are not supported.
"""
import nfstest_config as c
from packet.transport.tcp import TCP
from packet.transport.udp import UDP
from packet.internet.ipv4 import IPv4
from packet.internet.ipv6addr import IPv6Addr

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.1"

class IPv6(IPv4):
    """IPv6 object

       Usage:
           from packet.internet.ipv6 import IPv6

           x = IPv6(pktt)

       Object definition:

       IPv6(
           version       = int,
           traffic_class = int,
           flow_label    = int,
           total_size    = int,
           protocol      = int,
           hop_limit     = int,
           src           = IPv6Addr(),
           dst           = IPv6Addr(),
           psize         = int,     # payload data size
           data          = string,  # raw data of payload if protocol
                                    # is not supported
       )
    """
    # Class attributes
    _attrlist = ("version", "traffic_class", "flow_label", "total_size",
                 "protocol", "hop_limit", "src", "dst", "psize", "data")

    def __init__(self, pktt):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
        """
        unpack = pktt.unpack
        ulist = unpack.unpack(40, "!IHBB16s16s")
        self.version       = (ulist[0] >> 28)
        self.traffic_class = (ulist[0] >> 20)&0xFF
        self.flow_label    = ulist[0]&0xFFF
        self.total_size    = ulist[1]
        self.protocol      = ulist[2]
        self.hop_limit     = ulist[3]
        self.src           = IPv6Addr(ulist[4].hex())
        self.dst           = IPv6Addr(ulist[5].hex())

        pktt.pkt.add_layer("ip", self)

        # Get the payload data size
        self.psize = unpack.size()

        if self.protocol == 6:
            # Decode TCP
            TCP(pktt)
        elif self.protocol == 17:
            # Decode UDP
            UDP(pktt)
        else:
            self.data = unpack.getbytes()
