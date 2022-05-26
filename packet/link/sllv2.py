#===============================================================================
# Copyright 2022 NetApp, Inc. All Rights Reserved,
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
ERF module

Decode Linux "cooked" v2 capture encapsulation layer
"""
import nfstest_config as c
from baseobj import BaseObj
from packet.internet.ipv4 import IPv4
from packet.internet.ipv6 import IPv6
from packet.link.macaddr import MacAddr

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2022 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

class SLLv2(BaseObj):
    """Extensible record format object

       Usage:
           from packet.link.sllv2 import SLLv2

           x = SLLv2(pktt)

       Object definition:

       SLLv2(
           etype  = int,    # Protocol type
           index  = int,    # Interface index
           dtype  = int,    # Device type
           ptype  = int,    # Packet type
           alen   = int,    # Address length
           saddr  = int,    # Source Address
           psize  = int,    # Payload data size
       )
    """
    # Class attributes
    _attrlist = ("etype", "index", "dtype", "ptype", "alen", "saddr", "psize")

    def __init__(self, pktt):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
        """
        unpack = pktt.unpack
        ulist = unpack.unpack(20, "!HHIHBB8s")
        self.etype = ulist[0]
        self.index = ulist[2]
        self.dtype = ulist[3]
        self.ptype = ulist[4]
        self.alen  = ulist[5]
        self.saddr = ulist[6][:self.alen]

        if self.dtype == 1:
            # Ethernet device type
            self.saddr = MacAddr(self.saddr.hex())

        pktt.pkt.add_layer("sll", self)
        self.psize = unpack.size()

        if self.etype == 0x0800:
            # Decode IPv4 packet
            IPv4(pktt)
        elif self.etype == 0x86dd:
            # Decode IPv6 packet
            IPv6(pktt)

    def __str__(self):
        """String representation of object

           The representation depends on the verbose level set by debug_repr().
           If set to 0 the generic object representation is returned.
           If set to 1 the representation of the object is condensed:
               "SLLv2  etype: 0x86dd, index: 3, dtype: 65534, ptype: 4, alen: 0, saddr: b'', psize: 116"
        """
        rdebug = self.debug_repr()
        out = "etype: 0x%04x, index: %d, dtype: %s, ptype: %s, alen: %d, saddr: %s, psize: %d" % (self.etype, self.index, self.dtype, self.ptype, self.alen, self.saddr, self.psize)
        if rdebug == 1:
            out = "SLLv2  " + out
        elif rdebug != 2:
            out = BaseObj.__str__(self)
        return out
