#===============================================================================
# Copyright 2014 NetApp, Inc. All Rights Reserved,
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
UDP module

Decode UDP layer.
"""
import nfstest_config as c
from baseobj import BaseObj
from packet.utils import ShortHex
from packet.transport.ib import IB
from packet.application.dns import DNS
from packet.application.rpc import RPC
from packet.application.ntp4 import NTP
from packet.application.krb5 import KRB5

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2014 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.2"

class UDP(BaseObj):
    """UDP object

       Usage:
           from packet.transport.udp import UDP

           x = UDP(pktt)

       Object definition:

       UDP(
           src_port = int,
           dst_port = int,
           length   = int,
           checksum = int,
           psize    = int,       # payload data size
           data     = string,    # raw data of payload if unable to decode
       )
    """
    # Class attributes
    _attrlist = ("src_port", "dst_port", "length", "checksum", "psize", "data")
    _strfmt1  = "UDP {0} -> {1}, len: {2}"
    _strfmt2  = "src port {0} -> dst port {1}, len: {2}, checksum: {3}"

    def __init__(self, pktt):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
        """
        unpack = pktt.unpack

        # Decode the UDP layer header
        ulist = unpack.unpack(8, "!HHHH")
        self.src_port = ulist[0]
        self.dst_port = ulist[1]
        self.length   = ulist[2]
        self.checksum = ShortHex(ulist[3])
        self.psize    = unpack.size()

        pktt.pkt.add_layer("udp", self)
        self._decode_payload(pktt)

    def _decode_payload(self, pktt):
        """Decode UDP payload."""
        if 123 in [self.src_port, self.dst_port]:
            # NTP on port 123
            ntp = NTP(pktt)
            if ntp:
                pktt.pkt.add_layer("ntp", ntp)
        elif 53 in [self.src_port, self.dst_port]:
            # DNS on port 53
            dns = DNS(pktt, proto=17)
            if dns:
                pktt.pkt.add_layer("dns", dns)
        elif 88 in [self.src_port, self.dst_port]:
            # KRB5 on port 88
            krb = KRB5(pktt, proto=17)
            if krb:
                pktt.pkt.add_layer("krb", krb)
        elif 4791 in [self.src_port, self.dst_port]:
            # InfiniBand RoCEv2 (RDMA over Converged Ethernet)
            IB(pktt)
        else:
            # Decode RPC layer
            RPC(pktt, proto=17)
