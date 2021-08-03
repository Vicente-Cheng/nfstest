#===============================================================================
# Copyright 2021 NetApp, Inc. All Rights Reserved,
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
DDP module

Decode DDP layer.

RFC 5041 Direct Data Placement over Reliable Transports
"""
import nfstest_config as c
from baseobj import BaseObj
from packet.utils import IntHex, LongHex

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2021 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

class DDP(BaseObj):
    """DDP object

       Usage:
           from packet.transport.ddp import DDP

           x = DDP(pktt)

       Object definition:

       DDP(
           tagged  = int,  # Tagged message
           lastfl  = int,  # Last flag
           version = int,  # DDP version
           psize   = int,  # Payload size
           [
               # For tagged message:
               stag    = int,  # Steering tag
               offset  = int,  # Tagged offset
           ] | [
               # For untagged message:
               queue   = int,  # Queue number
               msn     = int,  # Message sequence number
               offset  = int,  # Message offset
           ]
       )
    """
    # Class attributes
    _attrlist = ("tagged", "lastfl", "version", "stag", "queue", "msn", "offset", "psize")

    def __init__(self, pktt):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
        """
        unpack = pktt.unpack
        offset = unpack.tell()

        # Decode the DDP layer header
        ulist = unpack.unpack(6, "!BBI")
        self.tagged  = (ulist[0] >> 7) & 0x01
        self.lastfl  = (ulist[0] >> 6) & 0x01
        reserved     = (ulist[0] >> 2) & 0x0F
        self.version =  ulist[0] & 0x03
        rsvdulp      =  ulist[1:]

        # Check if valid DDP layer
        if reserved != 0 or self.version != 1:
            unpack.seek(offset)
            return

        # This is a DDP packet
        pktt.pkt.add_layer("ddp", self)

        if self.tagged:
            # DDP tagged messaged
            self.stag   = IntHex(ulist[2])
            self.offset = LongHex(unpack.unpack_uint64())
            self._strfmt1 = "DDP   v{2:<3} stag: {3}, offset: {6}, last: {1}, len: {7}"
            self._strfmt2 = "version: {2}, stag: {3}, offset: {6}, last: {1}, len: {7}"
        else:
            # DDP untagged messaged
            ulist = unpack.unpack(12, "!3I")
            self.queue  = ulist[0]
            self.msn    = ulist[1]
            self.offset = ulist[2]
            self._strfmt1 = "DDP   v{2:<3} queue: {4}, msn: {5}, offset: {6}, last: {1}, len: {7}"
            self._strfmt2 = "version: {2}, queue: {4}, msn: {5}, offset: {6}, last: {1}, len: {7}"

        # Get the payload size
        self.psize = unpack.size()

        # Get the un-dissected bytes
        size = self.psize
        if size > 0:
            self.data = unpack.read(size)
