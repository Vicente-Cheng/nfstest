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
RDMAP module

Decode RDMAP layer.

RFC 5040 Remote Direct Memory Access Protocol Specification
"""
import nfstest_config as c
from baseobj import BaseObj
from packet.unpack import Unpack
from packet.application.rpc import RPC
from packet.utils import IntHex, LongHex, Enum
from packet.application.rpcordma import RPCoRDMA
import packet.application.rpcordma_const as rdma

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2021 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

rdmap_op_codes = {
    0b0000 : "RDMA_Write",
    0b0001 : "RDMA_Read_Request",
    0b0010 : "RDMA_Read_Response",
    0b0011 : "Send",
    0b0100 : "Send_Invalidate",
    0b0101 : "Send_SE",
    0b0110 : "Send_SE_Invalidate",
    0b0111 : "Terminate",
}

# Create Operation Code constants
for (key, value) in rdmap_op_codes.items():
    exec("%s = %d" % (value, key))

class OpCode(Enum):
    """enum OpCode"""
    _enumdict = rdmap_op_codes

class RDMAP(BaseObj):
    """RDMAP object

       Usage:
           from packet.transport.rdmap import RDMAP

           x = RDMAP(pktt, pinfo)

       Object definition:

       RDMAP(
           version = int,  # RDMA Protocol version
           opcode  = int,  # RDMA OpCode
           psize   = int,  # Payload Size
           [ # Only valid for Send with Invalidate and Send with Solicited Event
             # and Invalidate Messages
               istag = int,  # Invalidate STag
           ]
           [ # RDMA Read Request Header
               sinkstag = int,  # Data Sink STag
               sinksto  = int,  # Data Sink Tagged Offset
               dma_len  = int,  # RDMA Read Message Size
               srcstag  = int,  # Data Source STag
               srcsto   = int,  # Data Source Tagged Offset
           ]
       )
    """
    # Class attributes
    _attrlist = ("version", "opcode", "istag", "sinkstag", "sinksto",
                 "dma_len", "srcstag", "srcsto", "psize")
    _strfmt1  = "RDMAP v{0:<3} {1} {_ddp}, len: {8}"
    _strfmt2  = "{1}, version: {0},{2:? istag\: {2},:} len: {8}"
    _senddata = {}

    def __init__(self, pktt, pinfo):
        """Constructor

           Initialize object's private data.

           pktt:
               Packet trace object (packet.pktt.Pktt) so this layer has
               access to the parent layers.
           pinfo:
               List of two integers: [RDMAP control, Invalidate STag].
        """
        unpack = pktt.unpack
        offset = unpack.tell()
        self._ddp = pktt.pkt.ddp

        self.version = (pinfo[0] >> 6) & 0x03  # RDMAP version
        reserved     = (pinfo[0] >> 4) & 0x03
        self.opcode  = OpCode(pinfo[0] & 0x0f) # RDMAP opcode

        if self.version not in (0, 1) or reserved != 0:
            unpack.seek(offset)
            return

        if not self._ddp.tagged:
            # Invalidate STag
            self.istag = IntHex(pinfo[1])

        if self.opcode == RDMA_Read_Request:
            ulist = unpack.unpack(28, "!IQIIQ")
            self.sinkstag = IntHex(ulist[0])
            self.sinksto  = LongHex(ulist[1])
            self.dma_len  = ulist[2]
            self.srcstag  = IntHex(ulist[3])
            self.srcsto   = LongHex(ulist[4])
            self._strfmt1 = "RDMAP v{0:<3} {1}  src: ({6}, {7}), sink: ({3}, {4}), dma_len: {5}"
            self._strfmt2 = "{1}, version: {0}, src: ({6}, {7}), sink: ({3}, {4}), dma_len: {5}"
        elif self.opcode == Terminate:
            # Terminate OpCode not supported yet
            pass

        # This is an RDMAP packet
        pktt.pkt.add_layer("rdmap", self)

        # Get payload size
        self.psize = unpack.size()

        # Decode payload
        self._decode_payload(pktt)

        # Get the un-dissected bytes
        size = unpack.size()
        if size > 0:
            self.data = unpack.read(size)

    @property
    def stag(self):
        return self._ddp.stag

    @property
    def offset(self):
        return self._ddp.offset

    @property
    def lastfl(self):
        return self._ddp.lastfl

    def _decode_payload(self, pktt):
        """Decode RDMAP payload."""
        unpack = pktt.unpack
        offset = unpack.tell()
        rdma_info = pktt._rdma_info
        rpcordma = None

        if self.opcode in (Send, Send_Invalidate, Send_SE, Send_SE_Invalidate):
            if self.lastfl:
                # Last send fragment
                # Find out if there is a reassembly table for the queue number
                squeue = self._senddata.get(self._ddp.queue)
                if squeue is not None:
                    # Find out if there are any fragments for this send message
                    # and remove the reassembly info from the table
                    sdata = squeue.pop(self._ddp.msn, None)
                    if sdata is not None:
                        # Add last send fragment
                        sdata[self.offset] = unpack.read(self.psize)
                        data = bytes(0)
                        # Reassemble the send message using the offset
                        # to order the fragments
                        for off in sorted(sdata.keys()):
                            data += sdata.pop(off)
                        # Replace the Unpack object with the reassembled data
                        pktt.unpack = Unpack(data)
                        unpack = pktt.unpack
            else:
                # Add send fragment to the reassembly table given by the queue
                # number and the message sequence number
                squeue = self._senddata.setdefault(self._ddp.queue, {})
                sdata  = squeue.setdefault(self._ddp.msn, {})
                # Order is based on the DDP offset
                sdata[self.offset] = unpack.read(self.psize)
                return

            try:
                rpcordma = RPCoRDMA(unpack)
            except:
                pass
            if rpcordma and rpcordma.vers == 1 and rdma.rdma_proc.get(rpcordma.proc):
                pktt.pkt.add_layer("rpcordma", rpcordma)
                if rpcordma.proc == rdma.RDMA_ERROR:
                    return
                if rpcordma.reads:
                    # Save RDMA read first fragment
                    rpcordma.data = unpack.read(len(unpack))
                # RPCoRDMA is valid so process the RDMA chunk lists
                replydata = rdma_info.process_rdma_segments(rpcordma)
                if rpcordma.proc == rdma.RDMA_MSG and not rpcordma.reads:
                    # Decode RPC layer except for an RPC call with
                    # RDMA read chunks in which the data has been reduced
                    RPC(pktt)
                elif rpcordma.proc == rdma.RDMA_NOMSG and replydata:
                    # This is a no-msg packet but the reply has already been
                    # sent using RDMA writes so just add the RDMA reply chunk
                    # data to the working buffer and decode the RPC layer
                    unpack.insert(replydata)
                    # Decode RPC layer
                    RPC(pktt)
            else:
                # RPCoRDMA is not valid
                unpack.seek(offset)
        elif self.opcode == RDMA_Write:
            rdma_info.add_iwarp_data(self, unpack)
        elif self.opcode == RDMA_Read_Request:
            rdma_info.add_iwarp_request(self)
        elif self.opcode == RDMA_Read_Response:
            data = rdma_info.reassemble_rdma_reads(unpack, rdmap=self)
            if data is not None:
                # Decode RPC layer
                pktt.unpack = Unpack(data)
                RPC(pktt)
