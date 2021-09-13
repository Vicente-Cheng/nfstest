#===============================================================================
# Copyright 2017 NetApp, Inc. All Rights Reserved,
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
RDMA reassembly module

Provides functionality to reassemble RDMA fragments.
"""
import nfstest_config as c
from packet.utils import RDMAbase

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2017 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.0"

class RDMAseg(object):
    """RDMA sub-segment object

       The sub-segment is created for each RDMA_WRITE_First, RDMA_WRITE_Only
       or RDMA_READ_Request and each sub-segment belongs to a list in the
       RDMAsegment object so there is no segment identifier or handle.

       Reassembly for each sub-segment is done using the PSN or packet
       sequence number in each of the data fragments. Therefore, a range
       of PSN numbers define this object which is given by the spsn and
       epsn attributes (first and last PSN respectively).
    """
    def __init__(self, spsn, epsn, dmalen):
        self.spsn     = spsn   # First PSN in sub-segment
        self.epsn     = epsn   # Last PSN in sub-segment
        self.dmalen   = dmalen # DMA length in sub-segment
        self.fraglist = []     # List of data fragments

    def __del__(self):
        """Destructor"""
        self.fraglist.clear()

    def insert_data(self, psn, data):
        """Insert data at correct position given by the psn"""
        # Make sure fragment belongs to this sub-segment
        if psn >= self.spsn and psn <= self.epsn:
            # Normalize psn with respect to first PSN
            index = psn - self.spsn
            fraglist = self.fraglist
            nlen = len(fraglist)
            if index < nlen:
                # This is an out-of-order fragment,
                # replace fragment data at index
                fraglist[index] = data
            else:
                # Some fragments may be missing
                for i in range(index - nlen):
                    # Use an empty string for missing fragments
                    # These may come later as out-of-order fragments
                    fraglist.append(b"")
                fraglist.append(data)
            return True
        return False

    def get_data(self, padding=True):
        """Return sub-segment data"""
        data = b""
        # Get data from all fragments
        for fragdata in self.fraglist:
            data += fragdata
        if not padding and len(data) > self.dmalen:
            return data[:self.dmalen-len(data)]
        return data

    def get_size(self):
        """Return sub-segment data size"""
        size = 0
        # Get the size from all fragments
        for fragdata in self.fraglist:
            size += len(fragdata)
        return size

class RDMAsegment(object):
    """RDMA segment object

       Each segment is identified by its handle. The segment information
       comes from the RPC-over-RDMA protocol layer so the length attribute
       gives the total DMA length of the segment.
    """
    def __init__(self, rdma_seg, rpcrdma):
        self.handle  = rdma_seg.handle
        self.offset  = rdma_seg.offset
        self.length  = rdma_seg.length
        self.xdrpos  = getattr(rdma_seg, "position", 0)  # RDMA read chunk XDR position
        self.rpcrdma = rpcrdma # RPC-over-RDMA object used for RDMA reads
        self.rhandle = None    # Read Response handle belonging to this segment
        self.roffset = None    # Read Response offset belonging to this segment
        self.rlength = None    # Read Request length
        self.fragments = {}    # List of iWarp data fragments

        # List of sub-segments (RDMAseg)
        # When the RDMA segment's length (DMA length) is large it could be
        # broken into multiple sub-segments. This is accomplished by sending
        # multiple Write First (or Read Request) packets where the RETH
        # specifies the same RKey(or handle) for all sub-segments and the
        # DMA length for the sub-segment.
        self.seglist = []

    def __del__(self):
        """Destructor"""
        self.fragments.clear()
        self.seglist.clear()

    def valid_psn(self, psn):
        """True if given psn is valid for this segment"""
        # Search all sub-segments
        for seg in self.seglist:
            if psn >= seg.spsn and psn <= seg.epsn:
                # Correct sub-segment found
                return True
        return False

    def add_sub_segment(self, psn, dmalen, only=False, iosize=0):
        """Add RDMA sub-segment PSN information"""
        seg = None
        # Find if sub-segment already exists
        for item in self.seglist:
            if psn == item.spsn:
                seg = item
                break
        if seg:
            # Sub-segment already exists, just update epsn
            if only:
                seg.epsn = psn
            elif iosize == 0:
                # This is a retransmission of Read Request since there
                # is no data
                return seg
            else:
                dmalen = seg.dmalen
                seg.epsn = psn + int(dmalen/iosize) - 1 + (1 if dmalen%iosize else 0)
        else:
            # Sub-segment does not exist, add it to the list
            if only:
                # Only one fragment thus epsn == spsn
                epsn = psn
            else:
                # Multiple fragments, calculate epsn if iosize is nonzero
                if iosize == 0:
                    # The iosize is not known for a Read Request which gives all
                    # information for the segment but does not have any data,
                    # thus the iosize is zero. The epsn will be updated in the
                    # RDMA Read First for this case.
                    # The last PSN is not known so set it to spsn so at
                    # least this PSN is valid for the sub-segment
                    epsn = psn
                else:
                    epsn = psn + int(dmalen/iosize) - 1 + (1 if dmalen%iosize else 0)
            seg = RDMAseg(psn, epsn, dmalen)
            self.seglist.append(seg)
        return seg

    def add_data(self, psn, data):
        """Add fragment data"""
        # Search for correct sub-segment
        for seg in self.seglist:
            if seg.insert_data(psn, data):
                # The insert_data method returns True on correct
                # sub-segment for given psn
                return

    def get_data(self, padding=True):
        """Return segment data"""
        data = b""
        if len(self.seglist):
            # Get data from all sub-segments
            for seg in self.seglist:
                data += seg.get_data(padding)
        elif len(self.fragments):
            # Get data from all iWarp fragments
            nextoff = self.get_offset()
            for offset in sorted(self.fragments.keys()):
                # Check for missing fragments
                count = offset - nextoff
                if count > 0:
                   # There are missing fragments
                   data += bytes(count)
                data += self.fragments[offset]
                nextoff = offset + len(self.fragments[offset])
            if not padding and len(data) > self.length:
                return data[:self.length-len(data)]
        return data

    def get_size(self):
        """Return segment data"""
        size = 0
        if len(self.seglist):
            # Get the size from all sub-segments
            for seg in self.seglist:
                size += seg.get_size()
        else:
            # Get size from all iWarp fragments
            nextoff = self.get_offset()
            for offset in sorted(self.fragments.keys()):
                # Check for missing fragments
                count = offset - nextoff
                if count > 0:
                   # There are missing fragments
                   size += count
                size += len(self.fragments[offset])
                nextoff = offset + len(self.fragments[offset])
        return size

    def get_offset(self):
        """Return the segment offset used for writes or read responses"""
        return self.offset if self.roffset is None else self.roffset

    def add_request(self, rdmap):
        """Add iWarp read request"""
        self.rhandle = rdmap.sinkstag
        self.roffset = rdmap.sinksto
        self.rlength = rdmap.dma_len

    def add_fragment(self, rdmap, unpack):
        """Add iWarp fragment to segment"""
        self.fragments[rdmap.offset] = unpack.read(rdmap.psize)

class RDMAinfo(RDMAbase):
    """RDMA info object used for reassembly

       The reassembled message consists of one or multiple chunks and
       each chunk in turn could be composed of multiple segments. Also,
       each segment could be composed of multiple sub-segments and each
       sub-segment could be composed of multiple fragments.
       The protocol only defines segments but if the segment length is
       large, it is split into multiple sub-segments in which each
       sub-segment is specified by RDMA_WRITE_First or RDMA_READ_Request
       packets. The handle is the same for each of these packets but with
       a shorter DMA length.

       Thus in order to reassemble all fragments for a single message,
       a list of segments is created where each segment is identified
       by its handle or RKey and the message is reassembled according
       to the chuck lists specified by the RPC-over-RDMA layer.
    """
    def __init__(self):
        # RDMA Reads/Writes/Reply segments {key: handle, value: RDMAsegment}
        self._rdma_segments = {}

    def size(self):
        """Return the number RDMA segments"""
        return len(self._rdma_segments)
    __len__ = size

    def reset(self):
        """Clear RDMA segments"""
        self._rdma_segments = {}
        self.sindex = 0
    __del__ = reset

    def get_rdma_segment(self, handle):
        """Return RDMA segment identified by the given handle"""
        return self._rdma_segments.get(handle)

    def del_rdma_segment(self, rsegment):
        """Delete RDMA segment information"""
        if rsegment is None:
            return
        self._rdma_segments.pop(rsegment.handle, None)
        if rsegment.rhandle is not None:
            self._rdma_segments.pop(rsegment.rhandle, None)

    def add_rdma_segment(self, rdma_seg, rpcrdma=None):
        """Add RDMA segment information and if the information already
           exists just update the length and return the segment
        """
        rsegment = self._rdma_segments.get(rdma_seg.handle)
        if rsegment:
            # Update segment's length and return the segment
            rsegment.length = rdma_seg.length
        else:
            # Add segment information
            self._rdma_segments[rdma_seg.handle] = RDMAsegment(rdma_seg, rpcrdma)
        return rsegment

    def add_rdma_data(self, psn, unpack, reth=None, only=False, read=False):
        """Add RDMA fragment data"""
        if reth:
            # The RETH object header is given which is the case for an OpCode
            # like *Only or *First, use the RETH RKey(or handle) to get the
            # correct segment where this fragment should be inserted
            rsegment = self.get_rdma_segment(reth.r_key)
            if rsegment:
                size = len(unpack)
                seg = rsegment.add_sub_segment(psn, reth.dma_len, only=only, iosize=size)
                if size > 0:
                    seg.insert_data(psn, unpack.read(size))
            return rsegment
        else:
            # The RETH object header is not given, find the correct segment
            # where this fragment should be inserted
            for rsegment in self._rdma_segments.values():
                if rsegment.valid_psn(psn):
                    size = len(unpack)
                    if read:
                        # Modify sub-segment for RDMA read (first or only)
                        # The sub-segment is added in the read request where
                        # RETH is given but the request does not have any
                        # data to correctly calculate the epsn
                        seg = rsegment.add_sub_segment(psn, 0, only=only, iosize=size)
                        seg.insert_data(psn, unpack.read(size))
                    else:
                        rsegment.add_data(psn, unpack.read(size))
                    return rsegment

    def add_iwarp_data(self, rdmap, unpack):
        """Add iWarp fragment data"""
        rsegment = self.get_rdma_segment(rdmap.stag)
        if rsegment is not None:
            rsegment.add_fragment(rdmap, unpack)
        return rsegment

    def add_iwarp_request(self, rdmap):
        """Add iWarp read request information"""
        # The data source STag is the handle given in the read chunk segment
        rsegment = self.get_rdma_segment(rdmap.srcstag)
        if rsegment is not None:
            rsegment.add_request(rdmap)
            # Create another segment entry using the data sink STag since
            # this is the handle to be used in the RDMA read responses.
            # This creates a mapping between the read responses and the
            # read chunk segment.
            self._rdma_segments[rdmap.sinkstag] = rsegment

    def reassemble_rdma_reads(self, unpack, psn=None, only=False, rdmap=None):
        """Reassemble RDMA read chunks
           The RDMA read chunks are reassembled in the read last operation
        """
        # Payload data in the reduced message (e.g., two chunks)
        # where each chunk data is sent separately using RDMA:
        # +----------------+----------------+----------------+
        # |    xdrdata1    |    xdrdata2    |    xdrdata3    |
        # +----------------+----------------+----------------+
        #    chunk data1 --^  chunk data2 --^
        #
        # Reassembled message should look like the following in which
        # the xdrpos specifies where the chunk data must be inserted.
        # The xdrpos is relative to the reassembled message and NOT
        # relative to the reduced message:
        # +----------+-------------+----------+-------------+----------+
        # | xdrdata1 | chunk data1 | xdrdata2 | chunk data2 | xdrdata3 |
        # +----------+-------------+----------+-------------+----------+
        # xdrpos1 ---^              xdrpos2 --^

        # Add RDMA read fragment
        if rdmap is None:
            rsegment = self.add_rdma_data(psn, unpack, only=only, read=only)
        else:
            rsegment = self.add_iwarp_data(rdmap, unpack)
        if rsegment is None or (rdmap is not None and rdmap.lastfl == 0):
            # Do not try to reassemble the RDMA reads if this is not
            # a read response last
            return

        # Get saved RPCoRDMA object to know how to reassemble the RDMA
        # read chunks and the data sent on the RDMA_MSG which has the
        # reduced message data
        rpcrdma = rsegment.rpcrdma
        if rpcrdma:
            # Get reduced data
            reduced_data = rpcrdma.data
            read_chunks = {}
            # Check if all segments are done
            for seg in rpcrdma.reads:
                rsegment = self._rdma_segments.get(seg.handle)
                if rsegment is None or rsegment.get_size() < rsegment.length:
                    # Not all data has been accounted for this segment
                    return
                # The RPC-over-RDMA protocol does not have a read chunk
                # list but instead it has a list of segments so arrange
                # the segments into chunks by using the XDR position.
                slist = read_chunks.setdefault(rsegment.xdrpos, [])
                slist.append(rsegment)

            data = b""
            offset = 0  # Current offset of reduced message
            # Reassemble the whole message
            for xdrpos in sorted(read_chunks.keys()):
                # Check if there is data from the reduced message which
                # should be inserted before this chunk
                if xdrpos > len(data):
                    # Insert data from the reduced message
                    size = xdrpos - len(data)
                    data += reduced_data[offset:size]
                    offset = size
                # Add all data from chunk
                for rsegment in read_chunks[xdrpos]:
                    # Get the bytes for the segment including the padding
                    # bytes because this is part of the message that will
                    # be dissected and the opaque needs a 4-byte boundary
                    # except if this is a Position-Zero Read Chunk (PZRC)
                    # in which the payload has already been padded
                    padding = False if xdrpos == 0 else True
                    data += rsegment.get_data(padding=padding)
                    self.del_rdma_segment(rsegment)
            if len(reduced_data) > offset:
                # Add last fragment from the reduced message
                data += reduced_data[offset:]
            return data

    def process_rdma_segments(self, rpcrdma):
        """Process the RPC-over-RDMA chunks

           When this method is called on an RPC call, it adds the
           information of all the segments to the list of segments.
           When this method is called on an RPC reply, the segments
           should already exist so just update the segment's DMA length
           as returned by the reply.

           RPCoRDMA reads attribute is a list of read segments
           Read segment is a plain segment plus an XDR position
           A read chunk is the collection of all read segments
           with the same XDR position

           RPCoRDMA writes attribute is a list of write chunks
           A write chunk is a list of plain segments

           RPCoRDMA reply is just a single write chunk if it exists.
           Return the reply chunk data
        """
        # Reassembly is done on the last read response of the last segment.
        # Process the rdma list to set up the expected read chunks and
        # their respective segments.
        # - Used for a large RPC call which has at least one
        #   large opaque, e.g., NFS WRITE
        # - The RPC call packet is used only to set up the RDMA read
        #   chunk list. It also has the reduced message data which
        #   includes the first fragment (XDR data up to and including
        #   the opaque length), but it could also have fragments which
        #   belong between each read chunk, and possibly a fragment after
        #   the last read chunk data.
        # - The opaque data is transferred via RDMA reads, once all
        #   fragments are accounted for they are reassembled and the
        #   whole RPC call is dissected in the last read response, so
        #   there is no RPCoRDMA layer
        #
        # - Packet sent order, the reduced RPC call is sent first, then the
        #   RDMA reads, e.g., showing only for a single chunk:
        #   +----------------+-------------+-----------+-----------+-----+-----------+
        #   | WRITE call XDR | opaque size |  GETATTR  | RDMA read | ... | RDMA read |
        #   +----------------+-------------+-----------+-----------+-----+-----------+
        #   |<-------------- First frame ------------->|<-------- chunk data ------->|
        #   Each RDMA read could be a single RDMA_READ_Response_Only or a series of
        #   RDMA_READ_Response_First, RDMA_READ_Response_Middle, ...,
        #   RDMA_READ_Response_Last
        #
        # - NFS WRITE call, this is how it should be reassembled:
        #   +----------------+-------------+-----------+-----+-----------+-----------+
        #   | WRITE call XDR | opaque size | RDMA read | ... | RDMA read |  GETATTR  |
        #   +----------------+-------------+-----------+-----+-----------+-----------+
        #                                  |<--- opaque (chunk) data --->|
        if rpcrdma.reads:
            # Add all segments in the RDMA read chunk list
            for rdma_seg in rpcrdma.reads:
                self.add_rdma_segment(rdma_seg, rpcrdma)

        # Reassembly is done on the reply message (RDMA_MSG)
        # Process the rdma list on the call message to set up the write
        # chunks and their respective segments expected by the reply
        # - Used for a large RPC reply which has at least one
        #   large opaque, e.g., NFS READ
        # - The RPC call packet is used only to set up the RDMA write
        #   chunk list
        # - The opaque data is transferred via RDMA writes
        # - The RPC reply packet has the reduced message data which
        #   includes the first fragment (XDR data up to and including
        #   the opaque length), but it could also have fragments which
        #   belong between each write chunk, and possibly a fragment
        #   after the last write chunk.
        # - The message is not actually reassembled here but instead a
        #   list of write chunks is created in the shared class attribute
        #   rdma_write_chunks. This attribute can be accessed by the upper
        #   layer and use the chunk data instead of getting the data from
        #   the unpack object.
        # - Packet sent order, the RDMA writes are sent first, then the
        #   reduced RPC reply, e.g., showing only for a single chunk:
        #   +------------+-----+------------+----------------+-------------+---------+
        #   | RDMA write | ... | RDMA write | READ reply XDR | opaque size | GETATTR |
        #   +------------+-----+------------+----------------+-------------+---------+
        #   |<-------- write chunk -------->|<------------- Last frame ------------->|
        #   Each RDMA write could be a single RDMA_WRITE_Only or a series of
        #   RDMA_WRITE_First, RDMA_WRITE_Middle, ..., RDMA_WRITE_Last
        #
        # - NFS READ reply, this is how it should be reassembled:
        #   +----------------+-------------+------------+-----+------------+---------+
        #   | READ reply XDR | opaque size | RDMA write | ... | RDMA write | GETATTR |
        #   +----------------+-------------+------------+-----+------------+---------+
        #                                  |<---- opaque (chunk) data ---->|
        if rpcrdma.writes:
            # Clear the list of RDMA write chunks
            while len(self.rdma_write_chunks):
                self.rdma_write_chunks.pop()

            # Process RDMA write chunk list
            for chunk in rpcrdma.writes:
                self.rdma_write_chunks.append([])
                # Process all segments in RDMA write chunk
                for seg in chunk.target:
                    rsegment = self.add_rdma_segment(seg)
                    if rsegment:
                        # Add segment to write chunk list, this list is
                        # available to upper layer objects which inherit
                        # from packet.utils.RDMAbase
                        self.rdma_write_chunks[-1].append(rsegment)

                if len(self.rdma_write_chunks[-1]) == 0:
                    # Clear list of RDMA write chunks if no segments were added
                    self.rdma_write_chunks.pop()

        # Reassembly is done on the reply message with proc=RDMA_NOMSG.
        # The RDMA list is processed on the call message to set up the
        # reply chunk and its respective segments expected by the reply
        # - The reply chunk is used for a large RPC reply which does not
        #   fit into a single SEND operation and does not have a single
        #   large opaque, e.g., NFS READDIR
        # - The RPC call packet is used only to set up the RDMA reply chunk
        # - The whole RPC reply is transferred via RDMA writes
        # - The RPC reply packet has no data (RDMA_NOMSG) but fragments are
        #   then reassembled and the whole RPC reply is dissected
        #
        # - Packet sent order, this is the whole XDR data for the RPC reply:
        #   +--------------------------+------------------+--------------------------+
        #   |        RDMA write        |       ...        |        RDMA write        |
        #   +--------------------------+------------------+--------------------------+
        #   Each RDMA write could be a single RDMA_WRITE_Only or a series of
        #   RDMA_WRITE_First, RDMA_WRITE_Middle, ..., RDMA_WRITE_Last
        replydata = b""
        if rpcrdma.reply:
            # Process all segments in the RDMA reply chunk
            for rdma_seg in rpcrdma.reply.target:
                rsegment = self.add_rdma_segment(rdma_seg)
                if rsegment:
                    # Get the bytes for the segment including the padding
                    # bytes because this is part of the message that will
                    # be dissected and the opaque needs a 4-byte boundary
                    replydata += rsegment.get_data(padding=True)
                    self.del_rdma_segment(rsegment)
        return replydata
