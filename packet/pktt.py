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
Packet trace module

The Packet trace module is a python module that takes a trace file created
by tcpdump and unpacks the contents of each packet. You can decode one packet
at a time, or do a search for specific packets. The main difference between
these modules and other tools used to decode trace files is that you can use
this module to completely automate your tests.

How does it work? It opens the trace file and reads one record at a time
keeping track where each record starts. This way, very large trace files
can be opened without having to wait for the file to load and avoid loading
the whole file into memory.

Packet layers supported:
    - ETHERNET II (RFC 894)
    - IP layer (supports IPv4 and IPv6)
    - UDP layer
    - TCP layer
    - RPC layer
    - NFS v4.0
    - NFS v4.1 including pNFS file layouts
    - NFS v4.2
    - PORTMAP v2
    - MOUNT v3
    - NLM v4
"""
import os
import re
import ast
import sys
import gzip
import time
import fcntl
import struct
import termios
from formatstr import *
import nfstest_config as c
from baseobj import BaseObj
from packet.link.erf import ERF
from packet.unpack import Unpack
from packet.record import Record
from packet.link.sllv1 import SLLv1
from packet.link.sllv2 import SLLv2
from packet.internet.ipv4 import IPv4
from packet.internet.ipv6 import IPv6
from packet.pkt import Pkt, PKT_layers
from packet.link.ethernet import ETHERNET
from packet.transport.rdmainfo import RDMAinfo

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "2.7"

BaseObj.debug_map(0x100000000, 'pkt1', "PKT1: ")
BaseObj.debug_map(0x200000000, 'pkt2', "PKT2: ")
BaseObj.debug_map(0x400000000, 'pkt3', "PKT3: ")
BaseObj.debug_map(0x800000000, 'pkt4', "PKT4: ")
BaseObj.debug_map(0xF00000000, 'pktt', "PKTT: ")

# Map of items not in the array of the compound
_nfsopmap = {'status', 'tag', 'minorversion'}
# Set of valid layers
_pkt_layers = set(PKT_layers)

# Read size -- the amount of data read at a time from the file
# The read ahead buffer actual size is always >= 2*READ_SIZE
READ_SIZE = 64*1024

# Show progress if stderr is a tty and stdout is not
SHOWPROG = os.isatty(2) and not os.isatty(1)

oplogic_d = {
    ast.Eq    : " == ",
    ast.NotEq : " != ",
    ast.Lt    : " < ",
    ast.LtE   : " <= ",
    ast.Gt    : " > ",
    ast.GtE   : " >= ",
    ast.Is    : " is ",
    ast.IsNot : " is not ",
    ast.In    : " in ",
    ast.NotIn : " not in ",
}

binop_d = {
    ast.Add      : " + ",
    ast.Sub      : " - ",
    ast.Mult     : " * ",
    ast.Div      : " / ",
    ast.FloorDiv : " // ",
    ast.Mod      : " % ",
    ast.Pow      : " ** ",
    ast.LShift   : " << ",
    ast.RShift   : " >> ",
    ast.BitOr    : " | ",
    ast.BitXor   : " ^ ",
    ast.BitAnd   : " & ",
    ast.MatMult  : " @ ",
}

bool_d = {
    ast.And : " and ",
    ast.Or  : " or ",
}

unary_d = {
    ast.Not    : "not ",
    ast.USub   : "-",
    ast.UAdd   : "+",
    ast.Invert : "~",
}

precedence_d = {
    ast.Pow      : 80,
    ast.USub     : 70,
    ast.UAdd     : 70,
    ast.Invert   : 70,
    ast.MatMult  : 60,
    ast.Mult     : 60,
    ast.Div      : 60,
    ast.FloorDiv : 60,
    ast.Mod      : 60,
    ast.Add      : 50,
    ast.Sub      : 50,
    ast.LShift   : 40,
    ast.RShift   : 40,
    ast.BitAnd   : 34,
    ast.BitXor   : 32,
    ast.BitOr    : 30,
    ast.Compare  : 20,
    ast.Not      : 14,
    ast.And      : 12,
    ast.Or       : 10,
}

def get_op(op):
    """Return the string representation of the logical operator AST object"""
    ret = oplogic_d.get(type(op))
    if ret is None:
        raise Exception("Unknown logical operator class '%s'" % op)
    return ret

def get_binop(op):
    """Return the string representation of the operator AST object"""
    ret = binop_d.get(type(op))
    if ret is None:
        raise Exception("Unknown operator class '%s'" % op)
    return ret

def get_precedence(op):
    """Return the precedence of operator AST object"""
    ret = precedence_d.get(type(op))
    if ret is None:
        raise Exception("Unknown operator class '%s'" % op)
    return ret

def get_bool(op):
    """Return the string representation of the logical operator AST object"""
    ret = bool_d.get(type(op))
    if ret is None:
        raise Exception("Unknown boolean operator class '%s'" % op)
    return ret

def get_unary(op):
    """Return the string representation of the unary operator AST object"""
    ret = unary_d.get(type(op))
    if ret is None:
        raise Exception("Unknown unary operator class '%s'" % op)
    return ret

def unparse(tree):
    """Older Python releases do not define ast.unparse(). Create function
       unparse with limited functionality but enough for the matching
       language it is needed for match(). This function runs twice as fast
       as ast.unparse(), so always use it regardless if it is defined or
       not on the ast module.
    """
    if isinstance(tree, ast.Name):
        return tree.id
    elif isinstance(tree, ast.Attribute):
        return unparse(tree.value) + "." + tree.attr
    elif isinstance(tree, ast.Constant):
        return repr(tree.value)
    elif isinstance(tree, ast.Tuple):
        tlist = [unparse(x) for x in tree.elts]
        if len(tlist) <= 1:
            # Empty or single item tuple must have a comma, e.g., (,) or ("item",)
            tlist.append("")
        return "(%s)" % ", ".join(tlist)
    elif isinstance(tree, ast.List):
        return "[%s]" % ", ".join([unparse(x) for x in tree.elts])
    elif isinstance(tree, ast.Call):
        return "%s(%s)" % (unparse(tree.func), ", ".join([unparse(x) for x in tree.args]))
    elif isinstance(tree, ast.Num):   # Deprecated
        return repr(tree.n)
    elif isinstance(tree, ast.Str):   # Deprecated
        return repr(tree.s)
    elif isinstance(tree, ast.Bytes): # Deprecated
        return repr(tree.s)
    elif isinstance(tree, ast.Expression):
        tree = tree.body

    if isinstance(tree, ast.Compare):
        left = unparse(tree.left)
        ops = [get_op(x) for x in tree.ops]
        comparators = [unparse(x) for x in tree.comparators]
        ret = left + "".join([x+y for x,y in zip(ops, comparators)])
        return ret
    elif isinstance(tree, ast.BoolOp):
        blist = []
        for item in tree.values:
            itemstr = unparse(item)
            if isinstance(item, ast.BoolOp):
                # Nested logical operations -- add parentheses
                itemstr = "(%s)" % itemstr
            blist.append(itemstr)
        return get_bool(tree.op).join([x for x in blist])
    elif isinstance(tree, ast.BinOp):
        lhs = unparse(tree.left)
        rhs = unparse(tree.right)
        if isinstance(tree.left, ast.BinOp) and \
           ((isinstance(tree.op, ast.Pow) and tree.op == tree.left.op) or \
           get_precedence(tree.left.op) < get_precedence(tree.op)):
            # Add parentheses on the LHS according to operation precedence
            # or if both operations are '**' -- exponent operation has a
            # right-to-left associativity as opposed to others operations
            # which have a left-to-right associativity
            lhs = "(%s)" % lhs
        if isinstance(tree.right, ast.BinOp) and \
           get_precedence(tree.right.op) < get_precedence(tree.op):
            rhs = "(%s)" % rhs
        return (lhs + get_binop(tree.op) + rhs)
    elif isinstance(tree, ast.UnaryOp):
        operand = unparse(tree.operand)
        if isinstance(tree.operand, (ast.BinOp, ast.BoolOp)) and \
           get_precedence(tree.operand.op) < get_precedence(tree.op):
            operand = "(%s)" % operand
        return get_unary(tree.op) + operand

def convert_attrs(tree):
    """Convert all valid layer AST Attributes to fully qualified names.
       Also, return the name of the correct wrapper function to be used.

       NOTE:
         The tree argument is modified so when tree is unparsed, all layer
         attributes are expanded correctly.
    """
    name = None
    for node in ast.walk(tree):
        curr = node
        while isinstance(curr, ast.Attribute):
            if isinstance(curr.value, ast.Name):
                layer = curr.value.id.lower()
                if layer == 'nfs' and curr.attr not in _nfsopmap:
                    curr.value.id = layer
                    name = 'match_nfs'
                elif layer in _pkt_layers:
                    # Add proper object prefix
                    curr.value.id = 'self.pkt.' + layer
                    if name is None:
                        name = 'match_pkt'
                break
            curr = curr.value
    return name

class Header(BaseObj):
    # Class attributes
    _attrlist = ("major", "minor", "zone_offset", "accuracy",
                 "dump_length", "link_type")

    def __init__(self, pktt):
        ulist = struct.unpack(pktt.header_fmt, pktt._read(20))
        self.major       = ulist[0]
        self.minor       = ulist[1]
        self.zone_offset = ulist[2]
        self.accuracy    = ulist[3]
        self.dump_length = ulist[4]
        self.link_type   = ulist[5]

class Pktt(BaseObj):
    """Packet trace object

       Usage:
           from packet.pktt import Pktt

           x = Pktt("/traces/tracefile.cap")

           # Iterate over all packets found in the trace file
           for pkt in x:
               print pkt
    """
    def __init__(self, tfile, live=False, rpc_replies=True):
        """Constructor

           Initialize object's private data, note that this will not check the
           file for existence nor will open the file to verify if it is a valid
           tcpdump file. The tcpdump trace file will be opened the first time a
           packet is retrieved.

           tracefile:
               Name of tcpdump trace file or a list of trace file names
               (little or big endian format)
           live:
               If set to True, methods will not return if encountered <EOF>,
               they will keep on trying until more data is available in the
               file. This is useful when running tcpdump in parallel,
               especially when tcpdump is run with the '-C' option, in which
               case when <EOF> is encountered the next trace file created by
               tcpdump will be opened and the object will be re-initialized,
               all private data referencing the previous file is lost.
        """
        self.tfile   = tfile  # Current trace file name
        self.bfile   = tfile  # Base trace file name
        self.live    = live   # Set to True if dealing with a live tcpdump file
        self.offset  = 0      # Current file offset
        self.boffset = -1     # File offset of current packet
        self.ioffset = 0      # File offset of first packet
        self.index   = 0      # Current packet index
        self.frame   = 0      # Current frame number
        self.dframe  = 0      # Frame number was incremented when set to 1
        self.mindex  = 0      # Maximum packet index for current trace file
        self.findex  = 0      # Current tcpdump file index (used with self.live)
        self.pindex  = 0      # Current packet index (for pktlist)
        self.pktlist = None   # Match from this packet list instead
        self.fh      = None   # Current file handle
        self.eof     = False  # End of file marker for current packet trace
        self.serial  = False  # Processing trace files serially
        self.pkt     = None   # Current packet
        self.pkt_call  = None # The current packet call if self.pkt is a reply
        self.pktt_list = []   # List of Pktt objects created
        self.tfiles    = []   # List of packet trace files
        self.rdbuffer  = b""  # Read buffer
        self.rdoffset  = 0    # Read buffer offset
        self.filesize  = 0    # Size of packet trace file
        self.prevprog  = -1.0 # Previous progress percentage
        self.prevtime  = 0.0  # Previous segment time
        self.prevdone  = -1   # Previous progress bar units done so far
        self.prevoff   = 0    # Previous offset
        self.showprog  = 0    # If this is true the progress will be displayed
        self.progdone  = 0    # Display last progress only once
        self.maxindex  = None # Global maxindex default
        self.timestart = time.time() # Time reference base
        self.reply_matched = False   # Matching a reply
        self._cleanup_done = False   # Cleanup of attributes has been done
        self.rpc_replies = rpc_replies  # Dissect RPC replies

        # TCP stream map: to keep track of the different TCP streams within
        # the trace file -- used to deal with RPC packets spanning multiple
        # TCP packets or to handle a TCP packet having multiple RPC packets
        self._tcp_stream_map = {}

        # IPv4 fragments used in reassembly
        self._ipv4_fragments = {}

        # RDMA reassembly object
        self._rdma_info = RDMAinfo()

        # RPC xid map: to keep track of packet calls
        self._rpc_xid_map = {}
        # List of outstanding xids to match
        self._match_xid_list = []

        # Process tfile argument
        if isinstance(tfile, list):
            # The argument tfile is given as a list of packet trace files
            self.tfiles = tfile
            if len(self.tfiles) == 1:
                # Only one file is given
                self.tfile = self.tfiles[0]
            else:
                # Create all packet trace objects
                for tfile in self.tfiles:
                    self.pktt_list.append(Pktt(tfile, rpc_replies=self.rpc_replies))

    @property
    def rdma_info(self):
        return self._rdma_info

    def close(self):
        """Gracefully close the tcpdump trace file and cleanup attributes."""
        if self._cleanup_done:
            return

        # Cleanup is done just once
        self._cleanup_done = True

        if self.fh:
            # Close packet trace
            self.fh.close()
            self.fh = None
        elif self.pktt_list:
            # Close all packet traces
            for pktt in self.pktt_list:
                pktt.close()

        # Cleanup object attributes to release memory
        del self.pkt
        del self.pktlist
        del self.rdbuffer
        del self.pktt_list
        del self.pkt_call
        del self._match_xid_list
        del self._tcp_stream_map
        del self._rpc_xid_map
        del self._rdma_info

    def __del__(self):
        """Destructor

           Gracefully close the tcpdump trace file if it is opened.
        """
        self.close()

    def __iter__(self):
        """Make this object iterable."""
        return self

    def __contains__(self, expr):
        """Implement membership test operator.
           Return true if expr matches a packet in the trace file,
           false otherwise.

           The packet is also stored in the object attribute pkt.

           Examples:
               # Find the next READ request
               if ("NFS.argop == 25" in x):
                   print x.pkt.nfs

           See match() method for more information
        """
        pkt = self.match(expr)
        return (pkt is not None)

    def __getitem__(self, index):
        """Get the packet from the trace file given by the index
           or raise IndexError.

           The packet is also stored in the object attribute pkt.

           Examples:
               pkt = x[index]
        """
        self.dprint('PKT4', ">>> %d: __getitem__(%d)" % (self.get_index(), index))
        if index < 0:
            # No negative index is allowed
            raise IndexError

        try:
            if index == self.pkt.record.index:
                # The requested packet is in memory, just return it
                return self.pkt
        except:
            pass

        if index < self.index:
            # Reset the current packet index and offset
            # The index is less than the current packet offset so position
            # the file pointer to the offset of the packet given by index
            self.rewind(index)

        # Move to the packet specified by the index
        pkt = None
        while self.index <= index:
            try:
                pkt = next(self)
            except:
                break

        if pkt is None:
            raise IndexError
        return pkt

    def __next__(self):
        """Get the next packet from the trace file or raise StopIteration.

           The packet is also stored in the object attribute pkt.

           Examples:
               # Iterate over all packets found in the trace file using
               # the iterable properties of the object
               for pkt in x:
                   print pkt

               # Iterate over all packets found in the trace file using it
               # as a method and using the object variable as the packet
               # Must use the try statement to catch StopIteration exception
               try:
                   while (x.next()):
                       print x.pkt
               except StopIteration:
                   pass

               # Iterate over all packets found in the trace file using it
               # as a method and using the return value as the packet
               # Must use the try statement to catch StopIteration exception
               while True:
                   try:
                       print x.next()
                   except StopIteration:
                       break

           NOTE:
               Supports only single active iteration
        """
        self.dprint('PKT4', ">>> %d: next()" % self.index)
        # Initialize next packet
        self.pkt = Pkt()

        if len(self.pktt_list) > 1:
            # Dealing with multiple trace files
            minsecs  = None
            pktt_obj = None
            for obj in self.pktt_list:
                if obj.pkt is None:
                    # Get first packet for this packet trace object
                    try:
                        next(obj)
                    except StopIteration:
                        obj.mindex = self.index
                if obj.eof:
                    continue
                if minsecs is None or obj.pkt.record.secs < minsecs:
                    minsecs = obj.pkt.record.secs
                    pktt_obj = obj
            if self.filesize == 0:
                # Calculate total bytes to process
                for obj in self.pktt_list:
                    self.filesize += obj.filesize
            if pktt_obj is None:
                # All packet trace files have been processed
                self.offset = self.filesize
                self.show_progress(True)
                raise StopIteration
            elif len(self._tcp_stream_map) or len(self._rdma_info):
                # This packet trace file should be processed serially
                # Have all state transferred to next packet object
                pktt_obj.rewind()
                if len(self._tcp_stream_map):
                    pktt_obj._tcp_stream_map = self._tcp_stream_map
                    pktt_obj._rpc_xid_map    = self._rpc_xid_map
                    self._tcp_stream_map = {}
                    self._rpc_xid_map    = {}
                if len(self._rdma_info):
                    pktt_obj._rdma_info = self._rdma_info
                    self._rdma_info = RDMAinfo()
                next(pktt_obj)

            if pktt_obj.dframe:
                # Increment cumulative frame number
                self.frame += 1

            # Overwrite attributes seen by the caller with the attributes
            # from the current packet trace object
            self.pkt = pktt_obj.pkt
            self.pkt_call = pktt_obj.pkt_call
            self.tfile = pktt_obj.tfile
            self.pkt.record.index = self.index  # Use a cumulative index
            self.pkt.record.frame = self.frame  # Use a cumulative frame
            self.offset += pktt_obj.offset - pktt_obj.boffset

            try:
                # Get next packet for this packet trace object
                next(pktt_obj)
            except StopIteration:
                # Set maximum packet index for this packet trace object to
                # be used by rewind to select the proper packet trace object
                pktt_obj.mindex = self.index
                # Check if objects should be serially processed
                pktt_obj.serial = False
                for obj in self.pktt_list:
                    if not obj.eof:
                        if obj.index > 1:
                            pktt_obj.serial = False
                            break
                        elif obj.index == 1:
                            pktt_obj.serial = True
                if pktt_obj.serial:
                    # Save current state
                    self._tcp_stream_map = pktt_obj._tcp_stream_map
                    self._rpc_xid_map    = pktt_obj._rpc_xid_map
                    self._rdma_info      = pktt_obj._rdma_info

            self.show_progress()

            # Increment cumulative packet index
            self.index += 1
            return self.pkt

        if self.boffset != self.offset:
            # Frame number is one for every record header on the pcap trace
            # On the other hand self.index is the packet number. Since there
            # could be multiple packets on a single frame self.index could
            # be larger than self.frame except that self.index start at 0
            # while self.frame starts at 1.
            # The frame number can be used to match packets with other tools
            # like wireshark
            self.frame += 1
            self.dframe = 1
        else:
            self.dframe = 0

        # Save file offset for this packet
        self.boffset = self.offset

        # Get record header
        data = self._read(16)
        if len(data) < 16:
            self.eof = True
            self.offset = self.filesize
            self.show_progress(True)
            raise StopIteration
        # Decode record header
        record = Record(self, data)

        # Get record data and create Unpack object
        self.unpack = Unpack(self._read(record.length_inc))
        if self.unpack.size() < record.length_inc:
            # Record has been truncated, stop iteration
            self.eof = True
            self.offset = self.filesize
            self.show_progress(True)
            raise StopIteration

        if self.header.link_type == 1:
            # Decode ethernet layer
            ETHERNET(self)
        elif self.header.link_type == 101:
            # Decode raw ip layer
            uoffset = self.unpack.tell()
            ipver = self.unpack.unpack_uchar()
            self.unpack.seek(uoffset)
            if (ipver >> 4) == 4:
                # Decode IPv4 packet
                IPv4(self)
            elif (ipver >> 4) == 6:
                # Decode IPv6 packet
                IPv6(self)
        elif self.header.link_type == 113:
            # Decode Linux "cooked" v1 capture encapsulation layer
            SLLv1(self)
        elif self.header.link_type == 276:
            # Decode Linux "cooked" v2 capture encapsulation layer
            SLLv2(self)
        elif self.header.link_type == 197:
            # Decode extensible record format layer
            ERF(self)
        else:
            # Unknown link layer
            record.data = self.unpack.getbytes()

        self.show_progress()

        # Increment packet index
        self.index += 1

        return self.pkt

    def rewind(self, index=0):
        """Rewind the trace file by setting the file pointer to the start of
           the given packet index. Returns False if unable to rewind the file,
           e.g., when the given index is greater than the maximum number
           of packets processed so far.
        """
        self.dprint('PKT1', ">>> %d: rewind(%d)" % (self.get_index(), index))
        if self.pktlist is not None:
            self.pindex = index
            return True
        if index >= 0 and index < self.index:
            if len(self.pktt_list) > 1:
                # Dealing with multiple trace files
                self.index = 0
                self.frame = 0
                for obj in self.pktt_list:
                    if not obj.eof or index <= obj.mindex:
                        obj.rewind()
                        try:
                            next(obj)
                        except StopIteration:
                            pass
                    elif obj.serial and index > obj.mindex:
                        self.index = obj.mindex + 1
            else:
                # Reset the current packet index and offset to the first packet
                self.offset  = self.ioffset
                self.boffset = 0
                self.index   = 0
                self.frame   = 0
                self.eof     = False

                # Position the file pointer to the offset of the first packet
                self.seek(self.ioffset)

                # Clear state
                self._tcp_stream_map = {}
                self._rpc_xid_map    = {}
                self._rdma_info = RDMAinfo()

            # Move to the packet before the specified by the index so the
            # next packet fetched will be the one given by index
            while self.index < index:
                try:
                    pkt = next(self)
                except:
                    break

            # Rewind succeeded
            return True
        return False

    def seek(self, offset, whence=os.SEEK_SET, hard=False):
        """Position the read offset correctly
           If new position is outside the current read buffer then clear the
           buffer so a new chunk of data will be read from the file instead
        """
        soffset = self.fh.tell() - len(self.rdbuffer)
        if hard or offset < soffset or whence != os.SEEK_SET:
            # Seek is before the read buffer, do the actual seek
            self.rdbuffer = b""
            self.rdoffset = 0
            self.fh.seek(offset, whence)
            self.offset = self.fh.tell()
        else:
            # Seek is not before the read buffer
            self.rdoffset = offset - soffset
            self.offset = offset

    def _getfh(self):
        """Get the filehandle of the trace file, open file if necessary."""
        if self.fh == None:
            # Check size of file
            fstat = os.stat(self.tfile)
            if fstat.st_size == 0:
                raise Exception("Packet trace file is empty")

            # Open trace file
            self.fh = open(self.tfile, 'rb')
            self.filesize = fstat.st_size

            iszip = False
            self.header_fmt = None
            while self.header_fmt is None:
                # Initialize offset
                self.offset = 0

                # Get file identifier
                try:
                    self.ident = self._read(4)
                except:
                    self.ident = ""

                if self.ident == b'\324\303\262\241':
                    # Little endian
                    self.header_fmt = '<HHIIII'
                    self.header_rec = '<IIII'
                elif self.ident == b'\241\262\303\324':
                    # Big endian
                    self.header_fmt = '>HHIIII'
                    self.header_rec = '>IIII'
                else:
                    if iszip:
                        raise Exception('Not a tcpdump file')
                    iszip = True
                    # Get the size of the uncompressed file, this only works
                    # for uncompressed files less than 4GB
                    self.fh.seek(-4, os.SEEK_END)
                    self.filesize = struct.unpack("<I", self.fh.read(4))[0]
                    # Do a hard seek -- clear read ahead buffer
                    self.seek(0, hard=True)
                    # Try if this is a gzip compress file
                    self.fh = gzip.GzipFile(fileobj=self.fh)

            # Get header information
            self.header = Header(self)

            # Initialize packet number
            self.index   = 0
            self.tstart  = None
            self.ioffset = self.offset

        return self.fh

    def _read(self, count):
        """Wrapper for read in order to increment the object's offset. It also
           takes care of <EOF> when 'live' option is set which keeps on trying
           to read and switching files when needed.
        """
        # Open packet trace if needed
        self._getfh()
        while True:
            # Get the number of bytes specified
            rdsize = len(self.rdbuffer) - self.rdoffset
            if count > rdsize:
                # Not all bytes needed are in the read buffer
                if self.rdoffset > READ_SIZE:
                    # If the read offset is on the second half of the
                    # 2*READ_SIZE buffer discard the first bytes so the
                    # new read offset is right at the middle of the buffer
                    # This is done in case there is a seek behind the current
                    # offset so data is not read from the file again
                    self.rdbuffer = self.rdbuffer[self.rdoffset-READ_SIZE:]
                    self.rdoffset = READ_SIZE
                # Read next chunk from file
                self.rdbuffer += self.fh.read(max(count, READ_SIZE))
            # Get the bytes requested and increment read offset accordingly
            data = self.rdbuffer[self.rdoffset:self.rdoffset+count]
            self.rdoffset += count

            ldata = len(data)
            if self.live and ldata != count:
                # Not all data was read (<EOF>)
                tracefile = "%s%d" % (self.bfile, self.findex+1)
                # Check if next trace file exists
                if os.path.isfile(tracefile):
                    # Save information that keeps track of the next trace file
                    basefile = self.bfile
                    findex = self.findex + 1
                    # Re-initialize the object
                    self.__del__()
                    self.__init__(tracefile, live=self.live)
                    # Overwrite next trace file info
                    self.bfile = basefile
                    self.findex = findex
                # Re-position file pointer to last known offset
                self.seek(self.offset)
                time.sleep(1)
            else:
                break

        # Increment object's offset by the amount of data read
        self.offset += ldata
        return data

    def get_index(self):
        """Get current packet index"""
        if self.pktlist is None:
            return self.index
        else:
            return self.pindex

    def set_pktlist(self, pktlist=None):
        """Set the current packet list for buffered matching in which the
           match method will only use this list instead of getting the next
           packet from the packet trace file.
           This could be used when there is a lot of matching going back
           and forth but only on a particular set of packets.
           See the match() method for an example of buffered matching.
        """
        pstr = "None" if pktlist is None else "[...]"
        self.dprint('PKT1', ">>> %d: set_pktlist(%s)" % (self.get_index(), pstr))
        self.pindex  = 0
        self.pktlist = pktlist

    def clear_xid_list(self):
        """Clear list of outstanding xids"""
        self._match_xid_list = []

    def _convert_match(self, matchstr, astout=False):
        """Convert a string match expression into a valid match expression
           to be evaluated by eval(). All items specified as valid packet
           layers are replaced with a call to the correct wrapper function.

           Examples:
               expr = "TCP.flags.ACK == 1 and NFS.argop == 50"
               data = self._convert_match(expr)
               Returns:
               "self.match_pkt('self.pkt.tcp.flags.ACK == 1') and self.match_nfs('nfs.argop == 50')"

               expr = "tcp.dst_port == 2049"
               data = self._convert_match(expr)
               Returns:
               "self.match_pkt('self.pkt.tcp.dst_port == 2049')"

               expr = "2049 == tcp.dst_port"
               data = self._convert_match(expr)
               Returns:
               "self.match_pkt('2049 == self.pkt.tcp.dst_port')"

               expr = "nfs.status == 0"
               data = self._convert_match(expr)
               Returns:
               "self.match_pkt('self.pkt.nfs.status == 0')"

               expr = "(crc32(nfs.fh) == 0x0f581ee9)"
               data = self._convert_match(expr)
               Returns:
               "self.match_nfs('crc32(nfs.fh) == 257433321')"

               expr = "re.search(r'192\..*', ip.src)"
               data = self._convert_match(expr)
               Returns:
               "self.match_pkt(\"re.search('192\\\\..*', self.pkt.ip.src)\")"
        """
        if isinstance(matchstr, str):
            # Convert match string into an AST object
            tree = ast.parse(matchstr, mode='eval')
        else:
            tree = matchstr

        if isinstance(tree, ast.Expression):
            tree = tree.body
        if isinstance(tree, (ast.Compare, ast.Call, ast.UnaryOp, ast.BinOp)):
            name = convert_attrs(tree)
            if name is not None:
                # Create wrapper function AST having the modified tree as the arguments
                func = ast.Attribute(ast.Name("self", ast.Load()), name, ast.Load())
                args = [ast.Constant(unparse(tree))]
                tree = ast.Call(func, args, [])
        elif isinstance(tree, ast.BoolOp):
            # Process logical operators ("and", "or")
            for idx in range(len(tree.values)):
                subexpr = tree.values[idx]
                tree.values[idx] = self._convert_match(subexpr, True)
        else:
            raise Exception("%r should be a comparison, function call or unary operation" % unparse(tree))

        return (tree if astout else unparse(tree))

    def match_pkt(self, expr):
        """Default wrapper function to evaluate a simple string expression."""
        ret = False
        try:
            ret = eval(expr)
        except:
            pass

        self.dprint('PKT3', "    %d: match_pkt(%s) -> %r" % (self.pkt.record.index, expr, ret))
        return ret

    def match_nfs(self, expr):
        """Match NFS values on current packet.

           In NFSv4, there is a single compound procedure with multiple
           operations, matching becomes a little bit tricky in order to make
           the matching expression easy to use. The NFS object's name space
           gets converted into a flat name space for the sole purpose of
           matching. In other words, all operation objects in array are
           treated as being part of the NFS object's top level attributes.

           Consider the following NFS object:
               nfsobj = COMPOUND4res(
                   status=NFS4_OK,
                   tag='NFSv4_tag',
                   array = [
                       nfs_resop4(
                           resop=OP_SEQUENCE,
                           opsequence=SEQUENCE4res(
                               status=NFS4_OK,
                               resok=SEQUENCE4resok(
                                   sessionid='sessionid',
                                   sequenceid=29,
                                   slotid=0,
                                   highest_slotid=179,
                                   target_highest_slotid=179,
                                   status_flags=0,
                               ),
                           ),
                       ),
                       nfs_resop4(
                           resop=OP_PUTFH,
                           opputfh = PUTFH4res(
                               status=NFS4_OK,
                           ),
                       ),
                       ...
                   ]
               ),

           The result for operation PUTFH is the second in the list:
               putfh = nfsobj.array[1]

           From this putfh object the status operation can be accessed as:
               status = putfh.opputfh.status

           or simply as (this is how the NFS object works):
               status = putfh.status

           In this example, the following match expression 'NFS.status == 0'
           could match the top level status of the compound (nfsobj.status)
           or the putfh status (nfsobj.array[1].status)

           The following match expression 'NFS.sequenceid == 25' will also
           match this packet as well, even though the actual expression should
           be 'nfsobj.array[0].opsequence.resok.sequenceid == 25' or
           simply 'nfsobj.array[0].sequenceid == 25'.

           This approach makes the match expressions simpler at the expense of
           having some ambiguities on where the actual match occurred. If a
           match is desired on a specific operation, a more qualified name can
           be given. In the above example, in order to match the status of the
           PUTFH operation the match expression 'NFS.opputfh.status == 0' can
           be used. On the other hand, consider a compound having multiple
           PUTFH results the above match expression will always match the first
           occurrence of PUTFH where the status is 0. There is no way to tell
           the match engine to match the second or Nth occurrence of an
           operation.
        """
        ret = False
        try:
            if self.pkt.rpc.version == 3:
                # NFSv3 packet set nfs object
                nfs = self.pkt.nfs
                if eval(expr):
                    # Set NFSop and NFSidx
                    self._nfsop  = nfs
                    self._nfsidx = None
                    ret = True
            else:
                idx = 0
                # NFSv4 packet, nfs object is each item in the array
                for nfs in self.pkt.nfs.array:
                    try:
                        if eval(expr):
                            self._nfsop  = nfs
                            self._nfsidx = idx
                            ret = True
                            continue
                    except Exception:
                        # Continue searching on next operation
                        pass
                    idx += 1
        except:
            pass

        self.dprint('PKT3', "    %d: match_nfs(%s) -> %r" % (self.pkt.record.index, expr, ret))
        return ret

    def match(self, expr, maxindex=None, rewind=True, reply=False):
        """Return the packet that matches the given expression, also the packet
           index points to the next packet after the matched packet.
           Returns None if packet is not found and the packet index points
           to the packet at the beginning of the search.

           expr:
               String of expressions to be evaluated
           maxindex:
               The match fails if packet index hits this limit
           rewind:
               Rewind to index where matching started if match fails
           reply:
               Match RPC replies of previously matched calls as well

           Examples:
               # Find the packet with both the ACK and SYN TCP flags set to 1
               pkt = x.match("TCP.flags.ACK == 1 and TCP.flags.SYN == 1")

               # Find the next NFS EXCHANGE_ID request
               pkt = x.match("NFS.argop == 42")

               # Find the next NFS EXCHANGE_ID or CREATE_SESSION request
               pkt = x.match("NFS.argop in [42,43]")

               # Find the next NFS OPEN request or reply
               pkt = x.match("NFS.op == 18")

               # Find all packets coming from subnet 192.168.1.0/24 using
               # a regular expression
               while x.match(r"re.search('192\.168\.1\.\d*', IP.src)"):
                   print x.pkt.tcp

               # Find packet having a GETATTR asking for FATTR4_FS_LAYOUT_TYPES(bit 62)
               pkt_call = x.match("NFS.attr_request & 0x4000000000000000L != 0")
               if pkt_call:
                   # Find GETATTR reply
                   xid = pkt_call.rpc.xid
                   # Find reply where the number 62 is in the array NFS.attributes
                   pkt_reply = x.match("RPC.xid == %d and 62 in NFS.attributes" % xid)

               # Find the next WRITE request
               pkt = x.match("NFS.argop == 38")
               if pkt:
                   print pkt.nfs

               # Same as above, but using membership test operator instead
               if ("NFS.argop == 38" in x):
                   print x.pkt.nfs

               # Get a list of all OPEN and CLOSE packets then use buffered
               # matching to process each OPEN and its corresponding CLOSE
               # at a time including both requests and replies
               pktlist = []
               while x.match("NFS.op in [4,18]"):
                   pktlist.append(x.pkt)
               # Enable buffered matching
               x.set_pktlist(pktlist)
               while x.match("NFS.argop == 18"): # Find OPEN request
                   print x.pkt
                   index = x.get_index()
                   # Find OPEN reply
                   x.match("RPC.xid == %d and NFS.resop == 18" % x.pkt.rpc.xid)
                   print x.pkt
                   # Find corresponding CLOSE request
                   stid = x.escape(x.pkt.NFSop.stateid.other)
                   x.match("NFS.argop == 4 and NFS.stateid == '%s'" % stid)
                   print x.pkt
                   # Find CLOSE reply
                   x.match("RPC.xid == %d and NFS.resop == 4" % x.pkt.rpc.xid)
                   print x.pkt
                   # Rewind to right after the OPEN request
                   x.rewind(index)
               # Disable buffered matching
               x.set_pktlist()

           See also:
               match_ethernet(), match_ip(), match_tcp(), match_rpc(), match_nfs()
        """
        # Parse match expression
        pdata = self._convert_match(expr)
        self.reply_matched = False
        if self.pktlist is None:
            pkt_list   = self
            save_index = self.index
        else:
            pkt_list   = self.pktlist
            save_index = self.pindex
        self.dprint('PKT1', ">>> %d: match(%s)" % (save_index, expr))
        self._nfsop  = None
        self._nfsidx = None

        if maxindex is None:
            # Use global max index as default
            maxindex = self.maxindex

        # Search one packet at a time
        for pkt in pkt_list:
            if maxindex and pkt.record.index >= maxindex:
                # Hit maxindex limit
                break
            if self.pktlist is not None:
                if pkt.record.index < self.pindex:
                    continue
                else:
                    self.pindex = pkt.record.index + 1
                    self.pkt = pkt
            try:
                if reply and pkt == "rpc" and pkt.rpc.type == 1 and pkt.rpc.xid in self._match_xid_list:
                    self.dprint('PKT1', ">>> %d: match() -> True: reply" % pkt.record.index)
                    self._match_xid_list.remove(pkt.rpc.xid)
                    self.reply_matched = True
                    self.dprint('PKT2', "    %s" % pkt)
                    return pkt
                if eval(pdata):
                    # Return matched packet
                    self.dprint('PKT1', ">>> %d: match() -> True" % pkt.record.index)
                    if reply and pkt == "rpc" and pkt.rpc.type == 0:
                        # Save xid of matched call
                        self._match_xid_list.append(pkt.rpc.xid)
                    self.dprint('PKT2', "    %s" % pkt)
                    pkt.NFSop  = self._nfsop
                    pkt.NFSidx = self._nfsidx
                    return pkt
            except Exception:
                pass

        if rewind:
            # No packet matched, re-position the file pointer back to where
            # the search started
            self.rewind(save_index)
        self.pkt = None
        self.dprint('PKT1', ">>> %d: match() -> False" % self.get_index())
        return None

    def show_progress(self, done=False):
        """Display progress bar if enabled and if running on correct terminal"""
        if SHOWPROG and self.showprog and (done or self.index % 500 == 0) \
          and (os.getpgrp() == os.tcgetpgrp(sys.stderr.fileno())):
            rows, columns = struct.unpack('hh', fcntl.ioctl(2, termios.TIOCGWINSZ, "1234"))
            if columns < 100:
                sps = 40
            else:
                # Terminal is wide enough, include bytes/sec
                sps = 52
            # Progress bar length
            wlen = int(columns) - sps
            # Progress bar units done so far
            xdone = int(wlen*self.offset/self.filesize)
            xtime = time.time()
            progress = 100.0*self.offset/self.filesize

            # Display progress only if there is some change in progress
            if (done and not self.progdone) or (self.prevdone != xdone or \
               int(self.prevtime) != int(xtime) or \
               round(self.prevprog) != round(progress)):
                if done:
                    # Do not display progress again when done=True
                    self.progdone = 1
                otime  = xtime - self.timestart # Overall time
                tdelta = xtime - self.prevtime  # Segment time
                self.prevprog = progress
                self.prevdone = xdone
                self.prevtime = xtime
                # Number of progress bar units for completion
                slen = wlen - xdone
                if done:
                    # Overall average bytes/sec
                    bps = self.offset / otime
                else:
                    # Segment average bytes/sec
                    bps = (self.offset - self.prevoff) / tdelta
                self.prevoff = self.offset
                # Progress bar has both foreground and background colors
                # as green and in case the terminal does not support colors
                # then a "=" is displayed instead instead of a green block
                pbar = " [\033[32m\033[42m%s\033[m%s] " % ("="*xdone, " "*slen)
                # Add progress percentage and how many bytes have been
                # processed so far relative to the total number of bytes
                pbar += "%5.1f%% %9s/%-9s" % (progress, str_units(self.offset), str_units(self.filesize))
                if columns < 100:
                    sys.stderr.write("%s %8s\r" % (pbar, str_time(otime)))
                else:
                    # Terminal is wide enough, include bytes/sec
                    sys.stderr.write("%s %9s/s %8s\r" % (pbar, str_units(bps), str_time(otime)))
                if done:
                    sys.stderr.write("\n")

    @staticmethod
    def escape(data):
        """Escape special characters.

           Examples:
               # Call as an instance
               escaped_data = x.escape(data)

               # Call as a class
               escaped_data = Pktt.escape(data)
        """
        isbytes = isinstance(data, bytes)
        # repr() can escape or not a single quote depending if a double
        # quote is present, just make sure both quotes are escaped correctly
        rdata = repr(data)
        if isbytes:
            # Strip the bytes marker
            rdata = rdata[1:]
        if rdata[0] == '"':
            # Double quotes are escaped
            dquote = r'x22'
            squote = r'\x27'
        else:
            # Single quotes are escaped
            dquote = r'\x22'
            squote = r'x27'
        # Replace all double quotes to its corresponding hex value
        rdata = rdata[1:-1].replace('"', dquote)
        # Replace all single quotes to its corresponding hex value
        rdata = rdata.replace("'", squote)
        return rdata

    @staticmethod
    def ip_tcp_src_expr(ipaddr, port=None):
        """Return a match expression to find a packet coming from ipaddr:port.

           Examples:
               # Call as an instance
               expr = x.ip_tcp_src_expr('192.168.1.50', 2049)

               # Call as a class
               expr = Pktt.ip_tcp_src_expr('192.168.1.50', 2049)

               # Returns "IP.src == '192.168.1.50' and TCP.src_port == 2049"
               # Expression ready for x.match()
               pkt = x.match(expr)
        """
        ret = "IP.src == '%s'" % ipaddr
        if port is not None:
            ret += " and TCP.src_port == %d" % port
        return ret

    @staticmethod
    def ip_tcp_dst_expr(ipaddr, port=None):
        """Return a match expression to find a packet going to ipaddr:port.

           Examples:
               # Call as an instance
               expr = x.ip_tcp_dst_expr('192.168.1.50', 2049)

               # Call as a class
               expr = Pktt.ip_tcp_dst_expr('192.168.1.50', 2049)

               # Returns "IP.dst == '192.168.1.50' and TCP.dst_port == 2049"
               # Expression ready for x.match()
               pkt = x.match(expr)
        """
        ret = "IP.dst == '%s'" % ipaddr
        if port is not None:
            ret += " and TCP.dst_port == %d" % port
        return ret

if __name__ == '__main__':
    # Self test of module
    l_escape = [
        "hello",
        "\x00\\test",
        "single'quote",
        'double"quote',
        'back`quote',
        'single\'double"quote',
        'double"single\'quote',
        'single\'double"back`quote',
        'double"single\'back`quote',
    ]
    ntests = 2*len(l_escape)

    tcount = 0
    for quote in ["'", '"']:
        for data in l_escape:
            expr = "data == %s%s%s" % (quote, Pktt.escape(data), quote)
            if eval(expr):
                tcount += 1

    if tcount == ntests:
        print("All tests passed!")
        exit(0)
    else:
        print("%d tests failed" % (ntests-tcount))
        exit(1)
