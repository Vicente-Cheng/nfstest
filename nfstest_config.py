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
import os

NFSTEST_PACKAGE          = 'NFStest'
NFSTEST_VERSION          = '1.0.1'
NFSTEST_SUMMARY          = 'NFS Test Suite'
NFSTEST_AUTHOR           = 'Jorge Mora'
NFSTEST_AUTHOR_EMAIL     = 'mora@netapp.com'
NFSTEST_MAINTAINER       = NFSTEST_AUTHOR
NFSTEST_MAINTAINER_EMAIL = NFSTEST_AUTHOR_EMAIL
NFSTEST_COPYRIGHT        = "Copyright (C) 2012 NetApp, Inc."
NFSTEST_LICENSE          = 'GPLv2'
NFSTEST_URL    = 'http://wiki.linux-nfs.org/wiki/index.php/NFStest'
NFSTEST_DL_URL = 'http://www.linux-nfs.org/~mora/nfstest/releases/nfstest.tgz'
NFSTEST_DESCRIPTION = '''NFS Test Suite

Provides a set of tools for testing either the NFS client or the NFS server,
included tests focused mainly on testing the client. These tools include the
following:

Test utilities package (nfstest)
===============================
Provides a set of tools for testing either the NFS client or the NFS server,
most of the functionality is focused mainly on testing the client.
These tools include the following:

    - Process command line arguments
    - Provide functionality for PASS/FAIL
    - Provide test grouping functionality
    - Provide multiple client support
    - Logging mechanism
    - Debug info control
    - Mount/Unmount control
    - Create files/directories
    - Provide mechanism to start a packet trace
    - Provide mechanism to simulate a network partition
    - Support for pNFS testing

Packet trace package (packet)
============================
The Packet trace module takes a trace file created by tcpdump and unpacks
the contents of each packet. You can decode one packet at a time, or do a
search for specific packets. The main difference between this modules and
other tools used to decode trace files is that you can use this module to
completely automate your tests.

Packet layers supported:
    - Ethernet II (RFC 894)
    - IP layer (supports v4 only)
    - TCP layer
    - RPC layer
    - NFS v4.0
    - NFS v4.1 including pNFS file layouts
'''

NFSTEST_MAN_MAP = {}
def _get_manpages(src_list, mandir, section, mod=False):
    manpages = []
    for src in src_list:
        if src == 'README':
            manpage = os.path.join(mandir, 'nfstest.%d.gz' % section)
        elif mod:
            if '__init__' in src:
                continue
            manpage = os.path.splitext(src.replace('/', '.'))[0]
            manpage = os.path.join(mandir, manpage + '.%d.gz' % section)
        else:
            manpage = os.path.split(src)[1]
            manpage = os.path.join(mandir, manpage + '.%d.gz' % section)
        manpages.append(manpage)
        NFSTEST_MAN_MAP[src] = manpage
    return manpages

bin_dirs = [
    '/usr/bin',
    '/usr/sbin',
    '/bin',
    '/sbin',
]
def _find_exec(command):
    for bindir in bin_dirs:
        bincmd = os.path.join(bindir, command)
        if os.path.exists(bincmd):
            return bincmd
    return command

NFSTEST_TESTDIR = 'test'
NFSTEST_MANDIR  = 'man'
NFSTEST_USRMAN  = '/usr/share/man'
NFSTEST_SCRIPTS = [
    'test/nfstest_cache',
    'test/nfstest_delegation',
    'test/nfstest_dio',
    'test/nfstest_pnfs',
    'test/nfstest_posix',
]
NFSTEST_ALLMODS = [
    'baseobj.py',
    'nfstest/host.py',
    'nfstest/nfs_util.py',
    'nfstest/test_util.py',
    'packet/pkt.py',
    'packet/pktt.py',
    'packet/record.py',
    'packet/unpack.py',
    'packet/application/rpc.py',
    'packet/internet/ipv4.py',
    'packet/internet/ipv6.py',
    'packet/internet/ipv6addr.py',
    'packet/link/ethernet.py',
    'packet/link/macaddr.py',
    'packet/transport/tcp.py',
]

NFSTEST_MAN1  = _get_manpages(['README'], NFSTEST_MANDIR, 1)
NFSTEST_MAN1 += _get_manpages(NFSTEST_SCRIPTS, NFSTEST_MANDIR, 1)
NFSTEST_MAN1 += _get_manpages(NFSTEST_ALLMODS, NFSTEST_MANDIR, 1, mod=True)
NFSTEST_MODULES = ['baseobj', 'nfstest_config']
NFSTEST_PACKAGES = [
    'nfstest',
    'packet',
    'packet.application',
    'packet.internet',
    'packet.link',
    'packet.nfs',
    'packet.transport',
]

# Default values
NFSTEST_NFSVERSION   = 4
NFSTEST_MINORVERSION = 1
NFSTEST_NFSPORT      = 2049
NFSTEST_EXPORT       = '/'
NFSTEST_MTPOINT      = '/mnt/t'
NFSTEST_MTOPTS       = 'hard,intr,rsize=4096,wsize=4096'
NFSTEST_INTERFACE    = 'eth0'
NFSTEST_SUDO         = _find_exec('sudo')
NFSTEST_IPTABLES     = _find_exec('iptables')
NFSTEST_TCPDUMP      = _find_exec('tcpdump')
NFSTEST_MESSAGESLOG  = '/var/log/messages'
NFSTEST_TMPDIR       = '/tmp'
