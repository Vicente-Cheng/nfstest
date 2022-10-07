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
Test utilities module

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

In order to use some of the functionality available, the user id in all the
client hosts must have access to run commands as root using the 'sudo' command
without the need for a password, this includes the host where the test is being
executed. This is used to run commands like 'mount' and 'umount'. Furthermore,
the user id must be able to ssh to remote hosts without the need for a password
if test requires the use of multiple clients.

Network partition is simulated by the use of 'iptables', please be advised
that after every test run the iptables is flushed and reset so any rules
previously setup will be lost. Currently, there is no mechanism to restore
the iptables rules to their original state.
"""
import os
import re
import sys
import time
import errno
import fcntl
import ctypes
import struct
import inspect
import textwrap
import traceback
from formatstr import *
import nfstest_config as c
from baseobj import BaseObj
from nfstest.utils import *
from nfstest.rexec import Rexec
from nfstest.nfs_util import NFSUtil
import packet.nfs.nfs3_const as nfs3_const
import packet.nfs.nfs4_const as nfs4_const
from optparse import OptionParser,OptionGroup,IndentedHelpFormatter,SUPPRESS_HELP
import xml.dom.minidom
import datetime

# Module constants
__author__    = "Jorge Mora (%s)" % c.NFSTEST_AUTHOR_EMAIL
__copyright__ = "Copyright (C) 2012 NetApp, Inc."
__license__   = "GPL v2"
__version__   = "1.8"

# Constants
PASS = 0
HEAD = 1
INFO = 2
FAIL = -1
WARN = -2
BUG  = -3
IGNR = -4

VT_NORM = "\033[m"
VT_BOLD = "\033[1m"
VT_BLUE = "\033[34m"
VT_HL   = "\033[47m"

_isatty = os.isatty(1)

_test_map = {
    HEAD: "\n*** ",
    INFO: "    ",
    PASS: "    PASS: ",
    FAIL: "    FAIL: ",
    WARN: "    WARN: ",
    BUG:  "    BUG:  ",
    IGNR: "    IGNR: ",
}

# Provide colors on PASS, FAIL, WARN messages
_test_map_c = {
    HEAD: "\n*** ",
    INFO: "    ",
    PASS: "    \033[102mPASS\033[m: ",
    FAIL: "    \033[41m\033[37mFAIL\033[m: ",
    WARN: "    \033[33mWARN\033[m: ",
    BUG:  "    \033[33mBUG\033[m:  ",
    IGNR: "    \033[33mIGNR\033[m: ",
}

_tverbose_map = {'group': 0, 'normal': 1, 'verbose': 2, '0':0, '1':1, '2':2}
_rtverbose_map = dict(zip(_tverbose_map.values(),_tverbose_map))

# Mount options
MOUNT_OPTS = ["client", "server", "export", "nfsversion", "port", "proto", "sec"]
# Client option list of arguments separated by ":"
CLIENT_OPTS = MOUNT_OPTS + ["mtpoint"]
# Convert the following arguments to their correct types
MOUNT_TYPE_MAP = {"port":int}

BaseObj.debug_map(0x100, 'opts', "OPTS: ")

class TestUtil(NFSUtil):
    """TestUtil object

       TestUtil() -> New server object

       Usage:
           x = TestUtil()

           # Process command line options
           x.scan_options()

           # Start packet trace using tcpdump
           x.trace_start()

           # Mount volume
           x.mount()

           # Create file
           x.create_file()

           # Unmount volume
           x.umount()

           # Stop packet trace
           x.trace_stop()

           # Exit script
           x.exit()
    """
    def __init__(self, **kwargs):
        """Constructor

           Initialize object's private data.

           sid:
               Test script ID [default: '']
               This is used to have options targeted for a given ID without
               including these options in any other test script.
           usage:
               Usage string [default: '']
           testnames:
               List of test names [default: []]
               When this list is not empty, the --runtest option is enabled and
               test scripts should use the run_tests() method to run all the
               tests. Test script should have methods named as <testname>_test.
           testgroups:
                Dictionary of test groups where the key is the name of the test
                group and its value is a dictionary having the following keys:
                    tests:
                        A list of tests belonging to this test group
                    desc:
                        Description of the test group, this is displayed
                        in the help if the name of the test group is also
                        included in testnames
                    tincl:
                        Include a comma separated list of tests belonging to
                        this test group to the description [default: False]
                    wrap:
                        Reformat the description so it fits in lines no
                        more than the width given. The description is not
                        formatted for a value of zero [default: 72]

           Example:
               x = TestUtil(testnames=['basic', 'lock'])

               # The following methods should exist:
               x.basic_test()
               x.lock_test()
        """
        self.sid        = kwargs.pop('sid', "")
        self.usage      = kwargs.pop('usage', '')
        self.testnames  = kwargs.pop('testnames', [])
        self.testgroups = kwargs.pop('testgroups', {})
        self.progname = os.path.basename(sys.argv[0])
        self.testname = ""
        if self.progname[-3:] == '.py':
            # Remove extension
            self.progname = self.progname[:-3]
        self._name = None
        self.tverbose = 1
        self._bugmsgs = {}
        self.bugmsgs = None
        self.nocleanup = True
        self.isatty = _isatty
        self.test_time = [time.time()]
        self._disp_time = 0
        self._disp_msgs = 0
        self._empty_msg = 0
        self._fileopt = True
        self.fileidx = 1
        self.diridx = 1
        self.logidx = 1
        self.files = []
        self.dirs = []
        self.test_msgs = []
        self._msg_count = {}
        self._reset_files()
        self.runtest = None
        self._runtest = True
        self.runtest_list = []
        self.runtest_neg  = False
        self.client_list_opt = {}
        self.createtraces = False
        self._opts_done = False
        # List of sparse files
        self.sparse_files = []
        # Rexec attributes
        self.rexecobj = None
        self.rexecobj_list = []
        # List of remote files
        self.remote_files = []
        self.nfserr_list  = None
        self.nfs3err_list = [nfs3_const.NFS3ERR_NOENT]
        self.nfs4err_list = [nfs4_const.NFS4ERR_NOENT]
        self.nlm4err_list = []
        self.mnt3err_list = []
        self.xunit_report = False
        self.xunit_report_file = None
        self.xunit_report_doc = None
        self.test_results = []
        self._tcleanup_done = False
        self.keeptraces = False
        self.rmtraces = False
        self.tracefiles = []

        # Trace marker info
        self.trace_marker_name = "F__NFSTEST_MARKER__F__"
        self.trace_marker_list = []
        self.trace_marker_index = 0
        self.trace_marker_id = 0

        if len(self.testnames) > 0:
            # Add default testgroup: all
            self.testgroups["all"] = {
                "tests": [x for x in self.testnames if x not in self.testgroups],
                "desc": "Run all tests: ",
            }
            self.testnames.append("all")

        for tid in _test_map:
            self._msg_count[tid] = 0
        self.dindent(4)

        self.optfiles = []
        self.testopts = {}
        NFSUtil.__init__(self)
        self._init_options()

        # Get page size
        self.PAGESIZE = os.sysconf(os.sysconf_names['SC_PAGESIZE'])

        # Prototypes for libc functions
        self.libc.fallocate.argtypes = ctypes.c_int, ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong
        self.libc.fallocate.restype  = ctypes.c_int

    def __del__(self):
        """Destructor

           Gracefully stop the packet trace, cleanup files, unmount volume,
           and reset network.
        """
        self.cleanup()

    def _close(self, count):
        if self.dprint_count() > count:
            self._empty_msg = 0

        if len(self.test_msgs) > 0:
            if getattr(self, 'logfile', None):
                if not self._empty_msg:
                    print("")
                print("Logfile: %s" % self.logfile)
                self._empty_msg = 0
            ntests, tmsg = self._total_counts(self._msg_count)
            if ntests > 0:
                self._print_msg("", single=1)
                msg = "%d tests%s" % (ntests, tmsg)
                self.write_log(msg)
                if self._msg_count[FAIL] > 0:
                    msg = "\033[31m" + msg + "\033[m" if self.isatty else msg
                elif self._msg_count[WARN] > 0:
                    msg = "\033[33m" + msg + "\033[m" if self.isatty else msg
                else:
                    msg = "\033[32m" + msg + "\033[m" if self.isatty else msg
                print(msg)
        if self._opts_done:
            self.total_time = time.time() - self.test_time[0]
            total_str = "\nTotal time: %s" % self._print_time(self.total_time)
            self.write_log(total_str)
            print(total_str)
        self.close_log()

    def _verify_testnames(self):
        """Process --runtest option."""
        if self.runtest is None:
            return
        elif self.runtest == 'all':
            self.testlist = self.testnames
        else:
            if self.runtest[0] == '^':
                # List is negated tests -- do not run the tests listed
                self.runtest_neg = True
                runtest = self.runtest.replace('^', '', 1)
                negtestlist = self.str_list(runtest)
                self.testlist = list(self.testnames)
                for testname in negtestlist:
                    if testname in self.testlist:
                        self.testlist.remove(testname)
                    elif testname in self.testgroups:
                        # Remove all tests in the test group
                        for tname in self.testgroups[testname].get("tests", []):
                            if tname in self.testlist:
                                self.testlist.remove(tname)
                    elif testname not in self.testnames:
                        self.opts.error("invalid value given --runtest=%s" % self.runtest)
            else:
                idx = 0
                self.runtest_neg = False
                self.testlist = self.str_list(self.runtest)
                self.runtest_list = list(self.testlist)
                # Process the test groups by including all the tests
                # in the test group to the list of tests to run
                for testname in self.testlist:
                    tgroup = self.testgroups.get(testname)
                    if tgroup is not None:
                        # Add tests from the test group to the list
                        self.testlist.remove(testname)
                        for tname in tgroup.get("tests", []):
                            self.testlist.insert(idx, tname)
                            idx += 1
                    idx += 1
            if self.testlist is None:
                self.opts.error("invalid value given --runtest=%s" % self.runtest)
        msg = ''
        for testname in self.testlist:
            if testname not in self.testnames:
                msg += "Invalid test name:    %s\n" % testname
            elif not hasattr(self, testname + '_test'):
                msg += "Test not implemented: %s\n" % testname
            else:
                tname = testname + '_test'
        if len(msg) > 0:
            self.config(msg)

    def _init_options(self):
        """Initialize command line options parsing and definitions."""
        self.opts = OptionParser("%prog [options]", formatter = IndentedHelpFormatter(2, 10), version = "%prog " + __version__)
        hmsg = "File where options are specified besides the system wide " + \
               "file /etc/nfstest, user wide file $HOME/.nfstest or in " + \
               "the current directory .nfstest file"
        self.opts.add_option("-f", "--file", default="", help=hmsg)

        # Hidden options
        self.opts.add_option("--list--tests", action="store_true", default=False, help=SUPPRESS_HELP)
        self.opts.add_option("--list--options", action="store_true", default=False, help=SUPPRESS_HELP)

        self.nfs_opgroup = OptionGroup(self.opts, "NFS specific options")
        hmsg = "Server name or IP address"
        self.nfs_opgroup.add_option("-s", "--server", default=self.server, help=hmsg)
        hmsg = "Exported file system to mount [default: '%default']"
        self.nfs_opgroup.add_option("-e", "--export", default=self.export, help=hmsg)
        hmsg = "NFS version, e.g., 3, 4, 4.1, etc. [default: %default]"
        self.nfs_opgroup.add_option("--nfsversion", default=self.nfsversion, help=hmsg)
        hmsg = "Mount point [default: '%default']"
        self.nfs_opgroup.add_option("-m", "--mtpoint", default=self.mtpoint, help=hmsg)
        hmsg = "NFS server port [default: %default]"
        self.nfs_opgroup.add_option("-p", "--port", type="int", default=self.port, help=hmsg)
        hmsg = "NFS protocol name [default: '%default']"
        self.nfs_opgroup.add_option("--proto", default=self.proto, help=hmsg)
        hmsg = "Security flavor [default: '%default']"
        self.nfs_opgroup.add_option("--sec", default=self.sec, help=hmsg)
        hmsg = "Multiple TCP connections option [default: '%default']"
        self.nfs_opgroup.add_option("--nconnect", type="int", default=self.nconnect, help=hmsg)
        hmsg = "Mount options [default: '%default']"
        self.nfs_opgroup.add_option("-o", "--mtopts", default=self.mtopts, help=hmsg)
        hmsg = "Data directory where files are created, directory is " + \
               "created on the mount point [default: '%default']"
        self.nfs_opgroup.add_option("--datadir", default=self.datadir, help=hmsg)
        self.opts.add_option_group(self.nfs_opgroup)

        self.log_opgroup = OptionGroup(self.opts, "Logging options")
        hmsg = "Verbose level for debug messages [default: '%default']"
        self.log_opgroup.add_option("-v", "--verbose", default="none", help=hmsg)
        hmsg = "Verbose level for test messages [default: '%default']"
        self.log_opgroup.add_option("--tverbose", default=_rtverbose_map[self.tverbose], help=hmsg)
        hmsg = "Create log file"
        self.log_opgroup.add_option("--createlog", action="store_true", default=False, help=hmsg)
        hmsg = "Create rexec log files"
        self.log_opgroup.add_option("--rexeclog", action="store_true", default=False, help=hmsg)
        hmsg = "Display warnings"
        self.log_opgroup.add_option("--warnings", action="store_true", default=False, help=hmsg)
        hmsg = "Informational tag, it is displayed as an INFO message [default: '%default']"
        self.log_opgroup.add_option("--tag", default="", help=hmsg)
        hmsg = "Do not use terminal colors on output"
        self.log_opgroup.add_option("--notty", action="store_true", default=False, help=hmsg)
        hmsg = "Use terminal colors on output -- useful when running with nohup"
        self.log_opgroup.add_option("--isatty", action="store_true", default=self.isatty, help=hmsg)
        self.opts.add_option_group(self.log_opgroup)

        self.cap_opgroup = OptionGroup(self.opts, "Packet trace options")
        hmsg = "Create a packet trace for each test"
        self.cap_opgroup.add_option("--createtraces", action="store_true", default=False, help=hmsg)
        hmsg = "Capture buffer size for tcpdump [default: %default]"
        self.cap_opgroup.add_option("--tbsize", default="192k", help=hmsg)
        hmsg = "Seconds to delay before stopping packet trace [default: %default]"
        self.cap_opgroup.add_option("--trcdelay", type="float", default=2.0, help=hmsg)
        hmsg = "Do not remove any trace files [default: remove trace files if no errors]"
        self.cap_opgroup.add_option("--keeptraces", action="store_true", default=False, help=hmsg)
        hmsg = "Remove trace files [default: remove trace files if no errors]"
        self.cap_opgroup.add_option("--rmtraces", action="store_true", default=False, help=hmsg)
        hmsg = "Device interface [default: automatically selected]"
        self.cap_opgroup.add_option("-i", "--interface", default=None, help=hmsg)
        self.opts.add_option_group(self.cap_opgroup)

        self.file_opgroup = OptionGroup(self.opts, "File options")
        hmsg = "Number of files to create [default: %default]"
        self.file_opgroup.add_option("--nfiles", type="int", default=2, help=hmsg)
        hmsg = "File size to use for test files [default: %default]"
        self.file_opgroup.add_option("--filesize", default="64k", help=hmsg)
        hmsg = "Read size to use when reading files [default: %default]"
        self.file_opgroup.add_option("--rsize", default="4k", help=hmsg)
        hmsg = "Write size to use when writing files [default: %default]"
        self.file_opgroup.add_option("--wsize", default="4k", help=hmsg)
        hmsg = "Seconds to delay I/O operations [default: %default]"
        self.file_opgroup.add_option("--iodelay", type="float", default=0.1, help=hmsg)
        hmsg = "Read/Write offset delta [default: %default]"
        self.file_opgroup.add_option("--offset-delta", default="4k", help=hmsg)
        self.opts.add_option_group(self.file_opgroup)

        self.path_opgroup = OptionGroup(self.opts, "Path options")
        hmsg = "Full path of binary for sudo [default: '%default']"
        self.path_opgroup.add_option("--sudo", default=self.sudo, help=hmsg)
        hmsg = "Full path of binary for kill [default: '%default']"
        self.path_opgroup.add_option("--kill", default=self.kill, help=hmsg)
        hmsg = "Full path of binary for nfsstat [default: '%default']"
        self.path_opgroup.add_option("--nfsstat", default=self.nfsstat, help=hmsg)
        hmsg = "Full path of binary for tcpdump [default: '%default']"
        self.path_opgroup.add_option("--tcpdump", default=self.tcpdump, help=hmsg)
        hmsg = "Full path of binary for iptables [default: '%default']"
        self.path_opgroup.add_option("--iptables", default=self.iptables, help=hmsg)
        hmsg = "Full path of log messages file [default: '%default']"
        self.path_opgroup.add_option("--messages", default=self.messages, help=hmsg)
        hmsg = "Full path of tracing events directory [default: '%default']"
        self.path_opgroup.add_option("--trcevents", default=self.trcevents, help=hmsg)
        hmsg = "Full path of trace pipe file [default: '%default']"
        self.path_opgroup.add_option("--trcpipe", default=self.trcpipe, help=hmsg)
        hmsg = "Temporary directory [default: '%default']"
        self.path_opgroup.add_option("--tmpdir", default=self.tmpdir, help=hmsg)
        self.opts.add_option_group(self.path_opgroup)

        self.dbg_opgroup = OptionGroup(self.opts, "Debug options")
        hmsg = "Do not cleanup created files"
        self.dbg_opgroup.add_option("--nocleanup", action="store_true", default=False, help=hmsg)
        hmsg = "Do not display timestamps in debug messages"
        self.dbg_opgroup.add_option("--notimestamps", action="store_true", default=False, help=hmsg)
        hmsg = "File containing test messages to mark as bugs if they failed"
        self.dbg_opgroup.add_option("--bugmsgs", default=self.bugmsgs, help=hmsg)
        hmsg = "Do not mount server and run the tests on local disk space"
        self.dbg_opgroup.add_option("--nomount", action="store_true", default=self.nomount, help=hmsg)
        hmsg = "Base name for all files and logs [default: automatically generated]"
        self.dbg_opgroup.add_option("--basename", default='', help=hmsg)
        hmsg = "Set NFS kernel debug flags and save log messages [default: '%default']"
        self.dbg_opgroup.add_option("--nfsdebug", default=self.nfsdebug, help=hmsg)
        hmsg = "Set RPC kernel debug flags and save log messages [default: '%default']"
        self.dbg_opgroup.add_option("--rpcdebug", default=self.rpcdebug, help=hmsg)
        hmsg = "List of trace points modules to enable [default: '%default']"
        self.dbg_opgroup.add_option("--tracepoints", default=self.tracepoints, help=hmsg)
        hmsg = "Get NFS stats [default: '%default']"
        self.dbg_opgroup.add_option("--nfsstats", action="store_true", default=False, help=hmsg)
        hmsg = "Display main packets related to the given test"
        self.dbg_opgroup.add_option("--pktdisp", action="store_true", default=False, help=hmsg)
        hmsg = "Fail every NFS error found in the packet trace"
        self.dbg_opgroup.add_option("--nfserrors", action="store_true", default=False, help=hmsg)
        hmsg = "IP address of localhost"
        self.dbg_opgroup.add_option("--client-ipaddr", default=None, help=hmsg)
        self.opts.add_option_group(self.dbg_opgroup)

        self.report_opgroup = OptionGroup(self.opts, "Reporting options")
        hmsg = "Generate xUnit compatible test report"
        self.report_opgroup.add_option("--xunit-report", action="store_true", default=False, help=hmsg)
        hmsg = "Path to xout report file"
        self.report_opgroup.add_option("--xunit-report-file", default=None, help=hmsg)
        self.opts.add_option_group(self.report_opgroup)

        usage = self.usage
        if len(self.testnames) > 0:
            self.test_opgroup = OptionGroup(self.opts, "Test options")
            hmsg = "Comma separated list of tests to run, if list starts " + \
                   "with a '^' then all tests are run except the ones " + \
                   "listed [default: 'all']"
            self.test_opgroup.add_option("--runtest", default=None, help=hmsg)
            self.opts.add_option_group(self.test_opgroup)
            if len(usage) == 0:
                usage = "%prog [options]"
            usage += "\n\nAvailable tests:"
            for tgname, item in self.testgroups.items():
                tlist = item.get("tests", [])
                tincl = item.get("tincl", True)
                wrap = item.get("wrap", 72)
                if item.get("desc", None) is not None:
                    if tincl and tlist:
                        # Add the list of tests for this test group
                        # to the description
                        item["desc"] += ", ".join(tlist)
                    if wrap > 0:
                        item["desc"] = "\n".join(textwrap.wrap(item["desc"], wrap))
            for tname in self.testnames:
                tgroup = self.testgroups.get(tname)
                desc = None
                if tgroup is not None:
                    desc = tgroup.get("desc")
                if desc is None:
                    desc = self.test_description(tname)
                if desc is not None:
                    lines = desc.lstrip().split('\n')
                    desc = lines.pop(0)
                    if len(desc) > 0:
                        desc += '\n'
                    desc += textwrap.dedent("\n".join(lines))
                    desc = desc.replace("\n", "\n        ").rstrip()
                usage += "\n    %s:\n        %s\n" % (tname, desc)
            usage = usage.rstrip()
            # Remove test group names from the list of tests
            for tname in self.testgroups:
                self.testnames.remove(tname)
        if len(usage) > 0:
            self.opts.set_usage(usage)
        self._cmd_line = " ".join(sys.argv)

    @staticmethod
    def str_list(value, vtype=str, sep=","):
        """Return a list of <vtype> elements from the comma separated string."""
        slist = []
        try:
            for item in value.replace(' ', '').split(sep):
                if len(item) > 0:
                    slist.append(vtype(item))
                else:
                    slist.append(None)
        except:
            return
        return slist

    @staticmethod
    def get_list(value, nmap, sep=","):
        """Given the value as a string of 'comma' separated elements, return
           a list where each element is mapped using the dictionary 'nmap'.
               nmap = {"one":1, "two":2}
               out = x.get_list("one", nmap)        # out = [1]
               out = x.get_list("one,two", nmap)    # out = [1,2]
               out = x.get_list("two,one", nmap)    # out = [2,1]
               out = x.get_list("one,three", nmap)  # out = None
        """
        try:
            return [nmap[x] for x in TestUtil.str_list(value, sep=sep)]
        except:
            return

    def test_description(self, tname=None):
        """Return the test description for the current test"""
        if tname is None:
            tname = self.testname
        return getattr(self, tname+'_test').__doc__

    def need_run_test(self, testname):
        """Return True only if user explicitly requested to run this test"""
        if self.runtest_neg:
            # User specified negative testing
            return False
        return testname in self.runtest_list

    def remove_test(self, testname):
        """Remove all instances of test from the list of tests to run"""
        while testname in self.testlist:
            self.testlist.remove(testname)

    def process_option(self, value, arglist=[], typemap={}):
        """Process option with a list of items separated by "," and each
           item in the list could have different arguments separated by ":".

           value:
               String of comma separated elements
           arglist:
               Positional order of arguments, if this list is empty,
               then use named arguments only [default: []]
           typemap:
               Dictionary to convert arguments to their given types,
               where the key is the argument name and its value is the
               type function to use to convert the argument [default: {}]
        """
        option_list = []
        # Process each item definition separated by a comma ","
        for opt_item in self.str_list(value):
            if opt_item is None:
                # Redefine empty item definitions like ",,"
                opt_item = ""
            # Get arguments for this item definition
            clargs = self.str_list(opt_item, sep=":")
            # Item info dictionary for this definition
            cldict = {}
            index = 0
            while len(clargs) > 0:
                # Try it as a positional argument first
                val = clargs.pop(0)
                # Process each argument for this item definition
                if val is not None:
                    if index < len(arglist):
                        # Get argument name from ordered list
                        arg = arglist[index]
                    elif len(arglist):
                        # More arguments given than positional arguments,
                        # ignore the rest of the arguments
                        break
                    else:
                        # No ordered list was given
                        arg = None
                    # Name arguments are specified as "name=value"
                    dlist = val.split("=")
                    if len(dlist) == 2:
                        # This is specified as a named argument
                        arg, val = dlist
                    if arg is not None:
                        # Convert value if necessary
                        typefunc = typemap.get(arg)
                        if typefunc is not None:
                            val = typefunc(val)
                        # Add argument to the description
                        cldict[arg] = val
                index += 1
            # Add item description to list
            option_list.append(cldict)
        return option_list

    def compare_mount_args(self, mtopts1, mtopts2):
        """Compare mount arguments"""
        for item in MOUNT_OPTS:
            # Mount argument default value
            value = getattr(self, item, None)
            if mtopts1.get(item, value) != mtopts2.get(item, value):
                return False
        return True

    def process_client_option(self, option="client", remote=True, count=1):
        """Process the client option

           Clients are separated by a "," and each client definition can have
           the following options separated by ":":
               client:server:export:nfsversion:port:proto:sec:mtpoint

           option:
               Option name [default: "client"]
           remote:
               Expect a client hostname or IP address in the definition.
               If this is set to None do not verify client name or IP.
               [default: True]
           count:
               Number of client definitions to expect. If remote is True,
               return the number of definitions listed in the given option
               up to this number. If remote is False, return exactly this
               number of definitions [default: 1]

           Examples:
               # Using positional arguments with nfsversion=4.1 for client1
               client=client1:::4.1,client2

               # Using named arguments instead
               client=client1:nfsversion=4.1,client2
        """
        if count < 1:
            # No clients/processes are required
            return []

        option_val = getattr(self, option, None)
        if option_val is None:
            if remote:
                # Must have a client definition
                return []
            else:
                # Process definition is optional so include at least one
                option_val = ""

        # Process the client option to get a list of client items
        client_list = self.process_option(option_val, CLIENT_OPTS, MOUNT_TYPE_MAP)[:count]
        count -= len(client_list)

        if remote is not None:
            # Verify if client name is required
            for client_item in client_list:
                if remote and client_item.get("client", "") == "":
                    # Client definition should have a client
                    self.config("Info list should have a client name or IP address: %s = %s" % (option, option_val))
                elif not remote and client_item.get("client", "") != "":
                    # Process definition should not have a client
                    self.config("Info list should not have a client name or IP address: %s = %s" % (option, option_val))
        elif len(client_list) and client_list[0].get("client", "") in ("", "localhost", "127.0.0.1", self.client_ipaddr):
            remote = False
        else:
            remote = True

        if remote:
            if len(client_list) > 0 and client_list[0].get("mtpoint") is None:
                # Set mtpoint for the first client definition if it is not given
                # This is needed later to compare mount definitions against each
                # other to know which ones need to be mounted
                client_list[0]["mtpoint"] = self.mtpoint
                client_list[0]["mount"] = 1
        else:
            # Add process definitions to get the required number
            for idx in range(count):
                client_list.append({})
            # Include current object's mount info
            # for comparison purposes only
            cldict = {"mount":1}
            for arg in CLIENT_OPTS[1:]:
                val = getattr(self, arg)
                typefunc = MOUNT_TYPE_MAP.get(arg)
                if typefunc is not None:
                    val = typefunc(val)
                cldict[arg] = val
            client_list.insert(0, cldict)

        # Verify that there are no conflicting mounts and which
        # definitions need to be mounted
        index = 1
        for client_item in client_list[1:]:
            mount = 0
            mtpoint = client_item.get("mtpoint")
            if mtpoint is None:
                # The mount point is not given, select the correct one to use
                # by comparing against previous definitions
                for item in client_list[0:index]:
                    if self.compare_mount_args(client_item, item):
                        # This is the same mount definition so use the same
                        # mount point -- it should not be mounted again
                        client_item["mtpoint"] = item.get("mtpoint")
                        break
                if client_item.get("mtpoint") is None:
                    # This is a different mount definition so choose a
                    # new mount point -- it should be mounted
                    client_item["mtpoint"] = self.mtpoint + "_%02d" % index
                    mount = 1
            else:
                # Should be mounted if mount definition has mtpoint defined
                mount = 1
                # Check if mount does not conflict with previous definitions
                for item in client_list[0:index]:
                    if mtpoint == item.get("mtpoint"):
                        if self.compare_mount_args(client_item, item):
                            # Mount definitions are the same so just do not
                            # mount it
                            mount = 0
                            break
                        else:
                            # Mount definitions are different for the same
                            # mount point
                            self.config("conflicting mtpoint in --%s = %s" % (option, option_val))
            client_item["mount"] = mount
            index += 1

        if not remote:
            # Remove the first client definition from the process list since
            # it was just added to compare the mount definitions
            client_list.pop(0)
        # Save client list for given option
        self.client_list_opt[option] = client_list
        return client_list

    def verify_client_option(self, tclient_dict, option="client"):
        """Verify the client option is required from the list of tests to run.
           Also, check if enough clients were specified to run the tests.

           tclient_dict:
               Dictionary having the number of clients required by each test
           option:
               Option name [default: "client"]
        """
        tests_removed = 0
        client_list = self.client_list_opt.get(option, [])
        # Use a copy of the list since some elements might be removed
        for tname in list(self.testlist):
            ncount = tclient_dict.get(tname, 0)
            # Verify there are enough clients specified to run the tests
            if ncount > len(client_list):
                if self.need_run_test(tname):
                    # Test requires more clients then specified is explicitly
                    # given but there is not enough clients to run it
                    if len(client_list):
                        self.config("Not enough clients specified in --%s for '%s' to run" % (option, tname))
                    elif self.runtest is not None:
                        self.config("Specify option --%s for --runtest='%s'" % (option, self.runtest))
                else:
                    # Test was not explicitly given so do not run it
                    self.remove_test(tname)
                    tests_removed += 1

        if tests_removed > 0 and len(self.testlist) == 0 and self.runtest is not None:
            # Only tests which require a client were specified but
            # no client specification was given
            self.config("Specify option --%s for --runtest='%s'" % (option, self.runtest))

    def scan_options(self):
        """Process command line options.

           Process all the options in the file given by '--file', then the
           ones in the command line. This allows for command line options
           to over write options given in the file.

           Format of options file:
               # For options expecting a value
               <option_name> = <value>

               # For boolean (flag) options
               <option_name>

           Process options files and make sure not to process the same file
           twice, this is used for the case where HOMECFG and CWDCFG are the
           same, more specifically when environment variable HOME is not
           defined. Also, the precedence order is defined as follows:
             1. options given in command line
             2. options given in file specified by the -f|--file option
             3. options given in file specified by ./.nfstest
             4. options given in file specified by $HOME/.nfstest
             5. options given in file specified by /etc/nfstest

           NOTE:
             Must use the long name of the option (--<option_name>) in the file.
        """
        opts, args = self.opts.parse_args()
        if self._fileopt:
            # Find which options files exist and make sure not to process the
            # same file twice, this is used for the case where HOMECFG and
            # CWDCFG are the same, more specifically when environment variable
            # HOME is not defined.
            ofiles = {}
            self.optfiles = [[opts.file, []]] if opts.file else []
            for optfile in [c.NFSTEST_CWDCFG, c.NFSTEST_HOMECFG, c.NFSTEST_CONFIG]:
                if ofiles.get(optfile) is None:
                    # Add file if it has not been added yet
                    ofiles[optfile] = 1
                    if os.path.exists(optfile):
                        self.optfiles.insert(0, [optfile, []])
        if self.optfiles and self._fileopt:
            # Options are given in any of the options files
            self._fileopt = False # Only process the '--file' option once
            argv = []
            for (optfile, lines) in self.optfiles:
                bcount = 0
                islist = False
                idblock = None
                testblock = None
                for optline in open(optfile, 'r'):
                    line = optline.strip()
                    if len(line) == 0 or line[0] == '#':
                        # Skip comments
                        continue
                    # Save current line of file for displaying purposes
                    lines.append(optline.rstrip())
                    # Process valid options, option name and value is separated
                    # by spaces or an equal sign
                    m = re.search("([^=\s]+)\s*=?\s*(.*)", line)
                    name = m.group(1)
                    name = name.strip()
                    value = m.group(2)
                    # Add current option to argument list as if the option was
                    # given on the command line to be able to use parse_args()
                    # again to process all options given in the options files
                    if name in ["}", "]"]:
                        # End of block, make sure to close an opened testblock
                        # first before closing an opened idblock
                        bcount -= 1
                        if testblock is not None:
                            testblock = None
                        else:
                            idblock = None
                    elif len(value) > 0:
                        value = value.strip()
                        if value in ["{", "["]:
                            # Start of block, make sure to open an idblock
                            # first before opening a testblock
                            islist = True if value == "[" else False
                            bcount += 1
                            if idblock is None:
                                idblock = name
                            elif idblock == self.sid:
                                # Open a testblock only if testblock is located
                                # inside an idblock corresponding to script ID
                                testblock = name
                                if self.testopts.get(name) is None:
                                    # Initialize testblock only if it has not
                                    # been initialized, this allows for multiple
                                    # definitions of the same testblock
                                    if islist:
                                        self.testopts[name] = []
                                    else:
                                        self.testopts[name] = {}
                        elif testblock is not None:
                            # Inside a testblock, add name/value to testblock
                            # dictionary
                            if islist:
                                self.testopts[testblock].append(line)
                            else:
                                self.testopts[testblock][name] = value
                        elif idblock is None or idblock == self.sid:
                            # Include all general options and options given
                            # by the block specified by the correct script ID
                            argv.append("--%s=%s" % (name, value))
                    elif testblock is not None:
                        # Inside a testblock, add name to testblock dictionary
                        if islist:
                            self.testopts[testblock].append(name)
                        else:
                            self.testopts[testblock][name] = True
                    elif idblock is None or (idblock == self.sid and testblock is None):
                        # Include all general options and options given
                        # by the block specified by the correct script ID
                        argv.append("--%s" % name)
                if bcount != 0:
                    self.config("Missing closing brace in options file '%s'" % optfile)
            # Add all other options in the command line, make sure all options
            # explicitly given in the command line have higher precedence than
            # options given in any of the options files
            sys.argv[1:] = argv + sys.argv[1:]
            # Process the command line arguments again to overwrite options
            # explicitly given in the command line in conjunction with the
            # --file option
            self.scan_options()
        else:
            if opts.list__tests:
                print("\n".join(self.testnames + list(self.testgroups.keys())))
                sys.exit(0)
            if opts.list__options:
                hidden_opts = ("--list--tests", "--list--options")
                long_opts = [x for x in self.opts._long_opt.keys() if x not in hidden_opts]
                print("\n".join(list(self.opts._short_opt.keys()) + long_opts))
                sys.exit(0)

            if opts.notimestamps:
                # Disable timestamps in debug messages
                self.tstamp(enable=False)

            del opts.list__tests
            del opts.list__options

            if opts.notty:
                # Do not use terminal colors
                opts.isatty = False
                self.isatty = False

            try:
                # Set verbose level mask
                self.debug_level(opts.verbose)
            except Exception as e:
                self.opts.error("Invalid verbose level <%s>: %s" % (opts.verbose, e))

            if opts.createlog and len(opts.basename) == 0:
                self.logfile = "%s/%s.log" % (opts.tmpdir, self.get_name())
                self.open_log(self.logfile)

            if len(args) > 0:
                # Extra arguments in the command line create a new --runtest
                # list of tests overwriting any previous definition
                opts.runtest = ",".join([x.strip(",") for x in args])
            elif opts.runtest is None:
                # Default is to run all tests
                opts.runtest = "all"

            _lines = [self._cmd_line]
            for (optfile, lines) in self.optfiles:
                # Add the content of each option file that has been processed
                if len(lines) > 0:
                    _lines.append("")
                    _lines.append("Contents of options file [%s]:" % optfile)
                    _lines += lines
            self.dprint('OPTS', "\n".join(_lines))
            self.dprint('OPTS', "")
            for key in sorted(vars(opts)):
                optname = "--" + key
                if not self.opts.has_option(optname):
                    optname = optname.replace("_", "-")
                    if not self.opts.has_option(optname):
                        continue
                value = getattr(opts,key)
                self.dprint('OPTS', "%s = %s" % (optname[2:], value))
            self.dprint('OPTS', "")

            if len(opts.tag) > 0:
                # Display tag information
                self.dprint('INFO', "TAG: %s" % opts.tag)

            # Display system information
            self.dprint('INFO', "SYSTEM: %s" % " ".join(os.uname()))

            # Process all command line arguments -- all will be part of the
            # objects namespace
            self.__dict__.update(opts.__dict__)
            if not self.server:
                self.opts.error("server option is required")

            self._verify_testnames()
            ipv6 = self.proto[-1] == '6'
            # Get IP address of server
            self.server_ipaddr = self.get_ip_address(host=self.server, ipv6=ipv6)
            # Get IP address of client
            if self.client_ipaddr is None:
                self.client_ipaddr = self.get_ip_address(ipv6=ipv6)
                if self.interface is None:
                    out = self.get_route(self.server_ipaddr)
                    if out[1] is not None:
                        self.interface = out[1]
                        if out[2] is not None:
                            self.client_ipaddr = out[2]
                    else:
                        self.interface = c.NFSTEST_INTERFACE
            self.ipaddr = self.client_ipaddr

            self.tverbose = _tverbose_map.get(self.tverbose)
            if self.tverbose is None:
                self.opts.error("invalid value for tverbose option")

            # Convert units
            self.filesize     = int_units(self.filesize)
            self.rsize        = int_units(self.rsize)
            self.wsize        = int_units(self.wsize)
            self.offset_delta = int_units(self.offset_delta)
            self.tbsize       = int_units(self.tbsize)

            # Set NFS version -- the actual value will be set after the mount
            self.nfs_version = float(self.nfsversion)

            # Option basename is use for debugging purposes only, specifically
            # when debugging the assertions of a test script without actually
            # running the test itself. When this option is given the client
            # does not mount the NFS server so the test is run in a local file
            # system (it must have rw permissions) and it takes the packet
            # traces previously created by a different run to check the results.
            # If packet traces come from a different client and server the
            # following options can be used to reflect the values used when
            # the packet traces were created:
            #   server = <server-ip-addr-to-use>
            #   export = </export/path/to/use>
            #   datadir = <data/dir/to/use>
            #   client-ipaddr = <client-ip-addr-to-use>
            if len(self.basename) > 0:
                self._name      = self.basename
                self.nomount    = True
                self.notrace    = True
                self.keeptraces = True

            if self.bugmsgs is not None:
                try:
                    for line in open(self.bugmsgs, 'r'):
                        line = line.strip()
                        if len(line):
                            binfo = ""
                            # Format:
                            # [bug message]: assertion message
                            regex = re.search(r"^(\[([^\]]*)\]:\s*)?(.*)", line)
                            if regex:
                                ftmp, binfo, line = regex.groups()
                                binfo = "" if binfo is None else binfo.strip()
                            self._bugmsgs[line] = binfo
                except Exception as e:
                    self.config("Unable to load bug messages from file '%s': %r" % (self.bugmsgs, e))

            # Set base name for trace files and log message files
            self.tracename = self.get_name()
            self.dbgname = self.get_name()
            self.trcpname = self.get_name()
            self.nfsstatname = self.get_name()

            if self.xunit_report:
                self.xunit_report_doc = xml.dom.minidom.Document()
                if self.xunit_report_file is None:
                    self.xunit_report_file = "%s.xml" % os.path.join(self.tmpdir, self.get_name())

            self._opts_done = True

    def test_options(self, name=None):
        """Get options for the given test name. If the test name is not given
           it is determined by inspecting the stack to find which method is
           calling this method.
        """
        if name is None:
            # Get current testname
            name = self.testname
            if len(name) == 0:
                # Get correct test name by inspecting the stack to find which
                # method is calling this method
                out = inspect.stack()
                name = out[1][3].replace("_test", "")

        # Get options given for this specific test name
        opts = self.testopts.get(name, {})

        # Find if any of the test options are regular expressions
        for key in self.testopts.keys():
            m = re.search("^re\((.*)\)$", key)
            if m:
                # Regular expression specified by re()
                regex = m.group(1)
            else:
                # Find if regular expression is specified by the characters
                # used in the name
                m = re.search("[.^$?+\\\[\]()|]", key)
                regex = key
            if m and re.search(regex, name):
                # Key is specified as a regular expression and matches
                # the test name given, add these options to any options
                # already given by static name match making sure the
                # options given by the exact name are not overwritten
                # by the ones found from a regular expression
                opts = dict(list(self.testopts[key].items()) + list(opts.items()))
        return opts

    def get_logname(self, remote=False):
        """Get next log file name."""
        tmpdir = c.NFSTEST_TMPDIR if remote else self.tmpdir
        logfile = "%s/%s_%02d.log" % (tmpdir, self.get_name(), self.logidx)
        self.logidx += 1
        return logfile

    def setup(self, nfiles=None):
        """Set up test environment.

           Create nfiles number of files [default: --nfiles option]
        """
        self.dprint('DBG7', "SETUP starts")
        if nfiles is None:
            nfiles = self.nfiles
        need_umount = False
        if not self.mounted and nfiles > 0:
            need_umount = True
            self.umount()
            self.mount()

        # Create files
        for i in range(nfiles):
            self.create_file()

        if need_umount:
            self.umount()
        self.dprint('DBG7', "SETUP done")

    def _cleanup_files(self):
        """Cleanup files created"""
        for item in self.remote_files:
            try:
                cmd = "scp %s:%s %s" % (item[0], item[1], self.tmpdir)
                self.run_cmd(cmd, dlevel='DBG4', msg="    Copy remote file: ")
            except Exception as e:
                self.dprint('DBG7', "    ERROR: %s" % e)

        for item in self.remote_files:
            try:
                cmd = "ssh -t %s sudo rm -f %s" % (item[0], item[1])
                self.run_cmd(cmd, dlevel='DBG4', msg="    Removing remote file: ")
            except:
                pass

        if not self.keeptraces and (self.rmtraces or self._msg_count[FAIL] == 0):
            for rfile in self.tracefiles:
                try:
                    # Remove trace files as root
                    self.dprint('DBG5', "    Removing trace file [%s]" % rfile)
                    os.system(self.sudo_cmd("rm -f %s" % rfile))
                except:
                    pass

    def cleanup(self):
        """Clean up test environment.

           Remove any files created: test files, trace files.
        """
        if self._tcleanup_done:
            return
        self._tcleanup_done = True
        self._tverbose()
        self.debug_repr(0)
        count = self.dprint_count()
        self.trace_stop()

        cleanup_msg = False
        if not self.nocleanup or len(self.rexecobj_list):
            self._print_msg("", single=1)
            self.dprint('DBG7', "CLEANUP starts")
            cleanup_msg = True

        for rexecobj in self.rexecobj_list:
            try:
                if rexecobj.remote:
                    srvname = "at %s" % rexecobj.servername
                else:
                    srvname = "locally"
                self.dprint('DBG3', "    Stop remote procedure server %s" % srvname)
                rexecobj.close()
            except:
                pass
        self.rexecobj = None
        self.rexecobj_list = []

        if not self.nocleanup:
            self._cleanup_files()

        NFSUtil.cleanup(self)

        if cleanup_msg:
            self.dprint('DBG7', "CLEANUP done")

        if self.xunit_report:
            with open(self.xunit_report_file, "w") as f:
                f.write(self.xunit_report_doc.toprettyxml(indent="  "))

        self._close(count)

    def set_nfserr_list(self, nfs3list=[], nfs4list=[], nlm4list=[], mnt3list=[]):
        """Temporaly set the NFS list of expected NFS errors in the next call
           to trace_open
        """
        self.nfserr_list = {
            "nfs3":   nfs3list,
            "nfs4":   nfs4list,
            "nlm4":   nlm4list,
            "mount3": mnt3list,
        }

    def insert_trace_marker(self, name=None):
        """Send a LOOKUP for an unknown file to have a marker in
           the packet trace and return the trace marker id

           name:
               Use this name as the trace marker but the caller must make
               sure this is a unique name in order to find the correct
               index for this marker. This could also be used to add any
               arbitrary information to the packet trace [default: None]
        """
        self.trace_marker_id += 1
        if name is None:
            # Use a unique trace marker name
            name = self.trace_marker_name + "%02d" % self.trace_marker_id
        self.trace_marker_list.append(name)
        os.path.exists(self.abspath(name))
        return self.trace_marker_id

    def get_marker_index(self, marker_id=None):
        """Find packet index of the trace marker given by the marker id

           marker_id:
               ID of trace marker to find in the packet trace, if this is
               not given the current marker id is used [default: None]
        """
        if marker_id is None:
            # Use current marker id
            marker_id = self.trace_marker_id
        name = self.trace_marker_list[marker_id - 1]
        marker_str = "NFS.name == '%s'" % name
        if self.nfs_version < 4:
            nfsop = nfs3_const.NFSPROC3_LOOKUP
        else:
            nfsop = nfs4_const.OP_LOOKUP
        pktcall, pktreply = self.find_nfs_op(nfsop, match=marker_str, call_only=True)
        self.trace_marker_index = pktcall.record.index
        return self.trace_marker_index

    def trace_start(self, *kwts, **kwds):
        """This is a wrapper to the original trace_start method to reset
           the trace marker state
        """
        self.trace_marker_list = []
        self.trace_marker_index = 0
        self.trace_marker_id = 0

        # Start the packet trace
        return super(TestUtil, self).trace_start(*kwts, **kwds)

    def trace_open(self, *kwts, **kwds):
        """This is a wrapper to the original trace_open method where the
           packet trace is scanned for NFS errors and a failure is logged
           for each error found not given on the list of expected errors
           set with method set_nfserr_list. Scanning for NFS error is done
           only if --nfserrors option has been specified.
        """
        # Open the packet trace
        super(TestUtil, self).trace_open(*kwts, **kwds)
        try:
            next(self.pktt)
        except Exception as e:
            pass
        finally:
            self.pktt.rewind()
        if self.pktt.eof:
            raise Exception("Packet trace file is empty: use --trcdelay " \
                            "option to give tcpdump time to flush buffer " \
                            "to packet trace")
        if self.nfserrors:
            if self.nfserr_list is None:
                # Use default lists
                self.nfserr_list = {
                    "nfs3":   self.nfs3err_list,
                    "nfs4":   self.nfs4err_list,
                    "nlm4":   self.nlm4err_list,
                    "mount3": self.mnt3err_list,
                }
            try:
                # Scan for NFS errors
                for pkt in self.pktt:
                    for objname in ("nfs", "nlm", "mount"):
                        nfsobj = getattr(pkt, objname, None)
                        if nfsobj:
                            # Get status
                            status = getattr(nfsobj, "status", 0)
                            if status != 0:
                                nfsver = pkt.rpc.version
                                name = objname + str(nfsver)
                                exp_err_list = self.nfserr_list.get(name)
                                if exp_err_list is not None and status not in exp_err_list:
                                    # Report error not on list of expected errors
                                    self.warning(str(nfsobj))
            except:
                self.test(False, traceback.format_exc())
            self.nfserr_list = None
            self.pktt.rewind()
        return self.pktt

    def create_rexec(self, servername=None, **kwds):
        """Create remote server object."""
        if servername in [None, "", "localhost", "127.0.0.1"]:
            remote = False
            svrname = "locally"
        else:
            remote = True
            svrname = "at %s" % servername

        if self.rexeclog:
            kwds["logfile"] = kwds.get("logfile", self.get_logname(remote))
        else:
            kwds["logfile"] = None

        # Start remote procedure server on given client
        if remote:
            if kwds.get("logfile") is not None:
                self.remote_files.append([servername, kwds["logfile"]])

        self.dprint('DBG2', "Start remote procedure server %s" % svrname)
        self.flush_log()
        self.rexecobj = Rexec(servername, **kwds)
        self.rexecobj_list.append(self.rexecobj)
        return self.rexecobj

    def run_tests(self, **kwargs):
        """Run all test specified by the --runtest option.

           testnames:
               List of testnames to run [default: all tests given by --testnames]

           All other arguments given are passed to the test methods.
        """
        testnames = kwargs.pop("testnames", self.testlist)
        for name in self.testlist:
            testmethod = name + '_test'
            if name in testnames and hasattr(self, testmethod):
                self._runtest = True
                self._tverbose()
                # Set current testname on object
                self.testname = name
                # Execute test
                getattr(self, testmethod)(**kwargs)

        if self.xunit_report:
            failures = 0

            xunit_testsuite = self.xunit_report_doc.createElement("testsuite")
            xunit_testsuite.setAttribute("timestamp", str(datetime.datetime.now()))
            xunit_testsuite.setAttribute("name", self.progname)

            for (t, s, r, m) in self.test_results:
                testcase = self.xunit_report_doc.createElement("testcase")
                xunit_testsuite.appendChild(testcase)
                testcase.setAttribute("name", s)
                testcase.setAttribute("classname", t)

                if r == FAIL:
                    failures += 1
                    failure = self.xunit_report_doc.createElement("failure")
                    failure.setAttribute("message", m)
                    testcase.appendChild(failure)

            xunit_testsuite.setAttribute("tests", str(len(self.test_results)))
            xunit_testsuite.setAttribute("errors", str(failures))
            self.xunit_report_doc.appendChild(xunit_testsuite)

    def _print_msg(self, msg, tid=None, single=0):
        """Display message to the screen and to the log file."""
        if single and self._empty_msg:
            # Display only a single empty line
            return
        tidmsg_l = '' if tid is None else _test_map[tid]
        self.write_log(tidmsg_l + msg)
        if self.isatty:
            tidmsg_s = _test_map_c.get(tid, tidmsg_l)
            if tid == HEAD:
                msg = VT_HL + VT_BOLD + msg + VT_NORM
            elif tid == INFO:
                msg = VT_BLUE + VT_BOLD + msg + VT_NORM
            elif tid in [PASS, FAIL]:
                msg = VT_BOLD + msg + VT_NORM
        else:
            tidmsg_s = tidmsg_l
        print(tidmsg_s + msg)
        sys.stdout.flush()
        if len(msg) > 0:
            self._empty_msg = 0
            self._disp_msgs += 1
        else:
            self._empty_msg = 1

    def _print_time(self, sec):
        """Return the given time in the format [[%dh]%dm]%fs."""
        hh = int(sec/3600)
        sec -= 3600.0*hh
        mm = int(sec/60)
        sec -= 60.0*mm
        ret = "%fs" % sec
        if mm > 0:
            ret = "%dm%s" % (mm, ret)
        if hh > 0:
            ret = "%dh%s" % (hh, ret)
        return ret

    def _total_counts(self, gcounts):
        """Internal method to return a string containing how many tests passed
           and how many failed.
        """
        total = gcounts[PASS] + gcounts[FAIL] + gcounts[BUG]
        bugs  = ", %d known bugs" % gcounts[BUG]  if gcounts[BUG] > 0  else ""
        warns = ", %d warnings"   % gcounts[WARN] if gcounts[WARN] > 0 else ""
        tmsg = " (%d passed, %d failed%s%s)" % (gcounts[PASS], gcounts[FAIL], bugs, warns)
        return (total, tmsg)

    def _tverbose(self):
        """Display test group message as a PASS/FAIL including the number
           of tests that passed and failed within this test group when the
           tverbose option is set to 'group' or level 0. It also groups all
           test messages belonging to the same sub-group when the tverbose
           option is set to 'normal' or level 1.
        """
        if self.tverbose == 0 and len(self.test_msgs) > 0:
            # Get the count for each type of message within the
            # current test group
            gcounts = {}
            for tid in _test_map:
                gcounts[tid] = 0
            for item in self.test_msgs[-1]:
                if item[3]:
                    # This message has already been displayed
                    continue
                item[3] = 1
                if len(item[2]) > 0:
                    # Include all subtest results on the counts
                    for subitem in item[2]:
                        gcounts[subitem[0]] += 1
                else:
                    # No subtests, include just the test results
                    gcounts[item[0]] += 1
            (total, tmsg) = self._total_counts(gcounts)
            if total > 0:
                # Fail the current test group if at least one of the tests within
                # this group fails
                tid = FAIL if gcounts[FAIL] > 0 else PASS
                # Just add the test group as a single test entity in the total count
                self._msg_count[tid] += 1
                # Just display the test group message with the count of tests
                # that passed and failed within this test group
                msg = self.test_msgs[-1][0][1].replace("\n", "\n          ")
                self._print_msg(msg + tmsg, tid)
                sys.stdout.flush()
        elif self.tverbose == 1 and len(self.test_msgs) > 0:
            # Process all sub-groups within the current test group
            group = self.test_msgs[-1]
            for subgroup in group:
                sgtid = subgroup[0]
                msg = subgroup[1]
                subtests = subgroup[2]
                disp = subgroup[3]
                if len(subtests) == 0 or disp:
                    # Nothing to process, there are no subtests
                    # or have already been displayed
                    continue
                # Do not display message again
                subgroup[3] = 1
                # Get the count for each type of message within this
                # test sub-group
                gcounts = {}
                for tid in _test_map:
                    gcounts[tid] = 0
                for subtest in subtests:
                    gcounts[subtest[0]] += 1
                (total, tmsg) = self._total_counts(gcounts)
                # Just add the test sub-group as a single test entity in the
                # total count
                self._msg_count[sgtid] += 1
                # Just display the test group message with the count of tests
                # that passed and failed within this test group
                msg = msg.replace("\n", "\n          ")
                self._print_msg(msg + tmsg, sgtid)
                sys.stdout.flush()
        if self.createtraces:
            if (self.traceproc or self.basename) and self.tracefile:
                self.trace_stop()
                try:
                    self.trace_open()
                except Exception as e:
                    self.warning(str(e))
                finally:
                    self.pktt.close()
        self._test_time()

    def _subgroup_id(self, subgroup, tid, subtest):
        """Internal method to return the index of the sub-group message"""
        index = 0
        grpid = None
        # Search the given message in all the sub-group messages
        # within the current group
        group = self.test_msgs[-1]
        if subtest is not None:
            # Look for sub-group message only if this test has subtests
            for item in group:
                if subgroup == item[1]:
                    # Sub-group message found
                    grpid = index
                    break
                index += 1
        if grpid is None:
            # Sub-group not found, add it
            # [tid, test-message, list-of-subtest-results]
            grpid = len(group)
            group.append([tid, subgroup, [], 0])
        return grpid

    def _test_msg(self, tid, msg, subtest=None, failmsg=None):
        """Common method to display and group test messages."""
        if len(self.test_msgs) == 0 or tid == HEAD:
            # This is the first test message or the start of a group,
            # so process the previous group if any and create a placeholder
            # for the current group
            if not self._runtest:
                self._tverbose()
            self.test_msgs.append([])
        # Match the given message to a sub-group or add it if no match
        grpid = self._subgroup_id(msg, tid, subtest)
        if subtest is not None:
            # A subtest is given so added to the proper sub-group
            subgroup = self.test_msgs[-1][grpid]
            subgroup[2].append([tid, subtest])
            if subgroup[0] == PASS and tid == FAIL:
                # Subtest failed so fail the subgroup
                subgroup[0] = FAIL
        if self.tverbose == 2 or (self.tverbose == 1 and subtest is None):
            # Display the test message if tverbose flag is set to verbose(2)
            # or if there is no subtest when tverbose is set to normal(1)
            self._msg_count[tid] += 1
            if subtest is not None:
                msg += subtest
            if failmsg is not None and tid == FAIL:
                msg += failmsg
            msg = msg.replace("\n", "\n          ")
            self._print_msg(msg, tid)

        if tid == HEAD:
            if self._runtest:
                self.test_info("TEST: Running test '%s'" % self.testname)
            self._runtest = False
            if self.createtraces:
                self.trace_start()

    def _test_time(self):
        """Add an INFO message having the time difference between the current
           time and the time of the last call to this method.
        """
        if self._disp_time >= self._disp_msgs + self.dprint_count():
            return
        self.test_time.append(time.time())
        if self._opts_done and len(self.test_time) > 1:
            ttime = self.test_time[-1] - self.test_time[-2]
            self._test_msg(INFO, "TIME: %s" % self._print_time(ttime))
        self._disp_time = self._disp_msgs + self.dprint_count()

    def exit(self):
        """Terminate script with an exit value of 0 when all tests passed
           and a value of 1 when there is at least one test failure.
        """
        if self._msg_count[FAIL] > 0:
            sys.exit(1)
        else:
            sys.exit(0)

    def config(self, msg):
        """Display config message and terminate test with an exit value of 2."""
        msg = "CONFIG: " + msg
        msg = msg.replace("\n", "\n        ")
        self.write_log(msg)
        print(msg)
        sys.exit(2)

    def test_info(self, msg):
        """Display info message."""
        self._test_msg(INFO, msg)

    def test_group(self, msg):
        """Display heading message and start a test group.

           If tverbose=group or level 0:
               Group message is displayed as a PASS/FAIL message including the
               number of tests that passed and failed within this test group.
           If tverbose=normal|verbose or level 1|2:
               Group message is displayed as a heading messages for the tests
               belonging to this test group.
        """
        self._test_msg(HEAD, msg)

    def warning(self, msg):
        """Display warning message."""
        if self.warnings:
            self._test_msg(WARN, msg)

    def test(self, expr, msg, subtest=None, failmsg=None, terminate=False):
        """Test expr and display message as PASS/FAIL, terminate execution
           if terminate option is True.

           expr:
               If expr is true, display as a PASS message,
               otherwise as a FAIL message
           msg:
               Message to display
           subtest:
               If given, append this string to the displayed message and
               mark this test as a member of the sub-group given by msg
           failmsg:
               If given, append this string to the displayed message when
               expr is false [default: None]
           terminate:
               Terminate execution if true and expr is false [default: False]

           If tverbose=normal or level 1:
               Sub-group message is displayed as a PASS/FAIL message including
               the number of tests that passed and failed within the sub-group
           If tverbose=verbose or level 2:
               All tests messages are displayed
        """
        tid = PASS if expr else FAIL
        if tid == FAIL and len(self._bugmsgs):
            for tmsg, binfo in self._bugmsgs.items():
                if re.search(tmsg, msg):
                    # Do not count as a failure if assertion is found
                    # in bugmsgs file
                    tid = BUG
                    if binfo is not None and len(binfo):
                        # Display bug message with the assertion
                        msg = "[%s]: %s" % (binfo, msg)
                    break

        self.test_results.append((self.testname, msg, tid, failmsg))
        self._test_msg(tid, msg, subtest=subtest, failmsg=failmsg)
        if tid == FAIL and terminate:
            self.exit()

    def testid_count(self, tid):
        """Return the number of instances the testid has occurred."""
        return self._msg_count[tid]

    def get_name(self):
        """Get unique name for this instance."""
        if not self._name:
            timestr = self.timestamp("{0:date:%Y%m%d_%H%M%S}")
            self._name = "%s_%s" % (self.progname, timestr)
        return self._name

    def get_dirname(self, dir=None):
        """Return a unique directory name under the given directory."""
        self.dirname = "%s_d_%03d" % (self.get_name(), self.diridx)
        self.diridx += 1
        self.absdir = self.abspath(self.dirname, dir=dir)
        self.dirs.append(self.dirname)
        self.remove_list.append(self.absdir)
        return self.dirname

    def get_filename(self, dir=None):
        """Return a unique file name under the given directory."""
        self.filename = "%s_f_%03d" % (self.get_name(), self.fileidx)
        self.fileidx += 1
        self.absfile = self.abspath(self.filename, dir=dir)
        self.files.append(self.filename)
        self.remove_list.append(self.absfile)
        return self.filename

    def data_pattern(self, offset, size, pattern=None):
        """Return data pattern.

           offset:
               Starting offset of pattern
           size:
               Size of data to return
           pattern:
               Data pattern to return, default is of the form:
               hex_offset(0x%08X) abcdefghijklmnopqrst\\n
        """
        data = b''
        if pattern is None:
            pattern = b'abcdefghijklmnopqrst'
            line_len = 32
            default = True
        else:
            line_len = len(pattern)
            default = False

        s_offset = offset % line_len
        offset = offset - s_offset
        N = int(0.9999 + (size + s_offset) / float(line_len))

        for i in range(0,N):
            if default:
                str_offset = b"0x%08X " % offset
                plen = 31 - len(str_offset)
                data += str_offset + pattern[:plen] + b'\n'
                offset += line_len
            else:
                data += pattern
        return data[s_offset:size+s_offset]

    def delay_io(self, delay=None):
        """Delay I/O by value given or the value given in --iodelay option."""
        if delay is None:
            delay = self.iodelay
        if not self.nomount and len(self.basename) == 0:
            # Slow down traffic for tcpdump to capture all packets
            time.sleep(delay)

    def create_dir(self, dir=None, mode=0o755):
        """Create a directory under the given directory with the given mode."""
        self.get_dirname(dir=dir)
        self.dprint('DBG3', "Creating directory [%s]" % self.absdir)
        os.mkdir(self.absdir, mode)
        return self.dirname

    def write_data(self, fd, offset=0, size=None, pattern=None, verbose=0, dlevel="DBG5"):
        """Write data to the file given by the file descriptor

           fd:
               File descriptor
           offset:
               File offset where data will be written to [default: 0]
           size:
               Total number of bytes to write [default: --filesize option]
           pattern:
               Data pattern to write to the file [default: data_pattern default]
           verbose:
               Verbosity level [default: 0]
        """
        if size is None:
            size = self.filesize

        while size > 0:
            # Write as much as wsize bytes per write call
            dsize = min(self.wsize, size)
            os.lseek(fd, offset, 0)
            if verbose:
                self.dprint(dlevel, "    Write file %d@%d" % (dsize, offset))
            count = os.write(fd, self.data_pattern(offset, dsize, pattern))
            size -= count
            offset += count

    def create_file(self, offset=0, size=None, dir=None, mode=None, **kwds):
        """Create a file starting to write at given offset with total size
           of written data given by the size option.

           offset:
               File offset where data will be written to [default: 0]
           size:
               Total number of bytes to write [default: --filesize option]
           dir:
               Create file under this directory
           mode:
               File permissions [default: use default OS permissions]
           pattern:
               Data pattern to write to the file [default: data_pattern default]
           ftype:
               File type to create [default: FTYPE_FILE]
           hole_list:
               List of offsets where each hole is located [default: None]
           hole_size:
               Size of each hole [default: --wsize option]
           verbose:
               Verbosity level [default: 0]
           dlevels:
               Debug level list to use [default: ["DBG3", "DBG4", "DBG5"]]

           Returns the file name created, the file name is also stored
           in the object attribute filename -- attribute absfile is also
           available as the absolute path of the file just created.

           File created is removed at cleanup.
        """
        _dlevels  = ["DBG3", "DBG4", "DBG5"]
        pattern   = kwds.pop("pattern",   None)
        ftype     = kwds.pop("ftype",     FTYPE_FILE)
        hole_list = kwds.pop("hole_list", None)
        hole_size = kwds.pop("hole_size", self.wsize)
        verbose   = kwds.pop("verbose", 0)
        dlevels   = kwds.pop("dlevels", _dlevels)

        # Make sure all levels are specified and if not use default values
        for idx in range(len(dlevels), 3):
            dlevels.append(_dlevels[idx])

        self.get_filename(dir=dir)
        if size is None:
            size = self.filesize

        if ftype == FTYPE_FILE:
            sfile = None
            self.dprint(dlevels[0], "Creating file [%s] %d@%d" % (self.absfile, size, offset))
        elif ftype in (FTYPE_SP_OFFSET, FTYPE_SP_ZERO, FTYPE_SP_DEALLOC):
            self.dprint(dlevels[0], "Creating sparse file [%s] of size %d" % (self.absfile, size))
            sfile = SparseFile(self.absfile, size, hole_list, hole_size)
        else:
            raise Exception("Unknown file type %d" % ftype)

        # Create file
        fd = os.open(self.absfile, os.O_WRONLY|os.O_CREAT|os.O_TRUNC)

        try:
            if ftype == FTYPE_FILE:
                self.write_data(fd, offset, size, pattern, verbose, dlevels[2])
            elif ftype in [FTYPE_SP_OFFSET, FTYPE_SP_ZERO]:
                for doffset, dsize, dtype in sfile.sparse_data:
                    # Do not write anything to a hole for FTYPE_SP_OFFSET
                    if dtype:
                        self.dprint(dlevels[1], "    Writing data segment starting at offset %d with length %d" % (doffset, dsize))
                        self.write_data(fd, doffset, dsize, pattern, verbose, dlevels[2])
                    elif ftype == FTYPE_SP_ZERO:
                        # Write zeros to create the hole
                        self.dprint(dlevels[1], "    Writing hole segment starting at offset %d with length %d" % (doffset, dsize))
                        self.write_data(fd, doffset, dsize, b"\x00", verbose, dlevels[2])
                if sfile.endhole and ftype == FTYPE_SP_OFFSET:
                    # Extend the file to create the last hole
                    os.ftruncate(fd, size)
            elif ftype == FTYPE_SP_DEALLOC:
                # Create regular file for FTYPE_SP_DEALLOC
                self.dprint(dlevels[1], "    Writing data segment starting at offset %d with length %d" % (0, size))
                self.write_data(fd, offset, size, pattern, verbose, dlevels[2])

                for doffset in hole_list:
                    self.dprint(dlevels[1], "    Create hole starting at offset %d with length %d" % (doffset, hole_size))
                    out = self.libc.fallocate(fd, SR_DEALLOCATE, doffset, hole_size)
                    if out == -1:
                        err = ctypes.get_errno()
                        raise OSError(err, os.strerror(err), self.filename)
        finally:
            os.close(fd)

        if sfile:
            self.sparse_files.append(sfile)
        if mode != None:
            os.chmod(self.absfile, mode)
        return self.filename

    def compare_data(self, data, offset=0, pattern=None, nlen=32, fd=None, msg=""):
        """Compare data to the given pattern and return a three item tuple:
           absolute offset where data differs from pattern, sample data at
           diff offset, and the expected data at diff offset according to
           pattern. If data matches exactly it returns (None, None, None).

           data:
               Data to compare against the pattern
           offset:
               Absolute offset to get the expected data from pattern
               [default: 0]
           pattern:
               Data pattern function or string. If this is a function,
               it must take offset and size as positional arguments.
               If given as a string, the pattern repeats over and over
               starting at offset = 0 [default: self.data_pattern]
           nlen:
               Size of sample data to return if a difference is found
               [default: 32]
           fd:
               Opened file descriptor for the data, this is used where
               the data comes from a file and a difference is found right
               at the end of the given data. In this case, the data is
               read from the file to return the sample diff of size given
               by nlen [default: None]
           msg:
               Message to append to debug message if a difference is
               found. If set to None, debug messages are not displayed
               [default: '']
        """
        if pattern is None:
            # Default pattern
            get_data = self.data_pattern
        elif isinstance(pattern, str):
            # String pattern
            get_data = lambda o, s: self.data_pattern(o, s, pattern)
        else:
            # User provided function as a pattern
            get_data = pattern

        count = len(data)
        edata = get_data(offset, count)

        # Compare data
        index = 0
        doffset = None
        for c in data:
            if c != edata[index]:
                # Absolute offset of difference
                doffset = offset + index
                break
            index += 1

        if doffset is not None:
            doff = doffset - offset
            if fd is not None and doff + nlen > count:
                # Not enough data in current buffer to display,
                # so read file at the given failed offset
                os.lseek(fd, doffset, os.SEEK_SET)
                mdata = os.read(fd, nlen)
                edata = get_data(doffset, len(mdata))
            else:
                # Enough data in current buffer
                mdata = data[doff:doff+nlen]
                edata = edata[doff:doff+nlen]
            if msg is not None:
                self.dprint('DBG2', "Found difference at offset %d%s" % (doffset, msg))
                self.dprint('DBG2', "    File data:     %r" % mdata)
                self.dprint('DBG2', "    Expected data: %r" % edata)
            return doffset, mdata, edata
        return (None, None, None)

    def verify_file_data(self, msg=None, pattern=None, path=None, filesize=None, nlen=None, cmsg=""):
        """Verify file by comparing the data to the given pattern.
           It returns the results from the compare_data method.

           msg:
               Test assertion message. If set to None, no assertion is
               done it just returns the results [default: None]
           pattern:
               Data pattern function or string. If this is a function,
               it must take offset and size as positional arguments.
               If given as a string, the pattern repeats over and over
               starting at offset = 0 [default: self.data_pattern]
           path:
               Absolute path of file to verify [default: self.absfile]
           filesize:
               Expected size of file to be verified [default: self.filesize]
           nlen:
               Size of sample data to return if a difference is found
               [default: compare_data default]
           cmsg:
               Message to append to debug message if a difference is
               found. If set to None, debug messages are not displayed
               [default: '']
        """
        doffset = None
        mdata   = None
        edata   = None
        if path is None:
            path = self.absfile

        if filesize is None:
            filesize = self.filesize
        nargs = { 'pattern': pattern, 'msg': cmsg }
        if nlen is not None:
            nargs['nlen'] = nlen

        self.dprint('DBG2', "Open file [%s] for reading to validate data" % path)
        fd = os.open(path, os.O_RDONLY)

        try:
            offset = 0
            size = filesize
            while size > 0:
                dsize = min(self.rsize, size)
                self.dprint('DBG5', "    Read file %d@%d" % (dsize, offset))
                data = os.read(fd, dsize)
                count = len(data)
                if count > 0:
                    doffset, mdata, edata = self.compare_data(data, offset, fd=fd, **nargs)
                    if doffset is not None:
                        break
                else:
                    size -= count
                    break
                size -= count
                offset += count
        finally:
            os.close(fd)

        if msg is not None and len(msg):
            fmsg = ""
            expr = False
            if doffset is not None:
                fmsg = ", difference at offset %d" % doffset
            elif size > 0:
                fmsg = ", file size (%d) is shorter than expected (%d)" % (filesize - size, filesize)
            else:
                fstat = os.stat(path)
                if fstat.st_size > filesize:
                    fmsg = ", file size (%d) is larger than expected (%d)" % (fstat.st_size, filesize)
                else:
                    # Data has been verified correctly
                    expr = True
            self.test(expr, msg, failmsg=fmsg)
        return (doffset, mdata, edata)

    def _reset_files(self):
        """Reset state used in *_files() methods."""
        self.roffset = 0
        self.woffset = 0
        self.rfds = []
        self.wfds = []

    def open_files(self, mode, create=True):
        """Open files according to given mode, the file descriptors are saved
           internally to be used with write_files(), read_files() and
           close_files(). The number of files to open is controlled by
           the command line option '--nfiles'.

           The mode could be either 'r' or 'w' for opening files for reading
           or writing respectively. The open flags for mode 'r' is O_RDONLY
           while for mode 'w' is O_WRONLY|O_CREAT|O_SYNC. The O_SYNC is used
           to avoid the client buffering the written data.
        """
        for i in range(self.nfiles):
            if mode[0] == 'r':
                file = self.abspath(self.files[i])
                self.dprint('DBG3', "Open file for reading: %s" % file)
                fd = os.open(file, os.O_RDONLY)
                self.rfds.append(fd)
                self.lock_type = fcntl.F_RDLCK
            elif mode[0] == 'w':
                if create:
                    self.get_filename()
                    file = self.absfile
                else:
                    file = self.abspath(self.files[i])
                self.dprint('DBG3', "Open file for writing: %s" % file)
                # Open file with O_SYNC to avoid client buffering the write requests
                fd = os.open(file, os.O_WRONLY|os.O_CREAT|os.O_SYNC)
                self.wfds.append(fd)
                self.lock_type = fcntl.F_WRLCK

    def close_files(self, *fdlist):
        """Close all files opened by open_files() and all file descriptors
           given as arguments.
        """
        for fd_list in (self.wfds, self.rfds, fdlist):
            for fd in fd_list:
                try:
                    if fd is not None:
                        os.fstat(fd) # If fd is not opened -- it fails
                        self.dprint('DBG3', "Closing file")
                        os.close(fd)
                except:
                    pass
        self._reset_files()

    def write_files(self):
        """Write a block of data (size given by --wsize) to all files opened
           by open_files() for writing.
        """
        for fd in self.wfds:
            self.dprint('DBG4', "Write file %d@%d" % (self.wsize, self.woffset))
            os.write(fd, self.data_pattern(self.woffset, self.wsize))
        self.woffset += self.offset_delta

    def read_files(self):
        """Read a block of data (size given by --rsize) from all files opened
           by open_files() for reading.
        """
        for fd in self.rfds:
            self.dprint('DBG4', "Read file %d@%d" % (self.rsize, self.roffset))
            os.lseek(fd, self.roffset, 0)
            os.read(fd, self.rsize)
        self.roffset += self.offset_delta

    def lock_files(self, lock_type=None, offset=0, length=0):
        """Lock all files opened by open_files()."""
        if lock_type is None:
            lock_type = self.lock_type
        ret = []
        mode_str = 'WRITE' if lock_type == fcntl.F_WRLCK else 'READ'
        lockdata = struct.pack('hhllhh', lock_type, 0, offset, length, 0, 0)
        for fd in self.rfds + self.wfds:
            try:
                self.dprint('DBG3', "Lock file F_SETLKW (%s)" % mode_str)
                rv = fcntl.fcntl(fd, fcntl.F_SETLKW, lockdata)
                ret.append(rv)
            except Exception as e:
                self.warning("Unable to get lock on file: %r" % e)
        return ret

    def str_args(self, args):
        """Return the formal string representation of the given list
           where string objects are truncated.
        """
        alist = []
        for item in args:
            if isinstance(item, str) and len(item) > 16:
                alist.append(repr(item[:16]+"..."))
            else:
                alist.append(repr(item))
        return ", ".join(alist)

    def run_func(self, func, *args, **kwargs):
        """Run function with the given arguments and return the results.
           All positional arguments are passed to the function while the
           named arguments change the behavior of the method.
           Object attribute "oserror" is set to the OSError object if the
           function fails.

           msg:
               Test assertion message [default: None]
           err:
               Expected error number [default: 0]
        """
        msg = kwargs.get("msg", None)
        err = kwargs.get("err", 0)
        error = 0
        result = None
        self.oserror = None
        expestr = str(errno.errorcode.get(err,err))
        fmsg = ", expecting %s but it succeeded" % expestr if err else ""
        self.dprint('DBG4', "%s(%s)" % (func.__name__, self.str_args(args)))
        try:
            result = func(*args)
        except OSError as oserr:
            self.oserror = oserr
            error = oserr.errno
            errstr = str(errno.errorcode.get(error,error))
            strerr = os.strerror(error)
            self.dprint('DBG4', "%s() got error [%s] %s" % (func.__name__, errstr, strerr))
            if err:
                fmsg = ", expecting %s but got %s" % (expestr, errstr)
            else:
                fmsg = ", got error [%s] %s" % (errstr, strerr)
        if msg is not None:
            # Display test assertion
            self.test(error == err, msg, failmsg=fmsg)
        return result
