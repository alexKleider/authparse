#!../venv/bin/python3
#   print("Running Python3 script: 'authparse.py'.......")
# -*- coding: utf-8 -*-
# vim: set file encoding=utf-8 :
#
# file: 'authparse.py'
# Part of ___, ____.

# Copyright 2015 Alex Kleider
#   This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#   Look for file named COPYING.
"""
A TDD version of logparse limited only to auth.log,
'authparse.py' is typically used to process /var/log/auth.log files
and retrieve IP addresses which can then be considered for filtering
using iptables.
When used without command line options: IP addresses are collected
from STDIN and reported to STDOUT.  All IP addresses are collected and
reported.  Additional information gleaned from data in the input
auth.log file(s) can also be reported.

usage:
  logparser3.py --help
  logparser3.py --version
  logparser3.py  [-qkfd]
                [-r | -rr ]
                [--white <wfile>...]
                [--black <bfile>...]
                [--input <ifile>...]
                [--output <ofile>]

Options:
  -h --help  Print the __doc__ string.
  --version  Print the version number.
  -r --report  How much to report about the IP addresses.
          0 - Addresses alone.
          1 - Addresses and number of times each one appeared.
          2 - Addresses, number of appearances, type of appearances,
              and additional information if available.
  -d --demographics  Include location/origin of IP if possible.
  -q --quiet  Supress reporting of success list, file access errors,
              or files devoid of IPs.
  -k --known  Report any known ('white' or 'black') IPs
                that have been removed from output.
  -w --white=<wfile>  Specify 0 or more files containing white listed IPs.
  -b --black=<bfile>  Specify 0 or more files containing black listed IPs.
  -i --input=<ifile>  Specify 0 or more input files.  If none are
                      provided, stdin is used.
                      These are typically auth.log files but don't have to be.
                      If a specified file is a directory, all files
                      with names ending in the suffix '.log' 
                      beneath that directory are considered as though
                      separately specified.
  -o --output=<ofile>  Specify output file, otherwise std out is used.
  -f --frequency   Sort output by frequency of appearance of IPs
                   (Default is by IP.)

Any known IPs can be provided in files specified as containing either
'--black' or '--white' listed IPs.  These are also read and any IP
addresses found will NOT be included in the output.  (See the
-k/--known option which causes this to be reported.) Typically this
would be useful if you have a 'white' list of known IPs you would
definitely NOT want to block and/or if you had a 'black' list of already
blocked IPs which you'd have no need to block again.
Keep in mind that it should not be possible to have a black listed IP
address appear in log files if it has in fact been blocked.

If any provided file(s) don't exist or don't contain any IP's, this
will be reported unless the -q/--quiet option is selected.

If this scrolls too much, try piping to pager:
./logparser3.py -h | pager
"""
# import standard library modules
import os
import re
import shlex
from pprint import pprint
# import custom modules
from docopt import docopt
from ipwhois import IPWhois
# metadata such as version number
VERSION = "v0.0.0"
# other constants
DummyIP = '0.0.0.0'
LOG = "log"  # Used by select_logs function.
# To retrieve (ipv4) IP addresses from a line:
_IP_EXP = \
r"""
\b
\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
"""
_findall_ips = re.compile(_IP_EXP, re.VERBOSE).findall
# global variables
SPoL = dict(
    invalid_user = dict(
        re =  r"""Invalid user (?P<user>\S+) from """,
        header_text =  "'auth.log' reporting 'invalid user's:",
        key_ =  "user"
        ),
    no_id = dict(
        re =  (r"""Did not receive identification string from """),
        header_text =  "'auth.log' reporting 'no id's:",
        key_ =   None
        ),
    break_in = dict(
        re =  r"POSSIBLE BREAK-IN ATTEMPT!",  # Not in logs of dogpatch.
        header_text =  (
            "'auth.log' reporting 'POSSIBLE BREAK-IN ATTEMPT!'s:"),
        key_ =   None
        ),
    pub_key = dict(
        re =  r""" Accepted publickey for (?P<user>\S+)""",
        header_text =  "'auth.log' reporting ''s:",
        key_ = "user"
        ),
    closed = dict(
        re =  r""" Connection closed by \S+""",
        header_text =  "'auth.log' reporting 'closed's:",
        key_ = None
        ),
    disconnect = dict(
        re =  (
                r""" Received disconnect from """),
        header_text =  (
                "'auth.log' reporting 'Received disconnect from's:"),
        key_ = None
        ),
    listening = dict(
        re =  r""" Server listening on (?P<listener>.+)""",
        header_text =  "'auth.log' reporting 'Server listening on's:",
        key_ = "listener"
        ),
    not_allowed = dict(   # Not in logs of dogpatch.
        re = r""" User (?P<user>\S+) from (?:\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) not allowed because none """,
        header_text = "'auth.log' reporting ''s:",
        key_ = "user"
        ),
    unrecognized = dict(  # Besure this key is alphabetically last!
        re = ".*",
        header_text = "Unrecognized line.",
        key_ = None
        ),
    )


_line_types = sorted(SPoL)
# invalid_user, no_id, break_in, pub_key,
# closed, disconnect, listening, not_allowed
# unrecognized
# Was going to include noip but decided to keep presence or absence of
# IP at a separate level.

for key in _line_types:
    SPoL[key]['search4'] = re.compile(SPoL[key]['re']).search

# custom exception types  (I have none)
# private functions and classes
# public functions and classes

class FileNameCollector(object):
    """Maintains a list of file names by providing an
    <add2list_of_file_names> method.
    A named parameter <restrict2logs> can be set to True if
    one wants to include only files with names containing the
    string defined by the constant LOG.
    Uses function select_logs(files).
    """
    def __init__(self, restrict2logs=False):
        self.file_names = []
        self.restrict2logs = restrict2logs
    def include(self, f_name):
        if self.restrict2logs and not(LOG in f_name):
            return False
        else:
            return True
    def add2list_of_file_names(self, f_or_dir_name):
        f_or_dir_full_name = os.path.abspath(
                            os.path.expanduser(
                                f_or_dir_name))
        if os.path.isfile(f_or_dir_full_name):
            if self.include(f_or_dir_name):
                self.file_names.append(f_or_dir_full_name)
        elif os.path.isdir(f_or_dir_full_name):
            for path, __dirs, files in os.walk(f_or_dir_full_name):
                for f in files:
                    if self.include(f):
                        self.file_names.append(os.path.join(path, f))
        else:
            print(
            "File '{}' doesn't exist.".format(f_or_dir_full_name))

# Overview:  (of the next three Class declarations)
#  The top level data structure is one instance of IpDict:
#  a dict keyed by Ip addresses with values instances of IpInfo.
# <line_info> entries are made using the add_entry method of IpInfo
# instances of which are themselves dictionaries keyed by _line_types.

class LineInfo(object):
    """Each instance has the following attributes...
        line_type: one of the keys of SPoL.
        key_: possibly None.
            currently, possible keys are 'user', 'listener', ..
        value: name matched by key_, None if key_ is None
            NOTE: in the IP_Info class instance,
            the corresponding value is a list of values
            or a counter.
    """
    def __init__(self, line):
        """Accepts a line of text and returns an instance.
        Provides support for get_log_info(line)
        If <line> is None, returns an 'unrecognized' instance.
        """
        self.line_type = 'unrecognized'
        self.key_ = None
        self.value = None
        if line != None:
            for line_type in _line_types:
                match_obj = SPoL[line_type]['search4'](line)
                if match_obj:  # 'search': expect 0 or 1 match object.
                    self.line_type = line_type
                    self.key_ = SPoL[line_type]['key_']
                    if self.key_:
                        self.value = match_obj.group(
                                    SPoL[line_type]['key_'])
                    break  # Assume a line can only be of 1 type.

class IpInfo(object):
    """An instance of this type is used to collect information about
    each IP address that appears in the log (/var/log/authlog) files.
    Instances are kept in a dict keyed by the IP address and 
    consist of a dict keyed by line_type.
    Note: the ip address itself is not part of the instance.
    For line_type(s) with a string as key, the value is a list.
    For those with a key of None, the value is an integer counter.
    """
    def __init__(self):
        self.data = {}
    def add_entry(self, line_info):
        """<line_info> is expected to be an instance of LineInfo.
        """
        if line_info.key_:
            __0 = self.data.setdefault(line_info.line_type,
                                    [])
            self.data[line_info.line_type].append(line_info.value)
        else:
            entry = self.data.setdefault(line_info.line_type, 0)
            self.data[line_info.line_type] += 1

class IpDict():
    """An instance is used to maintain all information gleaned from
    the log files, and is typically a value indexed by IP address
    within an IpInfo instance.
    """
    def __init__(self):
        self.data = {}
    def add_data(self, ip_address, ip_info):
        """Adds information from an instance of LineInfo into it's
        dictionary, creating an instance of IpInfo if needed.
        """
        __0 = self.data.setdefault(ip_address, IpInfo())
        self.data[ip_address].add_entry(ip_info)

class IpDemographics(object):
    """Instances discover and keep demographics of an IP address
    provided to the __init__ as a dotted quad."""
    def __init__(self, ip_addr, NO_INFO="unavailable"):
        obj = IPWhois(ip_addr)
        all_ip_info = obj.lookup()
        nets = all_ip_info['nets'][0]
        self.data = dict(
                ip = all_ip_info.setdefault('query', NO_INFO),
                address = nets.setdefault('address', NO_INFO),
                city= nets.setdefault('city', NO_INFO),
                country = nets.setdefault('country', NO_INFO),
                description = nets.setdefault('description', NO_INFO),
                state = nets.setdefault('state', NO_INFO),
                )
        for k in self.data:  # Remove line breaks from within fields.
            ss = self.data[k].split('\n')
            s = ', '.join(ss)
            self.data[k] = s
    def __repr__(self):
        return """IP {ip}: {description}
    {address}, {city}, {state}, {country}""".format(**self.data)
    @property
    def get_data(self):
        return self.data

def get_args():
    """Uses docopt to return command line arguments.
    """
    return docopt(__doc__, version=VERSION)

def get_list_of_ips(line):
    """Returns a list (possibly empty) of all ipv4 addresses found in
    the line. Simply calls _findall_ips(line).
    """
    return _findall_ips(line)

def get_ip(line):
    """Returns an IP address. 
    Uses _IP_EXP regex to find all matches in the line.
    Returns the first one if there are any, if not
    it returns the string designated by the constant DummyIP.
    """
    l = _findall_ips(line)
    if l:
        return l[0]
    else:
        return DummyIP

def get_log_info(line):
    """<line> is assumed to be a log file line.
    Returns an instance of LineInfo class. Simply returns LineInfo(line)
    """
    return LineInfo(line)

def get_ips(list_of_sources):
    """
    The parameter is an iterable of file (regular or directory) names.
    Returned is the set of all IP addresses contained in the files,
    both those listed and those within directories listed.
    The parameter would typically be the list of white or black files.
    """
    ret = set()
    f_names = get_list_of_file_names(list_of_sources)
    for f_name in f_names:
        for line in open(f_name, 'r'):
            ips = _findall_ips(line)
            if ips:
                for ip in ips:
                    ret.append(ip)
    return ret

def store_ip_info(ip, ip_info, master_ip_dict):
    """First parameter is an IP address to serve as the index into the
    third parameter.
    Second parameter is an instance of IpInfo which 
    is stored in <master_ip_dict> (an instance of IpDict) indexed by <ip>.
    DON'T NEED THIS- CAN USE IpDict method add_data.
    """
    entry = master_ip_dict.setdefault(ip, )
    master_ip_dict.add_data(ip, line_info)

def move_info_sources2master(list_of_sources, master_ip_dict):
    """
    First parameter is an iterable of file (reg or dir) names
    (typically the list of log files to analyse) from which new
    information is gathered and added to <master_ip_dict>,
    an instance of IpDict.
    """
    f_names = get_list_of_file_names(list_of_sources)
    for f_name in f_names:
        for line in open(f_name, 'r'):
            ips = _findall_ips(line)
            if ips:
                ip = ips[0]
                line_info = get_log_info(line)  # LineInfo instance.
            else:
                ip = NON_IP
                line_info = LineInfo(None)

# main function
def main():
    white_collector = FileNameCollector()
    for fname in args["--white"]:
        white_collector.add2list_of_file_names(fname)
    black_collector = FileNameCollector()
    for fname in args["--black"]:
        black_collector.add2list_of_file_names(fname)
    logs_collector = FileNameCollector(True)
    for fname in args["--in"]:
        logs_collector.add2list_of_file_names(fname)

def test_get_ip_demographics():
    ip_info = get_ip_demographics('76.191.204.54')
    pprint(ip_info)

def debug_re():
    regex =  r"""Invalid user (?P<user>\S+) from """
    test_line = (
'Mar  9 08:12:51 localhost sshd[4522]: Invalid user postgres from 202.153.165.67')
    pattern_obj = re.compile(regex)
    search_func = pattern_obj.search
    match_obj = search_func(test_line)
    if match_obj:
        print('There is a match.')
    print(match_obj.group('user'))
    print(search_func(test_line).group('user'))  # param is a key
    print(search_func(test_line).groups())
    for key_ in search_func(test_line).groups():  # returns values
        print(key_)                               # NOT keys!
#       print(search_func(test_line).group(key_)) # so this crashes.
    inst = LineInfo(test_line)
    print("{}: {}: {}".format(inst.line_type, inst.key_, inst.value))
    pass

def test_include():
    collector = FileNameCollector()
    if collector.include("file.log"):
        print("'file.log' returns True")
    else:
        print("'file.log' returns False")
    collector = FileNameCollector(True)
    if collector.include("filenamealone"):
        print("'filenamealone' returns True")
    else:
        print("'filenamealone' returns False")

def test_IpDemographics():
    DaveAngel = '74.208.58.210'
    info = IpDemographics(DaveAngel)
    print(info)

if __name__ == '__main__':  # code block to run the application
#   test_include()
    test_IpDemographics()
    pass
#   debug_re()
