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
  logparser3.py --input <ifile>... 
                [-adfqkl] 
                [-r | -rr ]
                [--white <wfile>...]
                [--black <bfile>...]
                [--output <ofile>]
                [--list_all]

Options:
  -h --help  Print the __doc__ string.
  --version  Print the version number.
  -r --report  How much to report about the IP addresses.
          0 - Addresses alone.
          1 - Addresses and number of times each one appeared.
          2 - Addresses, number of appearances, type of appearances,
                and additional information if available.
  -a --list_all  Over ride the default which is to remove from the report
                any IP addresses that are white or black listed.
  -d --demographics  Include location/origin of IP if possible.
  -f --frequency   Sort output by frequency of appearance of IPs
                    (Default is by IP.)
  -k --known  Report any known ('white' or 'black') IPs that appeared
                in the input and may or may not have been removed from
                the output, depending on the --list_all option.
  -l --logsonly  Set this flag if only those input files containing the
                string designated by the constant LOG are to be
                included.
  -q --quiet  Supress reporting of success list, file access errors,
                or files devoid of IPs.
  -w --white=<wfile>  Specify 0 or more files containing white listed IPs.
  -b --black=<bfile>  Specify 0 or more files containing black listed IPs.
  -i --input=<ifile>  Specify 1 or more input files.
                    These are typically auth.log files but don't have to be.
                    If a specified file is a directory, all files beneath
                    that directory are considered as though separately
                    specified.  (See -l/--logsonly option.)
  -o --output=<ofile>  Specify output file, otherwise std out is used.

Any known IPs can be provided in files specified as containing either
'--black' or '--white' listed IPs.  These are also read and any IP
addresses found will NOT be included in the output unless the
-a/--list_all option is set.  (See the -k/--known option which causes
this to be reported.) Typically this would be useful if you have a 'white'
list of known IPs you would definitely NOT want to block and/or if you
had a 'black' list of already blocked IPs which you'd have no need to
block again.  Keep in mind that it should not be possible to have a black
listed IP address appear in log files if it has in fact been blocked.

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
import ipwhois
# Alternatively, could use http://freegeoip.net
# and a google maps API is also available:
# https://github.com/googlemaps/

# metadata such as version number
VERSION = "v0.0.0"

# other constants
DummyIP = '0.0.0.0'
LOG = "log"  # Used by FileNameCollector class.
             # Reference to it is made in __doc__.
# To retrieve (ipv4) IP addresses from a line:
_IP_EXP = \
r"""
\b
\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}
"""

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
    # invalid_user, no_id, break_in, pub_key, closed,
    # disconnect, listening, not_allowed, unrecognized
    # Was going to include noip but decided to keep
    # presence or absence of IP at a separate level:
    # Use the string constant DummyIP as the indicator
    # that no IP was discovered.  This functionality is
    # implemented in public function get_ip(line).

for key in _line_types:
    SPoL[key]['search4'] = re.compile(SPoL[key]['re']).search

# custom exception types  (I have none)

# private functions and classes
_findall_ips = re.compile(_IP_EXP, re.VERBOSE).findall

def _get_args():
    """Uses docopt to return command line arguments.
    """
    return docopt(__doc__, version=VERSION)

# public functions and classes:

class FileNameCollector(object):
    """Maintains a list of file names by providing an
    <add2list_of_file_names> method.
    A named parameter <restrict2logs> can be set to True if
    one wants to include only files with names containing the
    string defined by the constant LOG.
    Has its own include(self, f_name) method => Boolean
    which checks status of <restrict2logs>.
    """
    def __init__(self, restrict2logs=False):
        self.file_names = []
        self.restrict2logs = restrict2logs
    def include(self, f_name):
        if self.restrict2logs and not(LOG in f_name):
            return False
        else:
            return True
    @property
    def get_file_names(self):
        return self.file_names
    def add2list_of_file_names(self, f_or_dir_name):
        f_or_dir_full_name = os.path.abspath(
                            os.path.expanduser(
                                f_or_dir_name))
#       print('{} => {}'.format(f_or_dir_name, f_or_dir_full_name))
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
            pass

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
    Instances are kept in a dict keyed by the IP address  BUT
    don't themselves include the IP address
    They consist of a dict keyed by line_type.
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
    def frequency(self):
        ret = 0
        for line_type in self.data.keys():
            val = self.data[line_type]
            if isinstance(val, int):
                ret += val
            else:
                ret += len(val)
        return ret
    def show(self, args, ip='IP unspecified'):
        ret = []
        if args['--demographics']:
            demographics = GeoIP(ip)
            ret.append(demographics.show())
        else:
            ret.append("{}".format(ip))
        if args['--report']:
            ret.append("  Appearances: {}.".format(self.frequency()))
            if args['--report'] > 1:
                keys = self.data.keys()
                sortable_keys = (
                        [k for k in keys if k != None])
                sorted_keys = sorted(sortable_keys)
                if None in keys:
                    ret.append("    Unspecified: {}."
                                .format(self.data[None])) # an int
                for line_type in sorted_keys:
                    if isinstance(self.data[line_type], int):
                        ret.append("    {}: {}."
                            .format(line_type,
                                    self.data[line_type]))
                    else:
                        ret.append("    {}: {}. =>{}"
                            .format(line_type,
                                    len(self.data[line_type]),
                                    self.data[line_type]))
                pass
        return '\n'.join(ret)

class IpDict():
    """An instance is used to maintain all information gleaned from
    the log files. It is implemented as a dictionary keyed by IP
    with values consisting of IpInfo instances.
    """
    def __init__(self):
        self.data = {}
    def add_data(self, ip_address, ip_info):
        """Adds information from an instance of LineInfo into it's
        dictionary, creating an instance of IpInfo if needed.
        """
        __0 = self.data.setdefault(ip_address, IpInfo())
        self.data[ip_address].add_entry(ip_info)
    def populate_from_source_files(self, list_of_source_files):
        """
        <list_of_source_files> is an iterable of file names
        from which new information is gathered and added to 
        self.data.          (See collect_inputs(args).)
        Returned is a list, possibly empty, of the
        names of files that did NOT contain any IP addresses.
        """
        files_without_ips = []
        for f_name in list_of_source_files:
            no_ips_found = True
            with open(f_name, 'r') as f:
                for line in f:
                    ip = get_ip(line)
                    if ip == DummyIP:
                        line_info = LineInfo(None)
                    else:
                        line_info = LineInfo(line)
                        no_ips_found = False
                    self.add_data(ip, line_info)
                if no_ips_found:
                    files_without_ips.append(f_name)
        return files_without_ips

    @property
    def sorted_ips(self):
        return sorted(self.data.keys(), key=sortable_ip) 
    @property
    def ip_frequencies(self):
        frequencies = {}
        for ip in self.data.keys():
            frequency = 0
            ip_info = self.data[ip]  # Instance of IpInfo
            for line_type in ip_info.data.keys():
                if isinstance(ip_info.data[line_type], int):
                    frequency += ip_info.data[line_type]
                else:  # the None key
                    frequency += len(ip_info.data[line_type])
            frequencies[ip] = frequency
        return frequencies
    @property
    def frequency_sorted_ips(self):
        ip_f_dict = self.ip_frequencies
        def val(k):
            return ip_f_dict[k]
        low2high = sorted(self.data.keys(), key=val)
        return reversed(low2high)
    def show(self, args):
        """Relevant args:
        --report [0..2]:
        --demographics:
        --frequency:
        """
        ret = []
        if args['--frequency']:
            sorted_ips = self.frequency_sorted_ips
        else:
            sorted_ips = self.sorted_ips
        for ip in sorted_ips:
            ip_info = self.data[ip]
            ret.append(ip_info.show(args, ip))
        return '\n'.join(ret)

class GeoIP(object):
    """Instances discover and keep demographics of an IP address
    provided to the __init__ as a dotted quad."""
    def __init__(self, ip_addr, NO_INFO="unavailable"):
        try:
            obj = ipwhois.IPWhois(ip_addr)
        except ipwhois.ipwhois.IPDefinedError as message:
            self.data = dict(ip= ip_addr, address= '',
                city= '', country= '',
                description= message, state= '')
            return
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
            if self.data[k]:
                ss = self.data[k].split('\n')
                s = ', '.join(ss)
                self.data[k] = s
    def __repr__(self):
        return """IP {ip}: {description}
    {address}, {city}, {state}, {country}""".format(**self.data)
    def show(self):
        return self.__repr__()
    @property
    def get_data(self):
        return self.data

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

def get_ips(list_of_sources, list_of_files_without_ips=[]):
    """
    The parameter is an iterable of regular file names.
    Returned is the set of all IP addresses contained in the files.
    The parameter would typically be the list of white or black files
    returned by the second and third items in the three tuple returned
    by collect_inputs(args).
    An optional parameter can be used to collect names of those source
    files that do not contain any recognizable IP addresses.
    """
    ret = set()
    for f_name in list_of_sources:
        no_ips_found = True
        with open(f_name, 'r') as f:
            for line in f:
                ips = _findall_ips(line)
                if ips:
                    no_ips_found = False
                    for ip in ips:
                        ret.add(ip)
        if no_ips_found:
            list_of_files_without_ips.append(f_name)
    return ret

def sortable_ip(ip):
    """Takes am IP address of the form 50.143.75.105
    and returns it in the form 050.143.075.105.
    ... useful as a key function for sorting.
    Quietly returns None if parameter is bad."""
    parts = ip.strip().split('.')
    if not len(parts)==4:
        return None
    else: 
        return (
        "{0[0]:0>3}.{0[1]:0>3}.{0[2]:0>3}.{0[3]:0>3}".format(parts)
                )

def sorted_ips(ip_list):
    """Takes an iterable of IP addresses and 
    returns the same addresses as a sorted list.
    """
    return sorted(ip_list, key=sortable_ip)

def collect_inputs(args):
    """Returns a three tuple of lists:
    The log files, files containing white listed IPs,
    and files containing black listed IPs.
    These are selected from the command line arguments.
    """
    logs_collector = FileNameCollector(args['--logsonly'])
    for fname in args["--input"]:
        logs_collector.add2list_of_file_names(fname)

    white_collector = FileNameCollector()
    for fname in args["--white"]:
        white_collector.add2list_of_file_names(fname)

    black_collector = FileNameCollector()
    for fname in args["--black"]:
        black_collector.add2list_of_file_names(fname)

    return (logs_collector.get_file_names,
            white_collector.get_file_names,
            black_collector.get_file_names,
            )

def show_file_list(file_list, indentation = 0):
    indented_list = [(' ' * indentation) + f for f in file_list]
    return '\n'.join(indented_list)

def subreport(header, iterable, indentation = (0, 4)):
    """Returns a string consisting of the header at the top
    followed by a listing of iterable, one per line.
    The listing is indented by the number of spaces specified.
    If iterable is empty, None is returned"""
    if iterable:
        ret = [''.join(((' ' * indentation[0]), header, ))]
        for item in iterable:
            item = ''.join(((' ' * indentation[1]), item))
            ret.append(item)
        return '\n'.join(ret)
    else:
        return None

def get_no_ips_report(iterable_of_name_list_tuples):
    """Returns a report in the form of a string,
    returns None if there is nothing to report."""
    subreports = []
    for header, file_names in iterable_of_name_list_tuples:
        subreports.append(subreport(header, file_names, (2, 4)))
    if subreports:
        sub_report = '\n'.join(('Files with no IP addresses:',
          '\n'.join([_report for _report in subreports if _report])))
        return sub_report
    else:
        return None


# main function
def main():
    report = ["<authparse> REPORT", ]
    white_files_without_ips = []
    black_files_without_ips = []
    args = _get_args()
    logs, whites, blacks = collect_inputs(args)
    white_ips = get_ips(whites, white_files_without_ips)
    black_ips = get_ips(blacks, black_files_without_ips)
    masterIP_dict = IpDict()
    log_files_without_ips = (
            masterIP_dict.populate_from_source_files(logs))
    if not args["--quiet"]:
        name_list_tuples = (
                ('White:', white_files_without_ips),
                ('Black:', black_files_without_ips),
                ('Logs:', log_files_without_ips),
                )
        subreport = get_no_ips_report(name_list_tuples)
        if subreport:
            report.append(subreport)
    print('\n'.join(report))


if __name__ == '__main__':  # code block to run the application
    main()
    pass
