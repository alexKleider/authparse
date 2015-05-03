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
        keys =  ["user"]
        ),
    no_id = dict(
        re =  (r"""Did not receive identification string from \S+"""),
        header_text =  "'auth.log' reporting 'no id's:",
        keys =   []
        ),
    break_in = dict(
        re =  r"POSSIBLE BREAK-IN ATTEMPT!",
        header_text =  (
            "'auth.log' reporting 'POSSIBLE BREAK-IN ATTEMPT!'s:"),
        keys =   []
        ),
    pub_key = dict(
        re =  r""" Accepted publickey for (?P<user>\S+)""",
        header_text =  "'auth.log' reporting ''s:",
        keys =   ["user"]
        ),
    closed = dict(
        re =  r""" Connection closed by \S+""",
        header_text =  "'auth.log' reporting 'closed's:",
        keys =   []
        ),
    disconnect = dict(
        re =  (
                r""" Received disconnect from """),
        header_text =  (
                "'auth.log' reporting 'Received disconnect from's:"),
        keys =   []
        ),
    listening = dict(
        re =  r""" Server listening on (?P<listener>.+)""",
        header_text =  "'auth.log' reporting 'Server listening on's:",
        keys =   ["listener"]
        ),
    not_allowed = dict(
        re = r""" User (?P<user>\S+) from (?:\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}) not allowed because none """,
        header_text = "'auth.log' reporting ''s:",
        keys = ["user"]
        ),
    unrecognized = dict(  # Besure this key is alphabetically last!
        re = ".*",
        header_text = "Unrecognized line.",
        keys = []
        ),
    )


_line_types = sorted(SPoL)
# invalid_user, no_id, break_in, pub_key,
# closed, disconnect, listening, not_allowed
# unrecognized
# noip

for key in _line_types:
    SPoL[key]['search4'] = re.compile(SPoL[key]['re'])

# custom exception types  (I have none)
# private functions and classes
# public functions and classes

class FileNameCollector(object):
    def __init__(self, restrict2logs=False):
        self.file_names = []
        self.restrict2logs = restrict2logs
    def add2list_of_file_names(self, f_or_dir_name):
        f_or_dir_name = os.path.abspath(
                            os.path.expanduser(
                                f_or_dir_name))
        if os.path.isfile(f_or_dir_name):
            self.file_names.append(f_or_dir_name)
        elif os.path.isdir(f_or_dir_name):
            for path, dirs, files in os.walk(f_or_dir_name):
                if self.restrict2logs:
                    restricted_files = select_logs(files)
                else:
                    restricted_files = files
                for f in restricted_files:
                    self.file_names.append(os.path.join(path, f))
        else:
            print(
            "Non-existing file name passed to FileNameCollector method.")

class Ip_Info(object):
    """An instance of this type is used to collect information about
    each IP address that appears in the log (/var/log/authlog) files.
    It is a dict keyed by the IP address.
    Each value is also a dict keyed by the contents of _line_types
    derived from SPoL in which it
    appeared. Note there is also an "unrecognized" line type, the default
    if none of the others match.
    The corresponding value for each of these keys is a list, one for
    each time that line type was encountered.  The list contents are in
    turn a list of the values, often empty.  Summing the number of
    lists for each line type provides a count for each IP address.
    {ipaddr: 
        {line_type:
            { # dict, often empty, currently never > 1 key.
            key(so far only "user" or "listener"):
                    [list of names or other info bits],
            }
        }
    }
    """
    def __init__(self):
        data = {}
    def add_entry(self, ip, info):
        """<ip> is an IP address- key in top level of <data>.
        <info> is the tuple returned by <get_log_info>:
            [0]: line_type
            [1]: group_dict: (often empty)
                key (if any): ('user', 'listener', ...)
                The value of each key is added to the list of values
                for the corresponding key 
        """
        pass


def get_args():
    return docopt(__doc__, version=VERSION)

def get_list_of_ips(line):
    """Returns a list (possibly empty) of all ipv4 addresses found in
    the line.
    """
    return _findall_ips(line)


def get_ip_info(ip_addr, NO_INFO = "NO_INFO"):
    """First parameter must be an IP address (as a dotted quad.)
    Returns a dictionary with the following keys:
        ip, description, city, address, state, country.
    An alternative default value can be set in case the response
    has no entry for one of the fields expected.
    """
    obj = IPWhois(ip_addr)
    all_ip_info = obj.lookup()
    nets = all_ip_info['nets'][0]
    return dict(
            ip = all_ip_info.setdefault('query', NO_INFO),
            address = nets.setdefault('address', NO_INFO),
            city= nets.setdefault('city', NO_INFO),
            country = nets.setdefault('country', NO_INFO),
            description = nets.setdefault('description', NO_INFO),
            state = nets.setdefault('state', NO_INFO),
            )

def get_log_info(line):
    """<line> is assumed to be a log file line.
    Returns a tuple: line_type, data_gleaned.  
        line_type: one of the keys of SPoL.
        group_dic: a dictionary, possibly empty.
             Currently there is never >1 item in the dictionary.
             Possible keys are 'user', 'listener', ..
             and only one value each. NOTE: in the IP_Info class
             instance, the corresponding value is a list of values
             collected by this procedure.
    !!!Returns None if line is not a recognized log entry.
    """
    for line_type in _line_types :  # Assume a line can only be of 1 type.
        search_result = SPoL[line_type]['search4'].search(line)
        if search_result:  # Used search so will get 0 or 1 match object.
            group_dic = {}
            info_provided = SPoL[line_type]['keys']
            for item in info_provided:  # May well be none.
                group_dic[item] = search_result.groups(item)
            return (line_type, group_dic, )

def select_logs(list_of_files):
    return [f_name for f_name in list_of_files if 'log' in f_name]

def get_list_of_file_names(list_of_sources):
    """
    The parameter is an iterable of file (regular or directory) names.
    Returned is a list of the full path names of all files.
    """
    file_name_collector = FileNameCollector()
    for f_or_dir in list_of_sources:
        file_name_collector.add2list_of_file_names(f_or_dir)
    return file_name_collector.file_names

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

def get_ips_with_info(list_of_sources):
    """
    Parameter is an iterable of file (regular or directory) names.
    Returned is a dict keyed by the first (if any) IP address found
    in any line contained in the files.  Each key's value is an 
    instance of IpInfo.
    The parameter is typically the list of log files to analyse.
    """
    ret = {}
    f_names = get_list_of_file_names(list_of_sources)
    for f_name in f_names:
        for line in open(f_name, 'r'):
            ips = _findall_ips(line)
            if ips:
                ip = ips[0]
                data = get_log_info(line)
                if data:
                    line_type, group_dict = data
                else:
                    line_type = 'unrecognized'
                    group_dict = None
    pass

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

#
if __name__ == '__main__':  # code block to run the application
    ip_info = get_ip_info('76.191.204.54')
    pprint(ip_info)
