#!./venv/bin/python3
# -*- coding: utf-8 -*-
# vim: set file encoding=utf-8 :
#
# file: 't1.py'
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
First test of ./src/authparse.py
"""
# import standard library modules
import re
import random
import unittest
import shlex
from pprint import pprint
# import custom modules
from docopt import docopt
import support
from src import authparse
# metadata such as version number
VERSION = "v0.0.0"
# other constants
# global variables

# invalid_user, no_id, break_in, pub_key, closed, disconnect, listening
log_dict = dict(
    invalid_user = (
'Mar  9 08:12:51 localhost sshd[4522]: Invalid user postgres from 202.153.165.67'),
    no_id = (
'Mar  9 06:48:15 localhost sshd[4513]: Did not receive identification string from 1.93.29.129'),
    break_in = (
'Apr 27 00:43:04 localhost sshd[16849]: reverse mapping checking getaddrinfo for canariosdelmundo.com [87.106.173.118] failed - POSSIBLE BREAK-IN ATTEMPT!'),
    pub_key = (
'Apr 28 03:52:20 localhost sshd[21641]: Accepted publickey for alex from 76.191.204.54 port 61583 ssh2'),
    closed = (
'Mar  9 09:47:15 localhost sshd[4561]: Connection closed by 61.174.51.208 [preauth]'),
    disconnect = (
'Mar  9 08:12:56 localhost sshd[4526]: Received disconnect from 202.153.165.67: 11: Bye Bye [preauth]'),
    listening = (
''),
    # Couldn't find a 'Server listening on' line. 
    not_allowed = (
"Apr 26 19:04:31 localhost sshd[16553]: User root from 222.186.134.98 not allowed because none of user's groups are listed in AllowGroups"),
      )

# custom exception types
# private functions and classes
# public functions and classes
class InfoTest(unittest.TestCase):
    """Tests VERSION,
            _IP_EXP
            get_ip_info
    """
    test_ips = ["76.191.204.54",   # by Sonic.net dhcp in Bolinas
# Commented out to save time.
#              "173.228.54.112",   # by Sonic.net dhcp in RWC
#              "204.14.156.167",   # by WebPass in San Francisco
#              "89.18.173.13",     # by pcExtreme in Amsterdam
                        ]
    def test_version(self):
        self.assertEqual(VERSION, authparse.VERSION)
        self.assertEqual(VERSION, support.VERSION)
    def test_get_ip_info(self):
        ips = InfoTest.test_ips
        for ip in ips:
            ip_info = authparse.get_ip_info(ip)
            self.assertEqual(ip_info['ip'], ip)
            pprint(ip_info)
    def test_IP_EXP(self):
        line = (
        'My IP in Bolinas is 76.191.204.54 provided by Sonic.net.')
        regex = re.compile(authparse._IP_EXP, re.VERBOSE)
        self.assertRegexpMatches(line, regex)

class LineTest(unittest.TestCase):
    """Tests get_list_of_ips, 
            get_log_info
    """
    def test_get_list_of_ips(self):
        for i in range(10):
            for n_ips in range(4):
                rl = support.get_random_line(40 + i)
                ips = [support.get_rand_ip() for i in range(n_ips)]
                test_line = support.insert(ips,
                                rl,
                                support.random_locations(n_ips, 40))
                list_of_ips = authparse.get_list_of_ips(test_line)
                self.assertEqual(len(list_of_ips), n_ips)
    def test_get_log_info(self):
        res = authparse.get_log_info(log_dict['invalid_user'])
        self.assertEqual(res[0], 'invalid_user')
        self.assertEqual(res[1]["user"][0], "postgres")
        res = authparse.get_log_info(log_dict['no_id'])
        self.assertEqual(res[0], 'no_id')
        print(res[1])
        self.assertEqual(res[1], {})
        res = authparse.get_log_info(log_dict['break_in'])
        self.assertEqual(res[0], 'break_in')
        self.assertEqual(res[1], {})
        res = authparse.get_log_info(log_dict['pub_key'])
        self.assertEqual(res[0], 'pub_key')
        self.assertEqual(res[1]["user"][0], "alex")
        res = authparse.get_log_info(log_dict['closed'])
        self.assertEqual(res[0], 'closed')
        self.assertEqual(res[1], {})
        res = authparse.get_log_info(log_dict['disconnect'])
        self.assertEqual(res[0], 'disconnect')
        self.assertEqual(res[1], {})
    #   res = authparse.get_log_info(log_dict['listening'])
    #   self.assertEqual(res[0], 'listening')
    #   self.assertEqual(res[1], {'server'})
        res = authparse.get_log_info(log_dict['not_allowed'])
        self.assertEqual(res[0], 'not_allowed')
        self.assertEqual(res[1]["user"][0], "root")

class FilesTest(unittest.TestCase):
    """Tests: select_logs
    """
    test_list_of_logfiles = ['a.log', 'auth.log', 'auth.log.1',
                            'auth.log.2', 'auth.log.3',
                            'auth.log.4', 'fail.log', 'beaware',]
    def test_select_logs(self):
        file_names = FilesTest.test_list_of_logfiles
        files = authparse.select_logs(file_names)
        non_log = ['beaware',]
        qualified = (
        [name for name in file_names if not name in non_log])
        self.assertEqual(files, qualified)

class ArgsTest(unittest.TestCase):
    """Test the command line argument/docopt componenet:
    def test_get_args0(self):  # template
        cmd = "" 
        c_l_args = shelx.split(cmd)
        args = docopt(authparse.__doc__,
                        argv=c_l_args[1:],
                        help=True,
                        version=VERSION,
                        options_first=False)
        assert args['--help'] == 
        assert args['--version'] ==
        assert args['--report'] == 
        assert args['--demographics'] == 
        assert args['--quiet'] == 
        assert args['--known'] == 
        assert args['--white'] == []
        assert args['--black'] == []
        assert args['--input'] == []
        assert args['--output'] == 
        assert args['--frequency'] == 
    """
    def test_get_args3(self):
        cmd ="argparser.py -rdqki auth.log -o output.txt" 
        c_l_args = shlex.split(cmd)
        args = docopt(authparse.__doc__,
                        argv=c_l_args[1:],
                        help=True,
                        version=VERSION,
                        options_first=False)
        self.assertEqual(args['--help'], False)
        self.assertEqual(args['--version'], False)
        self.assertEqual(args['--report'],  1)
        self.assertEqual(args['--demographics'], True)
        self.assertEqual(args['--quiet'], True)
        self.assertEqual(args['--known'], True)
        self.assertEqual(args['--white'], [])
        self.assertEqual(args['--black'], [])
        self.assertEqual(args['--input'], ['auth.log'])
        self.assertEqual(args['--output'], 'output.txt')
        self.assertEqual(args['--frequency'], False)

class TestFileNameCollector(unittest.TestCase):
    """Tests/exercises: FileNameCollector
            it's add2list_of_file_names method,
            and it's file_names attribute.
    """
    def test_dir_of_logs0(self):
        cmd ="argparser.py -i '~/Py/Logparse/DD/Logs' -o output.txt" 
        c_l_args = shlex.split(cmd)
        args = docopt(authparse.__doc__,
                        argv=c_l_args[1:],
                        help=True,
                        version=VERSION,
                        options_first=False)
        log_file_collector = authparse.FileNameCollector()
        for dir_or_file in args["--input"]:
            log_file_collector.add2list_of_file_names(dir_or_file)
        self.assertEqual(sorted(log_file_collector.file_names), sorted([
            "/home/alex/Py/Logparse/DD/Logs/a.log",
            "/home/alex/Py/Logparse/DD/Logs/auth.log",
            "/home/alex/Py/Logparse/DD/Logs/auth.log.1",
            "/home/alex/Py/Logparse/DD/Logs/auth.log.2",
            "/home/alex/Py/Logparse/DD/Logs/auth.log.3",
            "/home/alex/Py/Logparse/DD/Logs/auth.log.4",
            "/home/alex/Py/Logparse/DD/Logs/fail.log",
            "/home/alex/Py/Logparse/DD/Logs/not_l_o_g_file",
            "/home/alex/Py/Logparse/DD/Logs/SubLog/SubLogSubLog/subsub.log",
            "/home/alex/Py/Logparse/DD/Logs/SubLog/SubLogSubLog/subsub.log.1",
            "/home/alex/Py/Logparse/DD/Logs/SubLog/SubLogSubLog1/subsub1.log",
            "/home/alex/Py/Logparse/DD/Logs/SubLog/SubLogSubLog1/subsub1.log.1",
                ]))
        log_file_collector = authparse.FileNameCollector(True)
        log_file_collector.add2list_of_file_names(dir_or_file)
        self.assertEqual(sorted(log_file_collector.file_names), sorted([
            "/home/alex/Py/Logparse/DD/Logs/a.log",
            "/home/alex/Py/Logparse/DD/Logs/auth.log",
            "/home/alex/Py/Logparse/DD/Logs/auth.log.1",
            "/home/alex/Py/Logparse/DD/Logs/auth.log.2",
            "/home/alex/Py/Logparse/DD/Logs/auth.log.3",
            "/home/alex/Py/Logparse/DD/Logs/auth.log.4",
            "/home/alex/Py/Logparse/DD/Logs/fail.log",
            "/home/alex/Py/Logparse/DD/Logs/SubLog/SubLogSubLog/subsub.log",
            "/home/alex/Py/Logparse/DD/Logs/SubLog/SubLogSubLog/subsub.log.1",
            "/home/alex/Py/Logparse/DD/Logs/SubLog/SubLogSubLog1/subsub1.log",
            "/home/alex/Py/Logparse/DD/Logs/SubLog/SubLogSubLog1/subsub1.log.1",
                ]))

# main function
#
if __name__ == '__main__':  # code block to run the application
    pass

