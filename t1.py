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
test_lines = dict(
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
'Apr 26 00:24:58 dogpatch sshd[12643]: Server listening on 0.0.0.0 port 22.'),
    not_allowed = (
"Apr 26 19:04:31 localhost sshd[16553]: User root from 222.186.134.98 not allowed because none of user's groups are listed in AllowGroups"),
      )
test_line0 = "There is no IP address in this line."
test_line1 = (
'Mar  9 08:12:51 localhost sshd[4522]: Invalid user apache from 202.153.165.67')
test_line2 = (
'May  7 00:09:12 dogpatch sshd[3404]: Invalid user india from 191.237.2.80')
test_line3 = (
'May  6 23:37:57 dogpatch sshd[3392]: Invalid user romanian from 191.237.2.80')
test_line4 = (
'May  6 22:35:17 dogpatch sshd[3346]: Invalid user brazil from 191.237.2.80')
test_line5 = (
'May  6 20:58:22 dogpatch sshd[3273]: Did not receive identification string from 69.236.60.35')
test_line5 = (
'Apr 26 01:20:32 dogpatch sshd[14415]: Accepted publickey for alex from 10.0.0.21 port 33859 ssh2')
test_line5 = (
'Apr 26 01:20:17 dogpatch sshd[14409]: Accepted publickey for alex from 10.0.0.21 port 33850 ssh2')

ip_set = set(('202.153.165.67', '1.93.29.129', '87.106.173.118',
        '76.191.204.54', '61.174.51.208', '202.153.165.67',
        '222.186.134.98', '0.0.0.0'))
# custom exception types
# private functions and classes
# public functions and classes
class InfoTest(unittest.TestCase):
    """Tests VERSION,
            _IP_EXP
            IpDemographics
    """
    test_ips = ["76.191.204.54",   # by Sonic.net dhcp in Bolinas
# Commented out to save time.
#              "173.228.54.112",   # by Sonic.net dhcp in RWC
#              "204.14.156.167",   # by WebPass in San Francisco
#              "89.18.173.13",     # by pcExtreme in Amsterdam
                        ]
    def test_version_authparse(self):
        self.assertEqual(VERSION, authparse.VERSION)
    def test_version_support(self):
        self.assertEqual(VERSION, support.VERSION)
    def test_IpDemographics(self):
        ips = InfoTest.test_ips
        for ip in ips:
            ip_info = authparse.IpDemographics(ip)
            self.assertEqual(ip_info.get_data['ip'], ip)
#           pprint(ip_info)
    def test_IP_EXP(self):
        line = (
        'My IP in Bolinas is 76.191.204.54 provided by Sonic.net.')
        regex = re.compile(authparse._IP_EXP, re.VERBOSE)
        self.assertRegex(line, regex)

class LineTest(unittest.TestCase):
    """Tests get_list_of_ips, 
            get_log_info
    """
    def test_get_list_of_ips_on_random_data(self):
        for i in range(10):
            for n_ips in range(4):
                rl = support.get_random_line(40 + i)
                ips = [support.get_rand_ip() for i in range(n_ips)]
                test_line = support.insert(ips,
                                rl,
                                support.random_locations(n_ips, 40))
                list_of_ips = authparse.get_list_of_ips(test_line)
                self.assertEqual(len(list_of_ips), n_ips)
    def test_get_list_of_ips_on_line1(self):
        list_of_ips = authparse.get_list_of_ips(test_line1)
        self.assertEqual(list_of_ips[0], '202.153.165.67')
    def test_get_ip_on_test_lines(self):
        list = []
        for key in test_lines:
            list.append(authparse.get_ip(test_lines[key]))
        self.assertEqual(set(list), ip_set)
    def test_get_ip_on_line1(self):
        ip = authparse.get_ip(test_line1)
        self.assertEqual(ip, '202.153.165.67')
    def test_get_ip_on_line0(self):
        ip = authparse.get_ip(test_line0)
        self.assertEqual(ip, authparse.DummyIP)
    def test_get_log_info_invalid_user(self):
        res = authparse.get_log_info(test_lines['invalid_user'])
        self.assertEqual((res.line_type, res.key_, res.value, ),
                        ('invalid_user', 'user', "postgres"))
    def test_get_log_info_no_id(self):
        res = authparse.get_log_info(test_lines['no_id'])
        self.assertEqual((res.line_type, res.key_, res.value, ),
                        ('no_id', None, None, ))
    def test_get_log_info_break_in(self):
        res = authparse.get_log_info(test_lines['break_in'])
        self.assertEqual((res.line_type, res.key_, res.value, ),
                        ('break_in', None, None, ))
    def test_get_log_info_pub_key(self):
        res = authparse.get_log_info(test_lines['pub_key'])
        self.assertEqual((res.line_type, res.key_, res.value, ),
                        ('pub_key', 'user', "alex"))
    def test_get_log_info_closed(self):
        res = authparse.get_log_info(test_lines['closed'])
        self.assertEqual((res.line_type, res.key_, res.value, ),
                        ('closed', None, None, ))
    def test_get_log_info_disconnect(self):
        res = authparse.get_log_info(test_lines['disconnect'])
        self.assertEqual((res.line_type, res.key_, res.value, ),
                        ('disconnect', None, None, ))
#   def test_get_log_info_listening(self):
    #   res = authparse.get_log_info(test_lines['listening'])
    #   self.assertEqual((res.line_type, res.key_, res.value, ),
    #                   ('listening', 'server', '???', ))
    def test_get_log_info_not_allowed(self):
        res = authparse.get_log_info(test_lines['not_allowed'])
        self.assertEqual((res.line_type, res.key_, res.value, ),
                        ('not_allowed', 'user', "root"))

class FilesTest(unittest.TestCase):
    """Tests: FileNameCollector
    """
    test_dir = '/home/alex/Py/Logparse/DD/Logs'
    test_list_of_lognames = []
    with open('lognames', 'r')as f:
        for line in f:
            test_list_of_lognames.append(line.strip())
    test_list_of_allfiles = []
    for line in open('allfiles', 'r'):
        test_list_of_allfiles.append(line.strip())
    def test_FileNameCollector_include(self):
        collector = authparse.FileNameCollector(True)
        self.assertTrue(collector.include("file.log"))
#       print("How is restrict2logs set?")
        self.assertFalse(collector.include("file.without.extension"))
    def test_FileNameCollector_default(self):
        collector = authparse.FileNameCollector()
        collector.add2list_of_file_names(FilesTest.test_dir)
        self.assertEqual(set(collector.file_names),
                                    set(FilesTest.test_list_of_allfiles))
    def test_FileNameCollector_restricted(self):
        collector = authparse.FileNameCollector(restrict2logs=True)
        collector.add2list_of_file_names(FilesTest.test_dir)
        self.assertEqual(set(collector.file_names),
                                    set(FilesTest.test_list_of_lognames))

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

class data_collection(unittest.TestCase):
    def test_add2ip_info1(self):
        ip_info = authparse.IpInfo()
        line_info0 = authparse.LineInfo(test_lines['invalid_user'])
        line_info1 = authparse.LineInfo(test_line1)
        line_info2 = authparse.LineInfo(test_line2)
        line_info3 = authparse.LineInfo(test_line3)
        line_info4 = authparse.LineInfo(test_line4)
        ip_info.add_entry(line_info0)
        ip_info.add_entry(line_info1)
        ip_info.add_entry(line_info2)
        ip_info.add_entry(line_info3)
        ip_info.add_entry(line_info4)
        self.assertEqual(ip_info.data['invalid_user'], ["postgres",
        "apache", "india", "romanian", "brazil", ])

    def test_add2ip_dict(self):
        ip_set = set()
        ip = "10.0.0.10"
        ip_set.add(ip)
        master = authparse.IpDict()
        master.add_data(ip,
                authparse.LineInfo(test_lines['invalid_user']))
        self.assertEqual(master.data[ip].data['invalid_user'],
                ['postgres'])
        master.add_data(ip,
                authparse.LineInfo(test_line1))
        self.assertEqual(master.data[ip].data['invalid_user'],
                ['postgres', 'apache', ])
        master.add_data(ip,
                authparse.LineInfo(test_lines['no_id']))
        self.assertEqual(master.data[ip].data['no_id'],
                1)
        ip = "10.1.0.10"
        ip_set.add(ip)
        master.add_data(ip,
                authparse.LineInfo(test_lines['no_id']))
        self.assertEqual(master.data[ip].data['no_id'],
                1)
        self.assertEqual(set([key for key in master.data]),
                        ip_set)
        pass


    def test_master_dict(self):
        master = authparse.IpDict()
        for key in test_lines:
            ip = authparse.get_ip(test_lines[key])
            master.add_data(ip, authparse.LineInfo(test_lines[key]))
        keys = set([key for key in master.data])
        self.assertEqual(keys, ip_set)

class InputCollection(unittest.TestCase):
    """Test authparse.collect_inputs"""
    def setUp(self):
        cmd =("argparser.py -rdki ../DD/Logs " +
            "-w ../DD/Whites -b ../DD/Blacks")
        c_l_args = shlex.split(cmd)
        self.args = docopt(authparse.__doc__,
                        argv=c_l_args[1:],
                        help=True,
                        version=VERSION,
                        options_first=False)
        self.logs_default, self.whites, self.blacks = (
                            authparse.collect_inputs(self.args))
        cmd =("argparser.py -rdkli ../DD/Logs " +
            "-w ../DD/Whites -b ../DD/Blacks")
        c_l_args = shlex.split(cmd)
        self.args = docopt(authparse.__doc__,
                        argv=c_l_args[1:],
                        help=True,
                        version=VERSION,
                        options_first=False)
        self.logs_only, self.whites, self.blacks = (
                            authparse.collect_inputs(self.args))
        pass
    def test_args(self):
        self.assertEqual(self.args["--input"], ["../DD/Logs"])
        self.assertEqual(self.args["--white"], ["../DD/Whites"])
        self.assertEqual(self.args["--black"], ["../DD/Blacks"])
    def test_collect_blacks(self):
        self.assertEqual(set(self.blacks),
                        set(['/home/alex/Py/Logparse/DD/Blacks/black1',
                            ]))
    def test_collect_whites(self):
        self.assertEqual(set(self.whites),
                        set(['/home/alex/Py/Logparse/DD/Whites/white1',
                            ]))
    def test_collect_logs_default(self):
        self.assertEqual(set(self.logs_default), set([
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
    def test_collect_logs_only(self):
        self.assertSequenceEqual(set(self.logs_only), set([
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

class MoveInfoSources2Master(unittest.TestCase):
    def setUp(self):
        cmd = "argparser.py -rdki ../DD/Sources "
        c_l_args = shlex.split(cmd)
        self.args = docopt(authparse.__doc__,
                        argv=c_l_args[1:],
                        help=True,
                        version=VERSION,
                        options_first=False)
        self.logs_default, _whites, _blacks = (
                            authparse.collect_inputs(self.args))
    def testMove2Master(self):
        ip_dict = authparse.IpDict()
        authparse.move_info_sources2master(self.logs_default, ip_dict)
        self.assertEqual(True, True)
        print(ip_dict.show)


# main function
#
if __name__ == '__main__':  # code block to run the application
    unittest.main()

