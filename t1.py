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
# import custom modules
from src.authparse import get_ip_info
import unittest
# metadata such as version number
VERSION = "v0.0.0"
# other constants
# global variables
# custom exception types
# private functions and classes
# public functions and classes
class IPInfoTest(unittest.TestCase):
    def test_get_ip_info(self):
        ip = "76.191.204.54"
        ip_info = get_ip_info(ip)
        assert ip_info['ip'] == ip

# main function
#
if __name__ == '__main__':  # code block to run the application
    pass
#   print("Running Python3 script: 't1.py'.......")
#   print('"""', end=''),
#   print(__doc__, end=''),
#   print('"""')


