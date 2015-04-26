#!../venv/bin/python3
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
Begin a TDD version of logparse limited only to auth.log
"""
#
# hash-bang line
# encoding cookie
# licence
# doc string explaining what the module does
# from __future__ imports
# import standard library modules
# import custom modules
from pprint import pprint
from docopt import docopt
from ipwhois import IPWhois
# metadata such as version number
# other constants
# global variables
# custom exception types
# private functions and classes
# public functions and classes
def get_ip_info(ip_addr):
    obj = IPWhois(ip_addr)
    all_ip_info = obj.lookup()
    nets = all_ip_info['nets'][0]
    return dict(
            ip = all_ip_info['query'],
            address = nets.setdefault('address', 'unavailable'),
            city= nets.setdefault('city', 'unavailable'),
            country = nets.setdefault('country', 'unavailable'),
            description = nets.setdefault('description', 'unavailable'),
            state = nets.setdefault('state', 'unavailable'),
            )

# main function
#
if __name__ == '__main__':  # code block to run the application
    ip_info = get_ip_info('76.191.204.54')
    pprint(ip_info)
    pass
#   print("Running Python3 script: 'authparse.py'.......")
#   print('"""', end=''),
#   print(__doc__, end=''),
#   print('"""')

    typical_output = """
{'asn': '7065',
 'asn_cidr': '76.191.192.0/19',
 'asn_country_code': 'US',
 'asn_date': '2007-09-10',
 'asn_registry': 'arin',
 'nets': [{'abuse_emails': 'abuse@sonic.net',
           'address': '2260 Apollo Way',
           'cidr': '76.191.128.0/17',
           'city': 'Santa Rosa',
           'country': 'US',
           'created': '2007-09-10T00:00:00',
           'description': 'SONIC.NET, INC.',
           'handle': 'NET-76-191-128-0-1',
           'misc_emails': None,
           'name': 'SONIC-BLK',
           'postal_code': '95407',
           'range': '76.191.128.0 - 76.191.255.255',
           'state': 'CA',
           'tech_emails': 'noc@sonic.net',
           'updated': '2012-03-02T00:00:00'}],
 'query': '76.191.204.54',
 'raw': None,
 'raw_referral': None,
 'referral': None}
"""

