#!venv/bin/python3
# -*- coding: utf-8 -*-
# vim: set file encoding=utf-8 :
#
# file: 'support.py'
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
Random insertions into strings.
"""
# from __future__ imports
# import standard library modules
import random
# import custom modules
# metadata such as version number
VERSION = "v0.0.1"
# other constants
insert_list = [c*3 for c in """@#$%^&>~<*=+;:'`!()_-'"?|.,"""]

# global variables
# custom exception types
# private functions and classes
# public functions and classes
# main function
def random_locations(n, length):
    """Returns a sorted list of n unique numbers
    each of which is in the range of 0...length.
    """
    assert (n <= (length + 1))
    n_set = set()
    while len(n_set) < n:
        n_set.add(random.randrange(length+1))
    return sorted(n_set)

def insert(insertion, line, locations):
    """Inserts <insertion> into <line> at <locations>,
    an ordered iterable of integers.
    The first parameter can be a string or a list of strings.
    If it is a list, it must have length no less than length of the last
    parameter.  If not a list, the same string will be inserted at each
    location.
    There can not be more insertion locations than line length plus one.
    Returns the resulting string.
    """
    assert (len(locations) <= (len(line) + 1))
    splits = []
    start = 0
    for i in range(0, len(locations)):
        next_part = line[start:locations[i]]
        splits.append(next_part)
        start= locations[i]
    next_part = line[start:len(line)]
    splits.append(next_part)
    if isinstance(insertion, str):
        ret = (insertion.join(splits))
    else:  # <insertion> is an iterable.
        ret = [splits[0]]
        i = 1
        while i < len(splits):
            ret.append(insertion[i-1])
            ret.append(splits[i])
            i += 1
        ret = ''.join(ret)
    return ret

def get_rand_ip():
    parts = []
    for _ in range(4):
        # I chose not to have 255 returned (broadcast.)
        str1_255 = str(random.randrange(1, 255))
        parts.append(str1_255)
    ip = ' ' + '.'.join(parts) + ' '
#   print("IP being returned: {}".format(ip))
    return ip

def get_random_line(length):
    return (
    ''.join([chr(random.randrange(65, 91)) for i in range(length)]))


def main():
    pass

def main0():
    print("exercise get_random_line...")
    for _ in range(4):
        l = random.randrange(30, 41)
        print("len: {}; line: {}"
                .format(l, get_random_line(l)))

    print("\nexercise get_rand_ip...")
    for _ in range(4):
        print(get_rand_ip())

    print("\nexercise random_locations..")
    for l in range(10):
        for n in range(l+2):
            print(".. n&l set to {} & {}: {}"
                    .format(n, l, random_locations(n, l)))

    print("\nexercise insert(insertion, line, locations)...")
    my_line = (
        'The big brown cow jumped over the moon while the fox ran away.')
    for l in range(10):
        for n in range(l+2):
            locations = random_locations(n, l)
            print(".. n&l set to {} & {}: {}"
                    .format(n, l, locations))
            print(insert(insert_list, my_line[:l], locations))

def main2():
    print(random_locations(0, 10))
    s = "hello world!"
    insertion = 'SPACE'
    LAST = len(s) + 1
    locations = [1, 4,  7, 11]
#   print(insert(insertion, s, locations))

def main3():
    rand3_11 = random_locations(3,11)
    print("Three random locations out of a possible 11: {}"
                    .format(rand3_11))
    cow = "How now brown cow."
    print("cow length is {}.".format(len(cow)))
    rand3_len_cow = random_locations(3,len(cow))
    print("Random locations picked for cow are {}"
                .format(rand3_len_cow))
    print(insert("**", cow, 
                random_locations(3, len(cow))))

    for i in range(30):
        rl = (random_locations(4, len(cow)))
        print(rl, '  ', insert(insert_list, cow, rl))

    print(random_locations(5, 4))
    print(insert('*', 'Alex', random_locations(5, 4)))
    
    for i in range(4):
        print(get_random_line(58))
    
    ip = get_rand_ip()
    print("a random ip: {}".format(ip))

if __name__ == '__main__':  # code block to run the application
    print("insert list is {}".format(insert_list))
#   print("Running Python3 script: 'junk.py'.......")
#   print('"""', end=''),
#   print(__doc__, end=''),
#   print('"""')
    main()

