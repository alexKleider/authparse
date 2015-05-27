#authparse.py

The following is an excerpt from its docstring:

"""
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
                [-dfqkl] 
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
  -a --list_all   Over ride the default which is to remove from the
                report any IP addresses that are white or black listed.
  -d --demographics  Include location/origin of IP if possible.
  -f --frequency   Sort output by frequency of appearance of IPs
                    (Default is by IP.)
  -k --known  Report any known ('white', 'black' or public) IPs that
                appeared in the input/log files and may or may not have
                been removed from the output, depending on the
                "--list_all" option.
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

Additional Notes:
Any known IPs can be provided in files specified as containing either
'--black' or '--white' listed IPs.  These are also read and any IP
addresses found will by default (unless the -a/--list_all option is set)
NOT be included in the output.  (See the -k/--known option which causes
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
