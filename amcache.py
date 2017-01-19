#!/usr/bin/python
#    This file is part of python-registry.
#
#   Copyright 2015 Will Ballenthin <william.ballenthin@mandiant.com>
#                    while at Mandiant <http://www.mandiant.com>Exe
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.

import sys
import logging
import datetime
from collections import namedtuple
import argparse
import unicodecsv
from Registry import Registry
from Registry.RegistryParse import parse_windows_timestamp as _parse_windows_timestamp
from parserutility import utility
import os
import re

g_logger = logging.getLogger("amcache")
Field = namedtuple("Field", ["name", "getter", "collname"])

def make_value_getter(value_name):
    """ return a function that fetches the value from the registry key """
    def _value_getter(key):
        try:
            return key.value(value_name).value()
        except Registry.RegistryValueNotFoundException:
            return None
    return _value_getter

def make_windows_timestamp_value_getter(value_name):
    """
    return a function that fetches the value from the registry key
      as a Windows timestamp.
    """
    f = make_value_getter(value_name)
    def _value_getter(key):
        try:
            return parse_windows_timestamp(f(key) or 0)
        except ValueError:
            return datetime.datetime.min
    return _value_getter

def parse_unix_timestamp(qword):
    if (qword) == 0:
        return ""
    try:
        return datetime.datetime.fromtimestamp(qword)
    except ValueError:
        return ""

def parse_windows_timestamp(qword):
    try:
        return utility().get_timestamp_str(qword)
    except ValueError:
        return ""

def make_unix_timestamp_value_getter(value_name):
    """
    return a function that fetches the value from the registry key
      as a UNIX timestamp.
    """
    f = make_value_getter(value_name)
    def _value_getter(key):
        try:
            return parse_unix_timestamp(f(key) or 0)
        except ValueError:
            return ""
    return _value_getter

UNIX_TIMESTAMP_ZERO = parse_unix_timestamp(0)
WINDOWS_TIMESTAMP_ZERO = parse_windows_timestamp(0)

def make_timezone_getter():
    return utility().get_timezone_str()

def make_trimming_timstamp(timestamp):
    trimed_timestamp = timestamp.strftime('%Y/%m/%d %H:%M:%S')
    ms = "%03d"%(timestamp.microsecond / 1000.0)
    return trimed_timestamp + "." + ms

# via: http://www.swiftforensics.com/2013/12/amcachehve-in-windows-8-goldmine-for.html
#Product Name    UNICODE string
#==============================================================================
#0   Product Name    UNICODE string
#1   Company Name    UNICODE string
#2   File version number only    UNICODE string
#3   Language code (1033 for en-US)  DWORD
#4   SwitchBackContext   QWORD
#5   File Version    UNICODE string
#6   File Size (in bytes)    DWORD
#7   PE Header field - SizeOfImage   DWORD
#8   Hash of PE Header (unknown algorithm)   UNICODE string
#9   PE Header field - Checksum  DWORD
#a   Unknown QWORD
#b   Unknown QWORD
#c   File Description    UNICODE string
#d   Unknown, maybe Major & Minor OS version DWORD
#f   Linker (Compile time) Timestamp DWORD - Unix time
#10  Unknown DWORD
#11  Last Modified Timestamp FILETIME
#12  Created Timestamp   FILETIME
#15  Full path to file   UNICODE string
#16  Unknown DWORD
#17  Last Modified Timestamp 2   FILETIME
#100 Program ID  UNICODE string
#101 SHA1 hash of file

# note: order here implicitly orders CSV column ordering cause I'm lazy
FIELDS = [
    Field("path", make_value_getter("15"), "File Path"),
    Field("source_key_timestamp", lambda key: make_trimming_timstamp(key.timestamp()), "Source Key Timestamp"),
    Field("created_timestamp", make_windows_timestamp_value_getter("12"), "Created Timestamp"),
    Field("modified_timestamp", make_windows_timestamp_value_getter("11"), "Modified Timestamp"),
    Field("modified_timestamp2", make_windows_timestamp_value_getter("17"), "Modified Timestamp2"),
    Field("linker_timestamp", make_unix_timestamp_value_getter("f"), "Linker Timestamp"),
    Field("timezone", lambda key: make_timezone_getter(), "Time Zone"),
    Field("sha1", make_value_getter("101"), "SHA1 Hash"),
    Field("size", make_value_getter("6"), "File Size"),
    Field("file_description", make_value_getter("c"), "File Description"),
    Field("product", make_value_getter("0"), "Product Name"),
    Field("company", make_value_getter("1"), "Company Name"),
    Field("pe_sizeofimage", make_value_getter("7"), "Size of Image"),
    Field("version_number", make_value_getter("2"), "Version Number"),
    Field("version", make_value_getter("5"), "Version"),
    Field("language", make_value_getter("3"), "Language Code"),
    Field("header_hash", make_value_getter("8"), "Hash of PE Header"),
    Field("pe_checksum", make_value_getter("9"), "PE Checksum"),
    Field("id", make_value_getter("100"), "Program ID"),
    Field("switchbackcontext", make_value_getter("4"), "Switch Back Context"),
]

ExecutionEntry = namedtuple("ExecutionEntry", map(lambda e: e.name, FIELDS))

def parse_execution_entry(key):
    return ExecutionEntry(**dict((e.name, e.getter(key)) for e in FIELDS))

class NotAnAmcacheHive(Exception):
    pass

def parse_execution_entries(registry):
    try:
        volumes = registry.open("Root\\File")
    except Registry.RegistryKeyNotFoundException:
        raise NotAnAmcacheHive()

    ret = []
    for volumekey in volumes.subkeys():
        for filekey in volumekey.subkeys():
            ret.append(parse_execution_entry(filekey))
    return ret

TimelineEntry = namedtuple("TimelineEntry", ["timestamp", "type", "entry"])

def searchHiveFiles(fol):
    hivefiles = []
    for root, dirs, files in os.walk(fol):
        for ff in files:
            if not re.search(r'\.hve$', ff):
                continue
            hivefiles.append(os.path.join(root, ff))
    return hivefiles

def standardOutput(ee, args, file, pf, count):
    w = unicodecsv.writer(pf, delimiter="\t", lineterminator="\n", encoding="utf-8")
    computer_name = utility().get_computer_name(file)
    if count == 0 and not args.noheader:
        w.writerow(["Computer Name"]+map(lambda e: e.collname, FIELDS))
    for e in ee:
        w.writerow([computer_name]+map(lambda i: getattr(e, i.name), FIELDS))

def parseHive(file, outputdirectory, args, count):
    r = Registry.Registry(file)
    try:
        entries = parse_execution_entries(r)
    except NotAnAmcacheHive:
        g_logger.error("Doesn't appear to be an Amcache.hve hive")
        return
    with open(outputdirectory + "\\amcache_output.csv", "a") as pf:
        standardOutput(entries, args, file, pf, count)

def main(argv=None):
    if argv is None:
        argv = sys.argv

    parser = argparse.ArgumentParser(
        description="Parse program execution entries from the Amcache.hve Registry hive")
    parser.add_argument('dir')
    parser.add_argument('--output', '-o', help='-o <output directory>',
                        required=True)
    parser.add_argument("-v", action="store_true", dest="verbose",
                        help="Enable verbose output")
    parser.add_argument("--noheader", action="store_true", dest="noheader",
                        help="Output without header")
    args = parser.parse_args(argv[1:])

    if args.verbose:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)

    if sys.platform == "win32":
        import os, msvcrt
        msvcrt.setmode(sys.stdout.fileno(), os.O_BINARY)

    inputdirectory=args.dir
    outputdirectory=args.output

    hivefiles = searchHiveFiles(inputdirectory)
    for file in hivefiles:
        count = hivefiles.index(file)
        parseHive(file, outputdirectory, args, count)
    if len(hivefiles) <= 0:
        print "Doesn't exist Amcache.hve files"
        sys.exit(1)
    else:
        print "Saved: %s\\amcache_output.csv" % outputdirectory

if __name__ == "__main__":
    main(argv=sys.argv)
