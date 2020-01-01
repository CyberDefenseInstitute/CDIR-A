#!/usr/bin/env python
# -*- coding: utf-8 -*-

# A parser for $UsnJrnl:$J
# Copyright 2017 Cyber Defense Institute, Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# USN_RECORD_V2 structure
# https://msdn.microsoft.com/en-us/library/aa365722(v=vs.85).aspx
import binascii
import re
import os
import time
import sys
import csv
import argparse
import struct
from parserutility import utility

parser = argparse.ArgumentParser(description="How to use usnjrnl")
parser.add_argument("--output", "-o", help="-o <output directory>", required=True)
parser.add_argument("input")
parser.add_argument("--noheader", action="store_true", dest="noheader", help="Output without header")
args = parser.parse_args()

in_dir = args.input
out_dir = args.output

row = ["Computer Name", "Time", "Time Zone", "File Name", "Value", "Reason", "File ID", "Parent Folder ID"]

flag_dict = {
    '32': '0x01 Data in one or more named data streams for the filee was overwritten.',
    '31': '0x02 The filee or directory was added to.',
    '30': '0x04 The filee or directory was truncated.',
    '28': '0x10 Data in one or more named data streams for the filee was overwritten.',
    '27': '0x20 One or more named data streams for the filee were added to.',
    '26': '0x40 One or more named data streams for the filee was truncated.',
    '24': '0x100 The filee or directory was created for the first time.',
    '23': '0x200 The filee or directory was deleted.',
    '22': '0x400 The user made a change to the filee\'s or directory\'s extended attributes.',
    '21': '0x800 A change was made in the access rights to the filee or directory.',
    '20': '0x1000 The filee or directory was renamed and the filee name in this structure is the previous name.',
    '19': '0x2000 The filee or directory was renamed and the filee name in this structure is the new name.',
    '18': '0x4000 A user toggled the fileE_ATTRIBUTE_NOT_CONTENT_INDEXED attribute.',
    '17': '0x8000 A user has either changed one or more filee or directory attributes or one or more time stamps.',
    '16': '0x10000 An NTFS hard link was added to or removed from the filee or directory',
    '15': '0x20000 The compression state of the filee or directory was changed from or to compressed.',
    '14': '0x40000 The filee or directory was encrypted or decrypted.',
    '13': '0x80000 The object identifier of the filee or directory was changed.',
    '12': '0x100000 The reparse point contained in the filee or directory was changed, or a reparse point was added to or deleted from the filee or directory.',
    '11': '0x200000 A named stream has been added to or removed from the filee or a named stream has been renamed.',
    '2': '0x80000000 The filee or directory was closed.'
}

flags = {
    0x00008000: "BASIC_INFO_CHANGE",
    0x80000000: "CLOSE",
    0x00020000: "COMPRESSION_CHANGE",
    0x00000002: "DATA_EXTEND",
    0x00000001: "DATA_OVERWRITE",
    0x00000004: "DATA_TRUNCATION",
    0x00000400: "EA_CHANGE",
    0x00040000: "ENCRYPTION_CHANGE",
    0x00000100: "FILE_CREATE",
    0x00000200: "FILE_DELETE",
    0x00010000: "HARD_LINK_CHANGE",
    0x00004000: "INDEXABLE_CHANGE",
    0x00800000: "INTEGRITY_CHANGE",
    0x00000020: "NAMED_DATA_EXTEND",
    0x00000010: "NAMED_DATA_OVERWRITE",
    0x00000040: "NAMED_DATA_TRUNCATION",
    0x00080000: "OBJECT_ID_CHANGE",
    0x00002000: "RENAME_NEW_NAME",
    0x00001000: "RENAME_OLD_NAME",
    0x00100000: "REPARSE_POINT_CHANGE",
    0x00000800: "SECURITY_CHANGE",
    0x00200000: "STREAM_CHANGE",
    0x00400000: "TRANSACTED_CHANGE"
}

def check_start_point(journal_pathname):
    current_offset = 0
    filename = os.path.basename(journal_pathname)
    filename = filename + "_output.csv"
    if os.path.exists(os.path.join(out_dir,filename)):
        column_name_flag = False
    else:
        column_name_flag = True

    with open(journal_pathname, "rb") as journal_file:
        with open(os.path.join(out_dir, filename), "a") as output_file:
            if column_name_flag and not args.noheader:
                csv.writer((output_file), delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(row)
            while True:
                if struct.unpack("<i", journal_file.read(4))[0] > 0 and struct.unpack("<H", journal_file.read(2))[0] == 2:
                    start_point = journal_file.tell() - 6
                    parseusnjrnl(journal_filesize, start_point, journal_pathname, journal_file, output_file)
                    return
                else:
                    current_offset += 4096
                    journal_file.seek(current_offset)
                continue

def reasonflag(f):
    reason_list = []
    flag = struct.unpack('<I', f.read(4))[0]

    for k, v in flags.items():
        if flag & k:
            reason_list.append(v)

    return hex(flag), "|".join(reason_list)

def parseusnjrnl(journal_filesize, start_point, pathname, journal_file, output_file):
    computer_name = utility().get_computer_name(pathname)
    while True:
        record_field = []

        #entry size
        journal_file.seek(int(start_point))

        size_hex = re.split('(..)', binascii.hexlify(journal_file.read(4)).decode())[1::2]
        list.reverse(size_hex)
        entry_size = int(("".join(size_hex)), 16)
        #file ID
        journal_file.seek(int(start_point + 8))
        file_id = struct.unpack("<L", journal_file.read(4))[0]

        #parent folder ID
        journal_file.seek(int(start_point + 16))
        parent_file_id = struct.unpack("<L", journal_file.read(4))[0]

        # TODO handle 8byte fileID/parentID extactly
        # file_id = struct.unpack("<Q", journal_file.read(8))[0]
        
        #timestamp
        journal_file.seek(int(start_point + 32))
        ts = struct.unpack("<Q", journal_file.read(8))[0]
        ts_s = utility().get_timestamp_str(ts)

        #reasonflag
        #journal_file.seek(int(start_point + 40))
        rhex, rflag = reasonflag(journal_file)

        #file name
        journal_file.seek(int(start_point+56))
        filename_size = struct.unpack("<H", journal_file.read(2))[0]
        journal_file.seek(int(start_point+60))
        filename = journal_file.read(filename_size)
        try:
            filename = filename.decode('UTF-16LE').encode('UTF-8')
        except UnicodeDecodeError:
            print(repr(filename))

        #write record field with appropriate order
        record_field.append(computer_name)
        record_field.append(ts_s)
        record_field.append(time_delta)
        record_field.append(filename.decode(errors="ignore"))
        record_field.append(rhex)
        record_field.append(rflag)
        record_field.append(file_id)
        record_field.append(parent_file_id)
        csv.writer((output_file), delimiter="\t", lineterminator="\n", quoting=csv.QUOTE_ALL).writerow(record_field)

        #search next startpoint or exit at EOF
        next_start = start_point + entry_size
        if next_start >= journal_filesize:
            output_file.close()
            return
        journal_file.seek(next_start)
        while True:
            if binascii.hexlify(journal_file.read(4)).decode() != "00000000":
                start_point = journal_file.tell() - 4
                break

if __name__ == '__main__':
    exists_flag = False
    for root, dirs, files in os.walk(in_dir):
        for filename in files:
            if not re.search(r'\$UsnJrnl-\$J', filename):
                continue
            exists_flag = True
            journal_pathname = os.path.join(root, filename)
            journal_filesize = os.path.getsize(journal_pathname)
            time_delta = utility().get_timezone_str()
            check_start_point(journal_pathname)
            print ("Saved: {}\\{}_output.csv".format(out_dir, filename))
    if not exists_flag:
        print ("$UsnJrnl-$J not found")
        sys.exit(1)
