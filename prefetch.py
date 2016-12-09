#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2016 Shingo Eda <eda@cyberdefense.jp>
# Cyber Defense Institute, Inc.

# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at

    # http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import binascii
import re
import time
import sys
import csv
import os
import argparse
import struct
import ctypes
import shutil
import codecs
from parserutility import utility

parser = argparse.ArgumentParser(description = "How to use prefetch.py")
parser.add_argument('--output','-o',help='-o <output directory>', required=True)
parser.add_argument('input')
parser.add_argument("--noheader", action="store_true", dest="noheader", help="Output without header")
args = parser.parse_args()

in_dir=args.input
out_dir=args.output

column_order = {
    "computer_name"  : ["Computer Name", 0],
    "exe_file_path"  : ["Exe Path", 1],
    "run_count"      : ["Run Count", 2],
    "date_time_1"    : ["Date Time1", 3],
    "date_time_2"    : ["Date Time2", 4],
    "date_time_3"    : ["Date Time3", 5],
    "date_time_4"    : ["Date Time4", 6],
    "date_time_5"    : ["Date Time5", 7],
    "date_time_6"    : ["Date Time6", 8],
    "date_time_7"    : ["Date Time7", 9],
    "date_time_8"    : ["Date Time8", 10],
    "time_zone"      : ["Time Zone", 11],
    "prefetch_file"  : ["Prefetch Name", 12],
    "hash"           : ["Hash", 13],
    "volume_path"    : ["Volume Path", 14]
}
column_num = len(column_order)

def main():
    try:
        RtlDecompressBufferEx = ctypes.windll.ntdll.RtlDecompressBufferEx
    except AttributeError:
        print "Notice: Windows 8 or above version needs to parse Windows 10 prefetch."
    searchDIR(in_dir)

def searchDIR(in_dir):
    fileindex = 0
    for root, dirs, files in os.walk(in_dir):
        for filename in files:
            if not re.search(r'\.pf$', filename):
                continue
            pf_filepath = os.path.join(root, filename)
            chkheader(pf_filepath, root, filename, fileindex)
            fileindex += 1            
    remove_dcpdir()

def chkheader(pf_filepath, root, filename, fileindex):
    with open(pf_filepath, "rb") as pf:
        header_version = binascii.hexlify(pf.read(1))
        if header_version == "17" or header_version == "1a" or header_version == "1e":
            parse_pf_win7and8(root, pf, filename, header_version, fileindex)
        if header_version == "4d":
            try:
                RtlDecompressBufferEx = ctypes.windll.ntdll.RtlDecompressBufferEx
            except AttributeError:
                return
            parse_pf_win10(root, filename, header_version, fileindex)
        else:
            pass

def remove_dcpdir():
    for root, dirs, files in os.walk(in_dir):
        for dir in dirs:
            if dir == "dcp":
                shutil.rmtree(root+"\\"+dir)

def parse_pf_win7and8(root, pf, filename, header_version, fileindex):
    parsepf(root, pf, filename, header_version, fileindex)

def parse_pf_win10(root, filename, header_version, fileindex):
    pf_filepath = os.path.join(root, filename)
    decomp(root, filename, pf_filepath)
    dcp_dir = root+"\\dcp\\"
    pf_filepath = dcp_dir+filename
    with open(pf_filepath, "rb") as pf:
        header_version = binascii.hexlify(pf.read(1))
        parsepf(root, pf, filename, header_version, fileindex)

def tohex(val, nbits):
    return hex((val + (1 << nbits)) % (1 << nbits))

def get_exename(pfname):
    break_line = pfname.rfind("-")
    return pfname[:(break_line)]

#decompress for windows 10 prefetch
def decomp(root, filename, pf_filepath):
    newdir = root+"\\"+"dcp"
    if not os.path.exists(newdir):
        os.mkdir(newdir)

    # --> reference (https://gist.github.com/dfirfpi/113ff71274a97b489dfd)
    # Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
    NULL = ctypes.POINTER(ctypes.c_uint)()
    SIZE_T = ctypes.c_uint
    DWORD = ctypes.c_uint32
    USHORT = ctypes.c_uint16
    UCHAR  = ctypes.c_ubyte
    ULONG = ctypes.c_uint32

    RtlDecompressBufferEx = ctypes.windll.ntdll.RtlDecompressBufferEx

    RtlGetCompressionWorkSpaceSize = \
        ctypes.windll.ntdll.RtlGetCompressionWorkSpaceSize

    with open(pf_filepath, 'rb') as fin:
        header = fin.read(8)
        compressed = fin.read()

        signature, decompressed_size = struct.unpack('<LL', header)
        calgo = (signature & 0x0F000000) >> 24
        crcck = (signature & 0xF0000000) >> 28
        magic = signature & 0x00FFFFFF
        if magic != 0x004d414d :
            sys.exit('Wrong signature... wrong file?')

        if crcck:
            # I could have used RtlComputeCrc32.
            file_crc = struct.unpack('<L', compressed[:4])[0]
            crc = binascii.crc32(header)
            crc = binascii.crc32(struct.pack('<L',0), crc)
            compressed = compressed[4:]
            crc = binascii.crc32(compressed, crc)          
            if crc != file_crc:
                sys.exit('Wrong file CRC {0:x} - {1:x}!'.format(crc, file_crc))

        compressed_size = len(compressed)

        ntCompressBufferWorkSpaceSize = ULONG()
        ntCompressFragmentWorkSpaceSize = ULONG()

        ntstatus = RtlGetCompressionWorkSpaceSize(USHORT(calgo),
            ctypes.byref(ntCompressBufferWorkSpaceSize),
            ctypes.byref(ntCompressFragmentWorkSpaceSize))

        if ntstatus:
            sys.exit('Cannot get workspace size, err: {}'.format(
                tohex(ntstatus, 32)))
                
        ntCompressed = (UCHAR * compressed_size).from_buffer_copy(compressed)
        ntDecompressed = (UCHAR * decompressed_size)()
        ntFinalUncompressedSize = ULONG()
        ntWorkspace = (UCHAR * ntCompressFragmentWorkSpaceSize.value)()
        
        ntstatus = RtlDecompressBufferEx(
            USHORT(calgo),
            ctypes.byref(ntDecompressed),
            ULONG(decompressed_size),
            ctypes.byref(ntCompressed),
            ULONG(compressed_size),
            ctypes.byref(ntFinalUncompressedSize),
            ctypes.byref(ntWorkspace))
    # <-- reference

    #create decompressed file
    with open(newdir+"\\" + filename, 'wb') as decomp_file:
        decomp_file.write(bytearray(ntDecompressed))

def parsepf(root, pf, filename, header_version, fileindex):

    output_csv = []
    output_list = []

    #prefetch filename for output list
    output_list.append(root+"\\"+filename+"\n")

    #search NULL in executable name
    pf.seek(16)    
    i = 0
    while i < 60:
        if utility().hextoint(pf.read(2)) == 0:
            break
        i += 2

    #extract executable name as UTF-16 from offset 16 to NULL
    pf.seek(16)
    exename_hex = binascii.hexlify(pf.read(i))
    exename_uni_str = codecs.decode(exename_hex, 'hex_codec').decode('utf-16')
    exename_utf_str = exename_uni_str.encode('utf-8')
    
    #list for comparing to exe path
    exename_list = []

    #parse filename list
    pf.seek(100)
    filename_list_offset = utility().hextoint(pf.read(4))
    filename_list_size = utility().hextoint(pf.read(4))    
    pf.seek(filename_list_offset)

    #loop from "filename_list_offset" to "filename_list_end_offset"
    current_offset = filename_list_offset
    filename_list_end_offset = filename_list_offset + filename_list_size
    filename_length = 0
    while current_offset < filename_list_end_offset:
        #search NULL(boundary) in filename list
        if utility().hextoint(pf.read(2)) == 0:
            pf.seek(current_offset)
            filename_hex = binascii.hexlify(pf.read(filename_length))
            filename_uni_str = codecs.decode(filename_hex, 'hex_codec').decode('utf-16')
            filename_utf_str = filename_uni_str.encode('utf-8')
            if exename_utf_str in filename_utf_str:
                exename_list.append(filename_utf_str)
            output_list.append(filename_utf_str+"\n")
            current_offset = current_offset + filename_length + 2
            pf.seek(current_offset)
            filename_length = 0
        else:
            filename_length += 2

    #record_field create
    record_field = [""] * column_num

    #time zone
    record_field[column_order["time_zone"][1]] = \
        utility().get_timezone_str()

    #computer name
    record_field[column_order["computer_name"][1]] = \
        utility().get_computer_name(root)

    #prefetch filename
    record_field[column_order["prefetch_file"][1]] = filename

    #prefetch hash
    pf.seek(76)
    hash_bin = pf.read(4)
    hash_hex = re.split('(..)', binascii.hexlify(hash_bin))[1::2]
    list.reverse(hash_hex)
    hash_value = "".join(hash_hex)
    record_field[column_order["hash"][1]] = hash_value

    #exe path
    if not len(exename_list) == 0:
        record_field[column_order["exe_file_path"][1]] = exename_list[0]
    else:
        #fill by file name if file path is nothing
        record_field[column_order["exe_file_path"][1]] = get_exename(filename)

    #run count(Win7)
    if header_version == "17":
        pf.seek(152)
        record_field[column_order["run_count"][1]] = utility().hextoint(pf.read(4))

    #run count(Win8 or Win10)
    if header_version == "1a" or header_version == "1e":
        pf.seek(208)
        record_field[column_order["run_count"][1]] = utility().hextoint(pf.read(4))

    #volume information/number
    pf.seek(108)
    vl_info_offset = utility().hextoint(pf.read(4))
    vl_num = utility().hextoint(pf.read(4))

    #seek volume infomation
    pf.seek(vl_info_offset)
    try:
        vl_devicepath_offset = utility().hextoint(pf.read(4))
    except ValueError:
        pass

    #volume length
    pf.seek(vl_info_offset + 4)
    vl_len = utility().hextoint(pf.read(4))
    pf.seek(vl_info_offset + vl_devicepath_offset)
    vol1 = []
    vol2 = []
    for a in re.split('(..)', binascii.hexlify(pf.read(vl_len*2)))[1::2]:
        if a != "00":
            vol1.append(a)
            vol2 = binascii.a2b_hex("".join(vol1))

    if vl_num >= 2:
        record_field[column_order["volume_path"][1]] = "Multiple"
        #remove volume path from exe file path with match
        record_field[column_order["exe_file_path"][1]] = \
            re.sub(r"\\VOLUME{[0-9a-z_./?-]+\}|\\DEVICE\\HARDDISKVOLUME\d+", \
                "", record_field[column_order["exe_file_path"][1]])
    else:
        record_field[column_order["volume_path"][1]] = vol2
        #remove volume path from exe file path with replace
        record_field[column_order["exe_file_path"][1]] = \
            record_field[column_order["exe_file_path"][1]].replace(vol2, "")

    #last run information(Win7)
    if header_version == "17":
        pf.seek(128)
        time = utility().get_timestamp_str(utility().hextoint(pf.read(8)))
        record_field[column_order["date_time_1"][1]] = time

    #run time information(Win8 or Win10)
    if header_version == "1a" or header_version == "1e":
        lastrun_location = 128
        while lastrun_location < 193:
            pf.seek(lastrun_location)
            try:
                time = utility().get_timestamp_str(
                    utility().hextoint(pf.read(8)))
                record_field[column_order["date_time_" + str((lastrun_location-128)/8+1)][1]] = time
            except ValueError:
                pass
            lastrun_location = lastrun_location + 8

    output_csv.append(record_field)

    row = [""] * column_num
    for column in column_order.values():
        row[column[1]] = column[0]

    #open/close output csv file
    with open(out_dir+"\\prefetch_output.csv", "a") as output_file:
        output_line = csv.writer((output_file), delimiter="\t", lineterminator="\n")
        if fileindex == 0 and not args.noheader:
            output_line.writerow(row)
        output_line.writerows(output_csv)

    #open/close output list file
    with open(out_dir+"\\prefetch_output_list.csv", "a") as output_list_file:
        output_list.append("\n")
        output_list_file.writelines(output_list)

if __name__ == '__main__':
    main()
print "Saved: %s\\prefetch_output.csv" % out_dir
print "Saved: %s\\prefetch_output_list.csv" % out_dir
