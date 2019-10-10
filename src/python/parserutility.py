import time
import datetime
import re
import binascii
import os
import ctypes

class utility(object):
    def get_timezone_str(self):
        diff_seconds = time.timezone
        diff_abs = abs(diff_seconds)
        delta = datetime.timedelta(seconds=diff_abs)
        delta_array = str(delta).split(":")
        diff_str = delta_array[0].zfill(2) + ":" + delta_array[1]
        if diff_seconds <= 0:
            diff_str = "+" + diff_str
        else:
            diff_str = "-" + diff_str
        return diff_str

    def get_computer_name(self, path):
        split_path = path.split(os.sep)
        for dir in reversed(split_path):
            if not dir or dir == split_path[-1] or re.match(r'NTFS|Registry|Prefetch', dir):
                continue
            else:
                parent_folder_name = dir
                break
        break_line = parent_folder_name.rfind("_")
        return parent_folder_name[:(break_line)]

    def get_timestamp_str(self, ts):
        s = (ts / 10000000.0) - 11644473600
        lt = time.ctime(s)
        ddt = time.strftime('%Y/%m/%d %H:%M:%S', time.strptime(lt))
        ms = str("%.3f"%(s)).split(".")[1]
        return ddt + "." + ms

    def hextoint(self, hex):
        hex_array = re.split('(..)', binascii.hexlify(hex))[1::2]
        list.reverse(hex_array)
        return int(("".join(hex_array)),16)

class LARGE_INTEGER ( ctypes.Structure ):
    LONGLONG = ctypes.c_longlong
    _fields_ = [
        ( "QuadPart", LONGLONG )
    ]

class WIN32_FIND_STREAM_DATA ( ctypes.Structure ):
    MAX_PATH = 260
    WCHAR = ctypes.c_wchar * ( MAX_PATH + 1 )
    _fields_ = [
        ( "StreamSize", LARGE_INTEGER ),
        ( "cStreamName", WCHAR )
    ]

def findstreams( path ):

    HANDLE = ctypes.c_void_p
    LPSTR = ctypes.c_wchar_p
    FindStreamInfoStandard = 0
    INVALID_HANDLE_VALUE = -1

    streamData = WIN32_FIND_STREAM_DATA()
    FindFirstStreamW = ctypes.windll.kernel32.FindFirstStreamW
    FindFirstStreamW.restype = HANDLE
    FindNextStreamW = ctypes.windll.kernel32.FindNextStreamW
    hfind = FindFirstStreamW( LPSTR( path ), FindStreamInfoStandard, ctypes.byref( streamData ), 0 )
    paths = list()

    if hfind != INVALID_HANDLE_VALUE:
        if streamData.cStreamName != "::$DATA":
            paths.append( streamData.cStreamName[0:len( streamData.cStreamName )-6] )
        while FindNextStreamW( HANDLE(hfind), ctypes.byref( streamData )):
            if streamData.cStreamName != "::$DATA":
                paths.append( streamData.cStreamName[0:len(streamData.cStreamName)-6] )
        
        if ctypes.windll.kernel32.FindClose( HANDLE(hfind) ) != True:
            print "ERROR"

    return paths