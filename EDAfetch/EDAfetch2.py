#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright 2016 Shingo Eda <eda@cyberdefense.jp>

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

parser = argparse.ArgumentParser()
parser.add_argument("--Dir","--Dir",type=str)			#--Dir option
parser.add_argument("--SaveTo","--SaveTo",type=str)		#--SaveTo directory　option
args = parser.parse_args()

fol = args.Dir			#fol  hensuu
out = args.SaveTo		#out output directory

list_csv = []		
dllout = []
return3 = []

def main():
	searchDIR(fol)

def searchDIR(fol):
	for root,dirs,files in os.walk(fol):
		for ff in files:
			if not re.search(r'\.pf$', ff):
				continue
			pfl = os.path.join(root,ff)
			chkheader(pfl,root,ff)

def chkheader(pfl,root,ff):
	with open(pfl,"rb") as pf:
		fomv = binascii.hexlify(pf.read(1))
		if fomv == "17" or fomv == "1a" or fomv == "1e":
			win7and8pf(root,pf,ff,fomv)
		if fomv == "4d":
			decomp(root,pf,ff,fomv,pfl)
			for root,dirs,files in os.walk(root+"\\"+"dcp"):
				for ff in files:
					print ff
		else:
			pass

def tohex(val, nbits):
    return hex((val + (1 << nbits)) % (1 << nbits))

def decomp(root,pf,ff,fomv,pfl):
	newdir = root+"\\"+"dcp"
	print newdir
	if not os.path.exists(newdir):
		os.mkdir(newdir)
	NULL = ctypes.POINTER(ctypes.c_uint)()
	SIZE_T = ctypes.c_uint
	DWORD = ctypes.c_uint32
	USHORT = ctypes.c_uint16
	UCHAR  = ctypes.c_ubyte
	ULONG = ctypes.c_uint32
	
	try:
		RtlDecompressBufferEx = ctypes.windll.ntdll.RtlDecompressBufferEx
	except AttributeError:
		sys.exit('You must have Windows with version >=8.')
	
	RtlGetCompressionWorkSpaceSize = \
        ctypes.windll.ntdll.RtlGetCompressionWorkSpaceSize
	
	with open(pfl, 'rb') as compfile:
		header = compfile.read(8)
		compressed = compfile.read()
		signature, decompressed_size = struct.unpack('<LL', header)
		calgo = (signature & 0x0F000000) >> 24
		crcck = (signature & 0xF0000000) >> 28
		
		if crcck:
			file_crc = struct.unpack('<L', compressed[:4])[0]
			crc = binascii.crc32(header)
			crc = binascii.crc32(struct.pack('<L',0), crc)
			compressed = compressed[4:]
			crc = binascii.crc32(compressed, crc)
		compressed_size = len(compressed)
		ntCompressBufferWorkSpaceSize = ULONG()
		ntCompressFragmentWorkSpaceSize = ULONG()
		ntstatus = RtlGetCompressionWorkSpaceSize(USHORT(calgo),ctypes.byref(ntCompressBufferWorkSpaceSize),ctypes.byref(ntCompressFragmentWorkSpaceSize))
		if ntstatus:
			sys.exit('cannot get workspace size, err: {}'.format(tohex(ntstatus, 32)))
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
			
	#create decompressed file
	with open(newdir+"\\" + ff, 'wb') as dfile:
		dfile.write(bytearray(ntDecompressed))
	
def win7and8pf(fol1,pf,pfl00,fomv):
	#Section C Length
	pf.seek(104)
	sd = re.split('(..)',binascii.hexlify(pf.read(4)))[1::2]
	list.reverse(sd)
	sdl = int(("".join(sd)),16)				
	
    #Section C Location
	pf.seek(100)
	sh2 = binascii.hexlify(pf.read(4))
	sh3 = re.split('(..)',sh2)[1::2]
	list.reverse(sh3)
	rfl = int(("".join(sh3)),16)
	
	#Section C Value
	pf.seek(rfl)    #Search for the location of Section C
	str1 = binascii.hexlify(pf.read(sdl))
	str2 = str1.replace("0000000","0zzz")
	str3 = str2.replace("000000","zzz")
	mm = re.split(r'zzz',str3)

	#filename for csv
	fff = fol1 + "\\"+pfl00
	ffc = []
	ffc.append(fff)
	dllout.append(ffc)
	
	#File name and Directory from binary data
	pf.seek(16)
	fnd = binascii.hexlify(pf.read(60))
	fdn = fnd.find("000000")
	kiri = fnd[0:fdn]
	ki = re.split('(..)',kiri)[1::2]	
	while '00' in ki:
		ki.remove('00')
	ki2 = "".join(ki)
	fname = binascii.a2b_hex(ki2)

	mo3 = []
	
	for ss in mm:
		kl = []
		gs = []
		kl = re.split('(..)',ss)[1::2]
		while '00' in kl:
			kl.remove('00')
		mo = "".join(kl)
		mo2 = binascii.a2b_hex(mo)
		print mo2
		if fname in mo2:
			mo3.append(mo2)
			print mo3[0]
			
		gs.append(mo2)
		dllout.append(gs)
		
	pf.seek(16)
	fname1 = binascii.hexlify(pf.read(60))
	fnamew = re.split(r'0000',fname1)
	fna = re.split('(..)',fnamew[0])[1::2]
	
	#list1 create
	list1 = []
	#machine name
	list1.append(fol1)
			
	#Filename from file
	list1.append(pfl00)
	
    #prefetch hash
	pf.seek(76)
	ha = pf.read(4)
	hh = re.split('(..)',binascii.hexlify(ha))[1::2]
	list.reverse(hh)
	mdh5 = "".join(hh)
	list1.append(mdh5)
	
	#Exe File Path
	if not len(mo3) == 0:
		mot = mo3[0]
		list1.append(mot)
	else:
		list1.append("-")
		
	#expath = mo3[0]
	#list1.append(mo3)
		
	#Run Count(Win7)
	if fomv == "17":
		pf.seek(152)
		pp = binascii.hexlify(pf.read(4))
		pp2 = re.split('(..)',pp)[1::2]
		list.reverse(pp2)
		cnt = int(("".join(pp2)),16)
	
	#Run Count(Win8 or Win10)
	if fomv == "1a" or fomv == "1e":
		pf.seek(208)
		pp = binascii.hexlify(pf.read(4))
		pp2 = re.split('(..)',pp)[1::2]
		list.reverse(pp2)
		cnt = int(("".join(pp2)),16)
		
	#Volume Information
	pf.seek(108)
	vl = binascii.hexlify(pf.read(4))
	vl2 = re.split('(..)',vl)[1::2]
	list.reverse(vl2)
	vll = int(("".join(vl2)),16)
	pf.seek(vll)
	vlp = binascii.hexlify(pf.read(4))
	vls = re.split('(..)',vlp)[1::2]
	list.reverse(vls)
	try:
		vlss = int(("".join(vls)),16)
	except ValueError:
		pass
		
	#Volume Length
	pf.seek(vll + 4)
	lv = binascii.hexlify(pf.read(4))
	lv2 = re.split('(..)',lv)[1::2]
	list.reverse(lv2)
	llv = int(("".join(lv2)),16)
	pf.seek(vll + vlss)
	vol1 = []
	vol2 = []
	for a in re.split('(..)',binascii.hexlify(pf.read(46)))[1::2]:
		if a != "00":
			vol1.append(a)
			vol2 = binascii.a2b_hex("".join(vol1))
	list1.append(vol2)		
	list1.append(cnt)
		
	#Latest Run Information(Win7)
	if fomv == "17":
		pf.seek(128)
		sp = re.split('(..)',binascii.hexlify(pf.read(8)))[1::2]
		list.reverse(sp)
		ttt = time.ctime((int("".join(sp),16)/10000000) - 11644473600).rstrip()
		ttt2 = time.strftime('%Y/%m/%d %H:%M:%S',time.strptime(ttt))
		list1.append(ttt2)
	
	#Latest Run Time Information(Win8 or Win10)
	if fomv == "1a" or fomv == "1e":
		loca = 128
		while loca < 193:
			pf.seek(loca)
			sp = re.split('(..)',binascii.hexlify(pf.read(8)))[1::2]
			list.reverse(sp)
			try:
				ttt = time.ctime((int("".join(sp),16)/10000000) - 11644473600).rstrip()
				ttt2 = time.strftime('%Y/%m/%d %H:%M:%S',time.strptime(ttt))
				list1.append(ttt2)
			except ValueError:
				pass
			loca = loca + 8
		
	print list1
	print ""
	
	while '00' in fna:
		fna.remove('00')
		fna2 = binascii.a2b_hex("".join(fna))
        list_csv.append(list1)
		
	retsu1 = ["Machine name","Prefetch file name","Hash","Exe File Path","Volume path","Run count","Date and time1","Date and time2","Date and time3","Date and time4","Date and time5","Date and time6","Date and time7","Date and time8"]
	
	with open(out+"prefetch_list.csv","w") as pfile:   #Open New File ( prefetch list file )
		prfline = csv.writer((pfile),lineterminator = "\n")
		prfline.writerow(retsu1)
		prfline.writerows(list_csv)
	
	with open(out+"dll_list.csv","w") as csvfile:     #Open New File ( DLL list file )
		csvline = csv.writer((csvfile),lineterminator = "\n")
		csvline.writerows(dllout)

if __name__ == '__main__':
    main()
print "This program has been successfully completed."		
	
