#!/usr/bin/env python
# coding: UTF-8

import binascii
import re
import time
import sys
import csv
import os
import argparse

parser = argparse.ArgumentParser()
parser.add_argument("--Dir","--Dir",type=str)		#--Dir option
parser.add_argument("--Sch","--Sch",type=str)		#--Sch search　option
parser.add_argument("--SaveTo","--SaveTo",type=str)		#--SaveTo directory　option
args = parser.parse_args()

fol = args.Dir			#fol  hensuu
sch = args.Sch			#sch  search keyword
out = args.SaveTo		#out output directory

list_csv = []		
dllout = []
return3 = []

def main():
	for root,dirs,files in os.walk(fol):
		for ff in files:
			if not re.search(r'\.pf$', ff):
				continue
			pfl = os.path.join(root,ff)
			with open(pfl,"rb") as pf:
				fomv = binascii.hexlify(pf.read(1))
				if fomv == "17" or fomv == "1a":
					win7and8pf(root,pf,ff,fomv)
				else:
					continue

#Prefetch files information (Windows 7 and 8)

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
		#print mo2
		if fname in mo2:
			mo3.append(mo2)
			
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
	list1.append(mo3)
		
	#Execution Counter(Win7)
	if fomv == "17":
		pf.seek(152)
		pp = binascii.hexlify(pf.read(4))
		pp2 = re.split('(..)',pp)[1::2]
		list.reverse(pp2)
		cnt = int(("".join(pp2)),16)
	
	#Execution Counter(Win8)
	if fomv == "1a":
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
		
	#Latest Execution Time Information(Win7)
	if fomv == "17":
		pf.seek(128)
		sp = re.split('(..)',binascii.hexlify(pf.read(8)))[1::2]
		list.reverse(sp)
		ttt = time.ctime((int("".join(sp),16)/10000000) - 11644473600).rstrip()
		ttt2 = time.strftime('%Y/%m/%d %H:%M:%S',time.strptime(ttt))
		list1.append(ttt2)
	
	#Latest Execution Time Information(Win8)
	if fomv == "1a":
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
		
	retsu1 = ["Machine name","Prefetch file name","Hash","Exe File Path","Volume path","Number of executions","Date and time1","Date and time2","Date and time3","Date and time4","Date and time5","Date and time6","Date and time7","Date and time8"]
	retsu3 = []
	
	with open(out+"prefetch_list.csv","w") as pfile:   #Open New File ( prefetch list file )
		prfline = csv.writer((pfile),lineterminator = "\n")
		for aa in retsu1:
			retsu2 = []
			retsu2.append(aa)
			retsu3.append(retsu2)
		prfline.writerow(retsu3)
		prfline.writerows(list_csv)
	
	with open(out+"dll_list.csv","w") as csvfile:     #Open New File ( DLL list file )
		csvline = csv.writer((csvfile),lineterminator = "\n")
		csvline.writerows(dllout)
	
if __name__ == '__main__':
    main()
