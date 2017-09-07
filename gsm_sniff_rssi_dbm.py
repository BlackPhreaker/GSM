#!/usr/bin/python
# -*- coding: utf-8 -*-
#======================================================================================
#pragma compile(ProductName, gsm_sniff_rssi_dbm.py)
#pragma compile(FileVersion, 0.0.2)
#pragma compile(ProductVersion, 0.0.2)
#pragma compile(FileDescription, GSM Utility)
#pragma compile(Comments, Program made by BlackPhreaker)
#pragma compile(LegalCopyright, Copyright © 1991-2017 BlackPhreaker (BlackPhreaker))
#pragma compile(Sign, BlackPhreaker)
#pragma compile(Date, 22.08.2017)
#======================================================================================

from scapy.all import sniff
#import json
from optparse import OptionParser

''' 
	      0  1  2  3  4  5  6  7   8  9  a  b  c  d  e  f  
	0000 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00 
	0010 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
	0020 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
	0030 ef 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
	0040 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 2b
	0050 2b

	Signal Level (dBm): -17
	
	      0
	0030 ef
	
	     (-(dbm4 & 0x80) | (dbm4 & 0x7f)) | int(hexs, 16)
	ef = -17 (HEX to DEC 1 byte)          | 239 (HEX to DEC 8 byte)
	***
	ee = -18 (HEX to DEC 1 byte)          | 238 (HEX to DEC 8 byte)
	***
'''

def gsm_sniff(x): #
	p=str(x)
	dbm=hex(ord(p[0x30]))
	dbm2=dbm[2:]	
	dbm3=(dbm2).encode("HEX").decode('utf-8') ###
	dbm4=int(dbm2, 16) # (HEX to DEC 8 byte)
	dbm5=(-(dbm4 & 0x80) | (dbm4 & 0x7f)) # (HEX to DEC 1 byte)
	
	print (" HEX: {:2s} | HEX: {:2s} | UTF-8: {:4s} | DEC(8 byte): {:4s} | DEC(1 byte): {:4s}".format(str(dbm), str(dbm2), str(dbm3), str(dbm4), str(dbm5))) #, str(tests)))

if __name__ == '__main__':
	parser = OptionParser(usage="%prog: [options]")
	parser.add_option("-i", "--iface", dest="iface", default="lo", help="Interface (default : lo)")
	parser.add_option("-p", "--port", dest="port", default="4729", type="int", help="Port (default : 4729)")
	(options, args) = parser.parse_args()

sniff(iface=options.iface, filter="port {} and not icmp and udp".format(options.port), prn=gsm_sniff, store=0)
