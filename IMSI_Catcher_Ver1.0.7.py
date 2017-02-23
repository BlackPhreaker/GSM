#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Oros
# Contributor : puyoulu
# 2016/10/22
# License : CC0 1.0 Universal

"""
This program shows you IMSI numbers of cellphones around you.


/!\ This program was made to understand how GSM network work. Not for bad hacking !


What you need :
1 PC
1 USB DVB-T key (RTL2832U) with antenna (less than 15$) or a OsmocomBB phone


Setup :

sudo add-apt-repository -y ppa:ptrkrysik/gr-gsm
sudo apt update
sudo apt install gr-gsm python-numpy python-scipy python-scapy

Run :

# Open 2 terminals.
# In terminal 1
sudo python simple_IMSI-catcher.py

# In terminal 2
airprobe_rtlsdr.py
# Now, change the frequency and stop it when you have output like :
# 15 06 21 00 01 f0 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b
# 25 06 21 00 05 f4 f8 68 03 26 23 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b 2b
# 49 06 1b 95 cc 02 f8 02 01 9c c8 03 1e 57 a5 01 79 00 00 1c 13 2b 2b
# ...
#
# Now, watch terminal 1 and wait. IMSI numbers should appear :-)
# If nothing appears after 1 min, change the frequency.
#
# Doc : https://fr.wikipedia.org/wiki/Global_System_for_Mobile_Communications
# Example of frequency : 9.288e+08 Bouygues

# You can watch GSM packet with
sudo wireshark -k -Y '!icmp && gsmtap' -i lo


Links :

Setup of Gr-Gsm : http://blog.nikseetharaman.com/gsm-network-characterization-using-software-defined-radio/
Frequency : https://fr.wikipedia.org/wiki/Global_System_for_Mobile_Communications
Scapy : http://secdev.org/projects/scapy/doc/usage.html
IMSI : https://fr.wikipedia.org/wiki/IMSI
Realtek RTL2832U : http://doc.ubuntu-fr.org/rtl2832u and http://doc.ubuntu-fr.org/rtl-sdr
"""

from scapy.all import sniff
import json
from optparse import OptionParser

imsis=[] # [IMSI,...]
tmsis={} # {TMSI:IMSI,...}
nb_IMSI=0 # count the number of IMSI


# return something like '0xd9605460'
def str_tmsi(tmsi):
	if tmsi != "":
		new_tmsi="0x"
		for a in tmsi:
			c=hex(ord(a))
			if len(c)==4:
				new_tmsi+=str(c[2])+str(c[3])
			else:
				new_tmsi+="0"+str(c[2])
		return new_tmsi
	else:
		return ""

# return something like '208 20 1752XXXXXX ; France ; Bouygues ; Bouygues Telecom'
def str_imsi(imsi, p=""):
	new_imsi=''
	for a in imsi:
		c=hex(ord(a))
		if len(c)==4:
			new_imsi+=str(c[3])+str(c[2])
		else:
			new_imsi+=str(c[2])+"0"
	
	mcc=new_imsi[1:4]
	mnc=new_imsi[4:6]
	country=""
	brand=""
	operator=""
	if mcc in mcc_codes:
		if mnc in mcc_codes[mcc]['MNC']:
			country=mcc_codes[mcc]['c'][0]
			brand=mcc_codes[mcc]['MNC'][mnc][0]
			operator=mcc_codes[mcc]['MNC'][mnc][1]
			new_imsi=mcc+" "+mnc+" "+new_imsi[6:]
		elif mnc+new_imsi[6:7] in mcc_codes[mcc]['MNC']:
			mnc+=new_imsi[6:7]
			country=mcc_codes[mcc]['c'][0]
			brand=mcc_codes[mcc]['MNC'][mnc][0]
			operator=mcc_codes[mcc]['MNC'][mnc][1]
			new_imsi=mcc+" "+mnc+" "+new_imsi[7:]
		else:
			country=mcc_codes[mcc]['c'][0]
			brand="Unknown"
			operator=mcc_codes[mcc]['MNC'][mnc][1]
			new_imsi=mcc+" "+mnc+" "+new_imsi[6:]

	try:
		m="{:17s} ; {} ; {} ; {}".format(new_imsi, country.encode('utf-8'), brand.encode('utf-8'), operator.encode('utf-8'))
	except:
		m=""
		print("Error", p, new_imsi, country, brand, operator)
	return m

# print TMSI, IMSI and operator's information
def show_imsi(imsi1="", imsi2="", tmsi1="", tmsi2="", p=""):
	global imsis
	global tmsis
	global nb_IMSI

	do_print=False
	n=''
	if imsi1 and (not imsi_to_track or imsi1 == imsi_to_track):
		if imsi1 not in imsis:
			# new IMSI
			do_print=True
			imsis.append(imsi1)
			nb_IMSI+=1
			n=nb_IMSI
		if tmsi1 and (tmsi1 not in tmsis or tmsis[tmsi1] != imsi1):
			# new TMSI to an ISMI
			do_print=True
			tmsis[tmsi1]=imsi1
		if tmsi2 and (tmsi2 not in tmsis or tmsis[tmsi2] != imsi1):
			# new TMSI to an ISMI
			do_print=True
			tmsis[tmsi2]=imsi1		
	
	if imsi2 and (not imsi_to_track or imsi2 == imsi_to_track):
		if imsi2 not in imsis:
			# new IMSI
			do_print=True
			imsis.append(imsi2)
			nb_IMSI+=1
			n=nb_IMSI
		if tmsi1 and (tmsi1 not in tmsis or tmsis[tmsi1] != imsi2):
			# new TMSI to an ISMI
			do_print=True
			tmsis[tmsi1]=imsi2
		if tmsi2 and (tmsi2 not in tmsis or tmsis[tmsi2] != imsi2):
			# new TMSI to an ISMI
			do_print=True
			tmsis[tmsi2]=imsi2

	if not imsi1 and not imsi2 and tmsi1 and tmsi2:
		if tmsi2 in tmsis:
			# switch the TMSI
			do_print=True
			imsi1=tmsis[tmsi2]
			tmsis[tmsi1]=imsi1
			del tmsis[tmsi2]

	if do_print:
		if imsi1:
			print("{:7s} ; {:10s} ; {:10s} ; {} ; {:5s} ; {:6s}".format(str(n), str_tmsi(tmsi1), str_tmsi(tmsi2), str_imsi(imsi1, p), str(lac), str(cell) ))
#			print("{:7s} ; {:10s} ; {:10s} ; {} ".format(str(n), str_tmsi(tmsi1), str_tmsi(tmsi2), str_imsi(imsi1, p)))
		if imsi2:
			print("{:7s} ; {:10s} ; {:10s} ; {} ; {:5s} ; {:6s}".format(str(n), str_tmsi(tmsi1), str_tmsi(tmsi2), str_imsi(imsi2, p), str(lac), str(cell) ))
#			print("{:7s} ; {:10s} ; {:10s} ; {} ".format(str(n), str_tmsi(tmsi1), str_tmsi(tmsi2), str_imsi(imsi2, p)))

	if not imsi1 and not imsi2 and show_all_tmsi:
		do_print=False
		if tmsi1 and tmsi1 not in tmsis:
			do_print=True
			tmsis[tmsi1]=""
		if tmsi1 and tmsi1 not in tmsis:
			do_print=True
			tmsis[tmsi2]=""
		if do_print:
			print("{:7s} ; {:10s} ; {:10s} ; {} ; {:5s} ; {:6s}".format(str(n), str_tmsi(tmsi1), str_tmsi(tmsi2), "; ; ;"))
#			print("{:7s} ; {:10s} ; {:10s} ; {} ".format(str(n), str_tmsi(tmsi1), str_tmsi(tmsi2), "; ; ;"))


def find_imsi(x):
	p=str(x)
	if ord(p[0x36]) != 0x1: # Channel Type != BCCH (0)
		tmsi1=""
		tmsi2=""
		imsi1=""
		imsi2=""
		lac=ord(p[0x42])*256+ord(p[0x43]) ###
		cell=ord(p[0x3d])*256+ord(p[0x3e]) ###
		if ord(p[0x3c]) == 0x21: # Message Type: Paging Request Type 1
			if ord(p[0x3e]) == 0x08 and (ord(p[0x3f]) & 0x1) == 0x1: # Channel 1: TCH/F (Full rate) (2)
				# Mobile Identity 1 Type: IMSI (1)
				"""
				        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
				0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
				0010   00 43 1c d4 40 00 40 11 1f d4 7f 00 00 01 7f 00
				0020   00 01 c2 e4 12 79 00 2f fe 42 02 04 01 00 00 00
				0030   c9 00 00 16 21 26 02 00 07 00 31 06 21 00 08 XX
				0040   XX XX XX XX XX XX XX 2b 2b 2b 2b 2b 2b 2b 2b 2b
				0050   2b
				XX XX XX XX XX XX XX XX = IMSI
				"""
				imsi1=p[0x3f:][:8]
				# ord(p[0x3a]) == 0x59 = l2 pseudo length value: 22
				if ord(p[0x3a]) == 0x59 and ord(p[0x48]) == 0x08 and (ord(p[0x49]) & 0x1) == 0x1: # Channel 2: TCH/F (Full rate) (2)
					# Mobile Identity 2 Type: IMSI (1)
					"""
				        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
				0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
				0010   00 43 90 95 40 00 40 11 ac 12 7f 00 00 01 7f 00
				0020   00 01 b4 1c 12 79 00 2f fe 42 02 04 01 00 00 00
				0030   c8 00 00 16 51 c6 02 00 08 00 59 06 21 00 08 YY
				0040   YY YY YY YY YY YY YY 17 08 XX XX XX XX XX XX XX
				0050   XX
				YY YY YY YY YY YY YY YY = IMSI 1
				XX XX XX XX XX XX XX XX = IMSI 2
					"""
					imsi2=p[0x49:][:8]
				elif ord(p[0x3a]) == 0x59 and ord(p[0x48]) == 0x08 and (ord(p[0x49]) & 0x1) == 0x1: # Channel 2: TCH/F (Full rate) (2)
					# Mobile Identity - Mobile Identity 2 - IMSI
					"""
				        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
				0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
				0010   00 43 f6 92 40 00 40 11 46 15 7f 00 00 01 7f 00
				0020   00 01 ab c1 12 79 00 2f fe 42 02 04 01 00 00 00
				0030   d8 00 00 23 3e be 02 00 05 00 4d 06 21 a0 08 YY
				0040   YY YY YY YY YY YY YY 17 05 f4 XX XX XX XX 2b 2b
				0050   2b
				YY YY YY YY YY YY YY YY = IMSI 1
				XX XX XX XX = TMSI
					"""
					tmsi1=p[0x4a:][:4]

#				show_imsi(imsi1, imsi2, tmsi1, tmsi2, p, lac, cell)
				show_imsi(imsi1, imsi2, tmsi1, tmsi2, p)

			elif ord(p[0x45]) == 0x08 and (ord(p[0x46]) & 0x1) == 0x1: # Channel 2: TCH/F (Full rate) (2)
				# Mobile Identity 2 Type: IMSI (1)
				"""
				        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
				0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
				0010   00 43 57 8e 40 00 40 11 e5 19 7f 00 00 01 7f 00
				0020   00 01 99 d4 12 79 00 2f fe 42 02 04 01 00 00 00
				0030   c7 00 00 11 05 99 02 00 03 00 4d 06 21 00 05 f4
				0040   yy yy yy yy 17 08 XX XX XX XX XX XX XX XX 2b 2b
				0050   2b
				yy yy yy yy = TMSI/P-TMSI - Mobile Identity 1
				XX XX XX XX XX XX XX XX = IMSI
				"""
				tmsi1=p[0x40:][:4]
				imsi2=p[0x46:][:8]
				show_imsi(imsi1, imsi2, tmsi1, tmsi2, p, lac, cell)
#				show_imsi(imsi1, imsi2, tmsi1, tmsi2, p)

			elif ord(p[0x3e]) == 0x05 and (ord(p[0x3f]) & 0x07) == 4: # Mobile Identity - Mobile Identity 1 - TMSI/P-TMSI 
				"""
				        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f
				0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
				0010   00 43 b3 f7 40 00 40 11 88 b0 7f 00 00 01 7f 00
				0020   00 01 ce 50 12 79 00 2f fe 42 02 04 01 00 03 fd
				0030   d1 00 00 1b 03 5e 05 00 00 00 41 06 21 00 05 f4
				0040   XX XX XX XX 17 05 f4 YY YY YY YY 2b 2b 2b 2b 2b
				0050   2b
				XX XX XX XX = TMSI/P-TMSI - Mobile Identity 1
				YY YY YY YY = TMSI/P-TMSI - Mobile Identity 2
				"""
				tmsi1=p[0x40:][:4]
				if ord(p[0x45]) == 0x05 and (ord(p[0x46]) & 0x07) == 4: # Mobile Identity - Mobile Identity 2 - TMSI/P-TMSI 
					tmsi2=p[0x47:][:4]
				else:
					tmsi2=""

				show_imsi(imsi1, imsi2, tmsi1, tmsi2, p)

		elif ord(p[0x3c]) == 0x22: # Message Type: Paging Request Type 2
			if ord(p[0x47]) == 0x08 and (ord(p[0x48]) & 0x1) == 0x1: # Mobile Identity 3 Type: IMSI (1)
				"""
				        0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f				
				0000   00 00 00 00 00 00 00 00 00 00 00 00 08 00 45 00
				0010   00 43 1c a6 40 00 40 11 20 02 7f 00 00 01 7f 00
				0020   00 01 c2 e4 12 79 00 2f fe 42 02 04 01 00 00 00
				0030   c9 00 00 16 20 e3 02 00 04 00 55 06 22 00 yy yy
				0040   yy yy zz zz zz 4e 17 08 XX XX XX XX XX XX XX XX
				0050   8b
				yy yy yy yy = TMSI/P-TMSI - Mobile Identity 1
				zz zz zz zz = TMSI/P-TMSI - Mobile Identity 2
				XX XX XX XX XX XX XX XX = IMSI
				"""
				tmsi1=p[0x3e:][:4]
				tmsi2=p[0x42:][:4]
				imsi2=p[0x48:][:8]
				show_imsi(imsi1, imsi2, tmsi1, tmsi2, p)


parser = OptionParser(usage="%prog: [options]")
parser.add_option("-a", "--alltmsi", action="store_true", dest="show_all_tmsi", help="Show TMSI who haven't got IMSI (default  : false)")
parser.add_option("-i", "--iface", dest="iface", default="lo", help="Interface (default : lo)")
parser.add_option("-m", "--imsi", dest="imsi", default="", type="string", help='IMSI to track (default : None, Example: 123456789101112 or "123 45 6789101112")')
parser.add_option("-p", "--port", dest="port", default="4729", type="int", help="Port (default : 4729)")
(options, args) = parser.parse_args()

show_all_tmsi=options.show_all_tmsi
imsi_to_track=""
if options.imsi:
	imsi="9"+options.imsi.replace(" ", "")
	for i in range(0,15,2):
		imsi_to_track+=chr(int(imsi[i+1])*16+int(imsi[i]))

# mcc codes form https://en.wikipedia.org/wiki/Mobile_Network_Code
with open('mcc-mnc/mcc_codes.json', 'r') as file:
	mcc_codes = json.load(file)

#print("{:7s} ; {:10s} ; {:10s} ; {:17s} ; {} ; {} ; {}".format("Nb IMSI", "TMSI-1", "TMSI-2", "IMSI", "country", "brand", "operator"))
#sniff(iface=options.iface, filter="port {} and not icmp and udp".format(options.port), prn=find_imsi, store=0)

#
# BlackPhreaker
#

print('====================================================================================================================' + '\n')
#print("{:7s} ; {:10s} ; {:10s} ; {:17s} ; {} ; {} ; {} ; {:5s} ; {:6s}".format("Nb IMSI", "TMSI-1", "TMSI-2", "IMSI", "Country", "Brand", "Operator", "LAC", "CellId"))
print("{:5s} ; {:4s} ; {:5s} ; {:6s} ; {} ; {} ; {}".format("MCC", "MNC", "LAC", "CellId", "Country", "Brand", "Operator"))
print('====================================================================================================================' + '\n')
sniff(iface=options.iface, filter="port {} and not icmp and udp".format(options.port), prn=find_imsi, store=0)
#sniff(iface=options.iface, filter="port {} and not icmp and udp".format(options.port), prn=find_cell, store=0)
