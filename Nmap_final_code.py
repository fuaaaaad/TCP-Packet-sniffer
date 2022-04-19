import argparse

import os

import sys

import math

from scapy.utils import RawPcapReader

from scapy.layers.l2 import Ether

from scapy.layers.inet import IP, TCP

from scapy.all import *

import numpy as np



def ipid(resid):

	rd=0

	ri=0

	bi=0

	incre=0

	diffid=[]

	for i in range(len(resid)-1):

		diffid.append(abs(resid[i]-resid[i+1]))

	if resid.count(0)==len(resid):

		print("Z",end='')

	else:

		if resid.count(resid[0])==len(resid):

			print(hex(resid[0]),end='')

			return

		for d in diffid:

			i=0

			if d<20000:

				rd=1

				break

			if d>1000 and d%256!=0:

				ri=1

			if d%256!=0 and d<5210:

				bi=1

				break

		for d in diffid:

			if d<10:

				incre+=1

		if incre==5:

			print("I")

			

		if rd==0:

			print('RD',end='')

			

		if ri==1:

			print('RI',end='')

			

		if bi==0:

			print('BI',end='')







def process_pcap(file_name):

	print('Opening {}...'.format(file_name))



	flags_val = {'S':'SYN','A':'ACK','F':'FIN','E':'ECE','P':'PSH','R':'RST','C':'CWR','U':'URG'}

	w = 0

	# rdpcap comes from scapy and loads in our pcap file

	packets = rdpcap(file_name)

	print('**PACKET ANALYZER**')

	i = 0

	p = 0

	t=0

	tcp=0

	srcport = [] #unique

	filteredPackets = []

	tPackets=[]

	tsrcport=[]

	tdstport=[]						

	tack=[]

	tseq=[]	

	udp=sniff(offline=file_name,filter='udp')

	a=sniff(offline=file_name,filter='icmp')

	synack=sniff(offline=file_name,filter='tcp')

	for pkt in synack:

		i+=1

		count=0

		ecount=0

		packet2 = pkt[TCP].options

		time = packet2.count(('Timestamp', (4294967295, 0)))

		wscale10 = packet2.count(('WScale',10))

		wscale0 = packet2.count(('WScale',0))

		wscale5 = packet2.count(('WScale',5))

		wscale15 = packet2.count(('WScale',15))

		sack = packet2.count(('SAckOK', b''))

		nop = packet2.count(('NOP', None))

		eol = packet2.count(('EOL', None))

		mss1460 = packet2.count(('MSS', 1460))

		mss1400 = packet2.count(('MSS', 1400))

		mss640 = packet2.count(('MSS', 640))

		mss536 = packet2.count(('MSS', 536))

		mss265 = packet2.count(('MSS', 265))

		listFlag =[]

		listFlag[:0]=pkt[TCP].flags

		sortedFlags = "".join(sorted(pkt[TCP].flags))

		noFlag = len(listFlag)

		

	#probe1

		if time and wscale10 and mss1460 and nop and p<=5 and pkt.window==1:

			p+=1

			filteredPackets.append(pkt)

			probe1ack = pkt.ack

			probe1seq = pkt.seq

			t1dst=pkt[TCP].sport

			t1src=pkt[TCP].dport

			srcport.append(pkt[TCP].sport)



	#probe2

		if time and wscale0 and mss1400 and eol and p<=5:

			p+=1

			filteredPackets.append(pkt)

			srcport.append(pkt[TCP].sport)



	#probe3

		if time and wscale5 and mss640 and nop and p<=5:

			p+=1

			filteredPackets.append(pkt)

			srcport.append(pkt[TCP].sport)





	#probe4

		if time and wscale10 and (mss536 == 0) and eol and p<=5:

			p+=1

			filteredPackets.append(pkt)

			srcport.append(pkt[TCP].sport)





	#probe5

		if time and wscale10 and mss536 and eol and p<=5:

			p+=1

			filteredPackets.append(pkt)

			srcport.append(pkt[TCP].sport)



	#probe6

		if time and mss265 and sack and (wscale0+wscale5+wscale10+wscale15) == 0 and p<=5:

			p+=1

			filteredPackets.append(pkt)

			srcport.append(pkt[TCP].sport)

	 #T2	

		if time and mss265 and nop and wscale10 and sack and noFlag==0 and pkt.window == 128 and pkt.flags == 'DF' and t<=5:

			t+=1

			print('t2')

			#filteredPackets.append(pkt)

			tPackets.append(pkt)  

			tsrcport.append(pkt[TCP].sport)

			tdstport.append(pkt[TCP].dport)   

			tack.append(pkt.ack)

			tseq.append(pkt.seq)       

            #T3	

		if time and mss265 and nop and wscale10 and sack and pkt.window == 256 and sortedFlags =='FPSU' and pkt.flags != 'DF' and t<=5:

			print('t3')



			t+=1

			#filteredPackets.append(pkt) 

			tPackets.append(pkt)

			tsrcport.append(pkt[TCP].sport)

			tdstport.append(pkt[TCP].dport)

			tack.append(pkt.ack)

			tseq.append(pkt.seq)

            #T4	

		if time and mss265 and nop and wscale10 and sack and pkt.window == 1024 and sortedFlags =='A' and pkt.flags == 'DF' and t<=5:

			print('t4')



			t+=1

			#filteredPackets.append(pkt)

			tPackets.append(pkt) 

			tsrcport.append(pkt[TCP].sport)

			tdstport.append(pkt[TCP].dport)

			tack.append(pkt.ack)

			tseq.append(pkt.seq)

            #T5	

		if time and mss265 and nop and wscale10 and sack and pkt.window == 31337 and sortedFlags =='S' and pkt.flags != 'DF' and t<=5:

			print('t5')



			t+=1

			#filteredPackets.append(pkt)

			tPackets.append(pkt) 

			tsrcport.append(pkt[TCP].sport)

			tdstport.append(pkt[TCP].dport)

			tack.append(pkt.ack)

			tseq.append(pkt.seq)

    	    #T6	

		if time and mss265 and nop and wscale10 and sack and pkt.window == 32768 and sortedFlags =='A' and pkt.flags == 'DF' and t<=5:

			print('t6')



			t+=1

			#filteredPackets.append(pkt)

			tPackets.append(pkt) 

			tsrcport.append(pkt[TCP].sport)

			tdstport.append(pkt[TCP].dport)

			tack.append(pkt.ack)

			tseq.append(pkt.seq)

    	    #T7	

		if time and mss265 and nop and wscale15 and sack and pkt.window == 65535 and sortedFlags =='FPU' and pkt.flags != 'DF' and t<=5:

			print('t7')



			t+=1

			#filteredPackets.append(pkt)

			tPackets.append(pkt)

			tsrcport.append(pkt[TCP].sport)

			tdstport.append(pkt[TCP].dport) 	

			tack.append(pkt.ack)

			tseq.append(pkt.seq)	

	

				











	i=0

	print(len(filteredPackets), "Packets found")

	for p in filteredPackets:

			i+=1

			print("--------------------------------")

			print("           Packet #", i)

			print('--------------------------------')

			print('Window size     :', p.window)

			print('Sequence No.    :', p.seq)

			print('Ack No.         :', p.ack)

			print('Source address  :', p.src)

			print('Source port     :', p[TCP].sport)

			print('Destination addr:', p.dst)

			print('Dest port       :', p[TCP].dport)

			print('Options         :', p[TCP].options)

			print('Flags           :', p[TCP].flags)

			print('Time to Live    :', p.ttl)



	print('Response packets')

	respondList = []

	seq=[]

	time=[]

	resid=[]

	for j in synack:

			for i in srcport:

				if i == j[TCP].dport:

					respondList.append(j)

					seq.append((j[tcp].seq))

					time.append(j[tcp].time)

					resid.append(j[IP].id)

	

	tcpid=[]

	i=0

	diff=[]

	for pkt in respondList:

		i+=1

		print("--------------------------------")

		print("           Packet #", i)

		print('--------------------------------')

		print('Window size     :', pkt.window)

		print('Sequence No.    :', pkt.seq)

		print('Ack No.         :', pkt.ack)

		print('Source address  :', pkt.src)

		print('Source port     :', pkt[TCP].sport)

		print('Destination addr:', pkt.dst)

		print('Dest port       :', pkt[TCP].dport)

		print('Options         :', pkt[TCP].options)

		print('Flags           :', pkt[TCP].flags)

		print('Time to Live    :', pkt.ttl)

		tcpid.append(pkt[IP].id)		

		if i==6:

			break





	##response of t2-7

	x=[0]*12

	y=0

	tresponse=[0]*6

	for j in synack:

		for i in range(0,len(tsrcport)):

			if x[i]!=1:

				if j[TCP].sport==tdstport[i] and j[TCP].dport==tsrcport[i]:

					tresponse[i]=j

					x[i]=1







	##retrieving ICMP packets

	

	icmp=sniff(offline=file_name,filter='icmp')

	

	for i in icmp: 

		if i.flags=='DF' and i.tos==0 and i.code==9 and i.seq==295 and i.id!=0 and i[ICMP].type==8 and len(i[Raw])==120:

			

			icmpsrc1=i[IP].dst

			icmpdst1=i[IP].src

			icmpseq1=i[ICMP].seq

			icmpid1=i[ICMP].id

			break

	for i in icmp: 

		if i.tos==4 and i.code==0 and i.seq==(icmpseq1+1) and i[ICMP].id==(icmpid1+1) and i[ICMP].type==8 and len(i[Raw])==150:

			icmpsrc2=i[IP].dst

			icmpdst2=i[IP].src

			break

##response of ICMP packets

	icmpid=[]

	flag1=0

	flag2=0

	df1=0

	df2=0

	t=0

	code1=0

	code2=0

	for i in icmp:

		if flag2==1 and flag1==1:

			break

		if i[IP].src==icmpsrc1 and i[IP].dst==icmpdst1 and flag1==0:

			if i.flags=='DF':

				df1=1

			t=i.ttl

			code1=i.code

			icmpid.append(i[IP].id)				

			flag1=1

		if i[IP].src==icmpsrc2 and i[IP].dst==icmpdst2 and flag2==0:

			if i.flags=='DF':

				df2=1	

			icmpid.append(i[IP].id)

			flag2=1

			code2=i.code

	











####seq test



	

	i=0

	for i in range(len(seq)-1):

		diff.append(abs(seq[i]-seq[i+1]))

		time[i]=(abs(time[i]-time[i+1]))

	time[len(seq)-1]=0

	

		

	i=2

	isr2=0

	diffid=[]

	diffid.append(abs(resid[0]-resid[1]))

	p=gcd(diff[0],diff[1])

	for i in range(2,len(diff)-1):

		p=gcd(p,diff[i+1])

		diffid.append(abs(resid[i]-resid[i+1]))

	i=0

	for i in range(len(diff)):

		isr2+=diff[i]/time[i]

	

	isr2=isr2/5

	

	#calculating sp	

	i=0

	sp=[]

	print('SEQ(',end='')

	if p > 9:

		for x in diff:

			sp.append(x/p)

		sp2=np.std(sp)

		if sp2<=1:

			print("sp=0",end='')

		else:

			print("sp=",hex(int(8*math.log2(sp2))),end='')

	else: 	

		print("sp=0",end='')

	print("%GCD=", p,end='')

	if isr2<1:

		print("%ISR=0",end='')

	else:

		isr=int(8*math.log2(isr2))

		print("%ISR=",hex(isr),end='')



	##calculation of TI	

	if len(respondList)>2:

		print('%TI=',end='')		

		ipid(tcpid)

	else:

		print('%TI=',end='')



	##calculation of CI

	tid=[]

	for i in range(3,len(tresponse)):

		if tresponse[i]!=0:

			tid.append(tresponse[i][IP].id)

	if len(tid)>=2:

		print('%CI=',end='')		

		ipid(tid)

	else:

		print('%CI=',end='')

	

	#calculation of II 

	if flag1==1 and flag2==1:

		print('%II=',end='')

		ipid(icmpid)

	else:

		print('%II=',end='')

	

	timest=[]

	count=0

	ts=0

	#calculting ts(timestamp)

	print("%TS=",end='')

	for i in respondList:

		packe=i[TCP].options

		for j in range(len(packe)):

			if packe[j][0]=='Timestamp':

				count+=1

				if packe[j][1][0]==0:

					ts=1

				timest.append(packe[j][1][0])

	tidiff=0

	timestdiff=0	

	for i in range(len(timest)-1):

		timestdiff+=(abs(timest[i]-timest[i+1]))

		tidiff+=time[i]

	tidiff=timestdiff/tidiff

	tidiff=tidiff/8

	if count==6:

		if ts==0:

			if tidiff>0 and tidiff<5.66:

				print('1',end='')

			elif tidiff>70 and tidiff<150:

				print('7',end='')

			elif tidiff>150 and tidiff<350:

				print('8', end='')

			else:

				print('A',end='')

		else:

			print('0',end='')		

	else:

		print('U',end='')

	print(')')



















	###printing ops field

	

	print('OPS(',end='')

	for pkt in respondList:

		for i in range(len(pkt[TCP].options)):

			if pkt[TCP].options[i][0]=='EOL':

				print('L',end="")

			if pkt[TCP].options[i][0]=='SAckOK':

				print('S',end="")

			if pkt[TCP].options[i][0]=='MSS':

				print("M",hex(pkt[TCP].options[i][1]),end="")	

			if pkt[TCP].options[i][0]=='NOP':

				print('N',end="")

			if pkt[TCP].options[i][0]=='WScale':

				print('W',pkt[TCP].options[i][1],end='')

			if pkt[TCP].options[i][0]=='Timestamp':

				print('T',end='')				

				if pkt[TCP].options[i][1][0]!=0:

					print('1',end='')

				if pkt[TCP].options[i][1][1]!=0:

					print('1',end='')

			

		

		print(',',end='')		

						

	print(')')

	





	###printing win field

	





	print('WIN(',end='')

	for pkt in respondList:

		print(hex(pkt[TCP].window),',',end='')

	print(')')







	









##ECN test  

	



	for i in synack:

		pack=i[TCP].options

		mss1460 = pack.count(('MSS', 1460))

		wscale10 = pack.count(('WScale',10))

		sack = pack.count(('SAckOK', b''))

		nop = pack.count(('NOP', None))

		if i[TCP].flags=='SEC' and i[TCP].ack==0 and i[TCP].window==3 and i[TCP].reserved!=0 and i[TCP].urgptr==63477 and mss1460 and wscale10 and sack and nop==3:

			srcport=i[TCP].sport

			dstport=i[TCP].dport

			break

	print('ECN(',end='')

	flag=0

	for pkt in synack:

		if pkt[TCP].sport==dstport and pkt[TCP].dport==srcport:

			print('R=Y',end='')

			flag=1

			if pkt[IP].flags=='DF':

				print('%DF=Y',end='')

			else:

				print('%DF=N',end='')

			print('%T=',hex(pkt[IP].ttl),end='')

			print('%W=',hex(pkt[TCP].window),end='')

			print('%O=',end='')

			for i in range(len(pkt[TCP].options)):

				if pkt[TCP].options[i][0]=='EOL':

					print('L',end="")

				if pkt[TCP].options[i][0]=='SAckOK':

					print('S',end="")

				if pkt[TCP].options[i][0]=='MSS':

					print("M",hex(pkt[TCP].options[i][1]),end="")	

				if pkt[TCP].options[i][0]=='NOP':

					print('N',end="")

				if pkt[TCP].options[i][0]=='WScale':

					print('W',pkt[TCP].options[i][1],end='')

				if pkt[TCP].options[i][0]=='Timestamp':

					print('T',end='')				

					if pkt[TCP].options[i][1][0]!=0:

						print('1',end='')

					if pkt[TCP].options[i][1][1]!=0:

						print('1',end='')

			print('%CC=',end='')

			if pkt[TCP].flags=='SAE':

				print('Y',end='')

			elif pkt[TCP].flags!='SACE':

				print('N',end='')

			elif pkt[TCP].flags=='SACE':

				print('S',end='')

			else:

				print('O',end='')

			counter = 0

			flags = []

			flags[:0] = pkt[TCP].flags

			print('%Q=',end='')

			for i in flags:

				if i == 'U':

					counter+=1

			if pkt.reserved != 0:

				print( 'R',end='')

			elif counter==0 and pkt.urgptr!=0:

				print('U',end='')

			else:

				print('',end='')

			break

	if flag==0:

		print('R=N',end='')

	print(')')





##T1  RespondList[0]  t1dst t1src

	print('T 1 (',end='')

	if respondList[0][TCP].sport==t1src and respondList[0][TCP].dport==t1dst:

		print('R=Y',end='')

		if respondList[0][IP].flags=='DF':

			print('%DF=Y',end='')

		else:

			print('%DF=N',end='')

		print('%T=',hex(respondList[0][IP].ttl),end='')

		print('%S=',end='')

		if respondList[0][TCP].seq==0:

			print('Z',end='')

		elif respondList[0][TCP].seq==probe1ack:

			print('A',end='')

		elif respondList[0][TCP].seq==(probe1ack+1):

			print('A+',end='')

		else:

			print('O',end='')

		print('%A=',end='')

		if respondList[0][TCP].ack==0:

			print('Z',end='')

		elif respondList[0][TCP].ack==probe1seq:

			print('S',end='')

		elif respondList[0][TCP].ack==(probe1seq+1):

			print('S+',end='')

		else:

			print('O',end='')

		print('%f=',end='')

		listFlag[:0]=respondList[0][TCP].flags

		sortedFlag = "".join(sorted(respondList[0][TCP].flags))

		print(sortedFlag,end='')

		print('%RD=',end='')

		if respondList[0][TCP].chksum==9677:

			print('0',end='')

		counter = 0

		flags = []

		flags[:0] = respondList[0][TCP].flags

		print('%Q=',end='')

		for i in flags:

			if i == 'U':

				counter+=1

		if respondList[0].reserved != 0:

			print( 'R',end='')

		elif counter==0 and respondList[0].urgptr!=0:

			print('U',end='')

		else:

			print('',end='')

	else:

		print('R=N')

			

	print(')')



















##T2-T7

	

	

	



	for j in tresponse:

		print('T',y+2,'(',end='')

		if j==0:

			print('R=N',end='')

			y+=1

			print(')')

			continue

		else:

			print('R=Y',end='')

			if j[IP].flags=='DF':

				print('%DF=Y',end='')

			else:

				print('%DF=N',end='')

			print('%T=',hex(j[IP].ttl),end='')

			print('%W=',j[TCP].window,end='')

			print('%S=',end='')

			if j[TCP].seq==0:

				print('Z',end='')

			elif j[TCP].seq==tack[y]:

				print('A',end='')

			elif j[TCP].seq==(tack[y]+1):

				print('A+',end='')

			else:

				print('O',end='')

			print('%A=',end='')

			if j[TCP].ack==0:

				print('Z',end='')

			elif j[TCP].ack==tseq[y]:

				print('S',end='')

			elif j[TCP].ack==(tseq[y]+1):

				print('S+',end='')

			else:

				print('O',end='')

			listFlag[:0]=j[TCP].flags

			sortedFlag = "".join(sorted(j[TCP].flags))

			print('%F=',sortedFlag,end='')

			print('%O=',end='')

			if j[TCP].chksum!=9677:

				print('%RD=0',end='')

			counter = 0

			flags = []

			flags[:0] = j[TCP].flags

			print('%Q=',end='')

			for i in flags:

				if i == 'U':

					counter+=1

			if j.reserved != 0:

				print( 'R',end='')

			elif counter==0 and j.urgptr!=0:

				print('U',end='')

			else:

				print('',end='')

		y+=1

		print(')')





#U1 test





	count=0

	

	print("U1(",end='')

	for i in range(len(udp)):

		if len(udp[i][3])==300:

			if hex(udp[i][IP].id)=='0x1042':

				

				for j in a:

					#type 3 -destination unreachable

					if j[ICMP].type==3:

						count=1

						print('R=Y%',j[IP].flags,end='')

						if j[IP].flags=='DF':

							print('DF=Y',end='')

						else:

							print('DF=N',end='')

						print('%T=',hex(j[IP].ttl),end='')

						print('%IPL=',hex(j[IP].len),end='')

						print('%UN=',j[ICMP].unused,end='')



						if j[IP].len!=0:

							print('%RIPL=G',end='')



						if j[IP].id==4162 :

							print('%RID=G',end='')

						else:

							print('%RID=',hex(j[IP].id),end='')



						if j[IPerror].chksum==udp[i][IP].chksum:

							print('%RIPCK=G',end='')

						elif j[IPerror].chksum==0:

							print('%RIPCK=Z',end='')

						else:

							print('%RIPCK=I',end='')



						if j[IPerror].chksum:

							print('%RUCK=G',end='')

						else:

							print('%RUCK=',j[IPerror].chksum,end='')

						if len(j[Raw])==300:

							print('%RUD=G',end='')

						else:

							print('%RUD=I',end='')

					if count==1:	

						break

	if count==0:

		print('R=N',end='')

							

	print(')')



























###IE test









	print('IE(',end='')

	

		

	if flag1==1 and flag2==1:

		print('R=Y',end='')

	else:

		print('R=N',end='')

		

	if df1==1 and df2==1:

		print('%DFI=Y',end='')

	else:

		print('%DFI=N',end='')

	print('%T=',hex(t),end='')

	if code1==0 and code2==0:

		print('%CD=Z',end='')

	elif code1==0 and code2==9:

		print('%CD=S',end='')

	elif code1==code2:

		print('%CD=',code1,end='')

	else:

		print('%CD=O',end='')

	print(')')

	

	





#points to be noted:

#[1]for packet1 seq no. of source port = ack no. of d port (for response message as source addr was dest addr here)

#In the responnse packet window size was provided(different to packet 1)

#[2]In options only mss was set to 1460



if __name__ == '__main__':

        #sniff(filter="ip",prn=print_summary)

        # or it possible to filter with filter parameter...!

        #sniff(filter="ip and host 192.168.0.1",prn=print_summary)





    parser = argparse.ArgumentParser(description='PCAP reader')

    parser.add_argument('--pcap', metavar='<pcap file name>',

                    help='pcap file to parse', required=True)

    args = parser.parse_args()



    file_name = args.pcap

    if not os.path.isfile(file_name):

        print('"{}" does not exist'.format(file_name), file=sys.stderr)

        sys.exit(-1)



    process_pcap(file_name)
