import argparse

import os

import sys

from scapy.utils import RawPcapReader

from scapy.layers.l2 import Ether

from scapy.layers.inet import IP, TCP

from scapy.all import *







def process_pcap(file_name):

    print('Opening {}...'.format(file_name))
    flags_val = {'S':'SYN','A':'ACK','F':'FIN','E':'ECE','P':'PSH','R':'RST','C':'CWR','U':'URG'}  #Dictionary for corresponding flag values

    # rdpcap comes from scapy and loads in our pcap file

    packets = rdpcap(file_name)

    print('**********PACKET ANALYZER**********')

    count = 0

    i = 0

    tcp=0

    synack=sniff(offline=file_name,filter='tcp[tcpflags]  & tcp-syn!=0 and tcp-ack!=0') #filters tcp syn-ack packets only

    for pac in synack:

            i+=1

            pkt=pac[IP]
		
	    listFlag=[]

            listFlag[:0]=pkt[TCP].flags 

            print('\n--------------------------------')

            print('    Packet No:',i)

            print('----------------------------------')

            print('Source address  :', pkt.src)

            print('Destination addr:', pkt.dst)

            print('Protocol        :', pkt.proto)

            print('Time to Live    :', pkt.ttl)

            print('Sequence No.    :', pkt.seq)

            print('Window size     :', pkt.window)

            print('Checksum        :', pkt.chksum)

            print('Flags           :', pkt.flags)
	    for f in listFlag:

            	print('                :',flags_val[f])

            for wscale in pac[TCP].options:

            	if wscale[0] == 'WScale':

           		print('Window Scale    :', wscale[1]) #Prints Wscale value

            	elif wscale[0] == 'MSS':

            		print('MSS             :', wscale[1]) #prints mss value

            	elif wscale[0] == 'Timestamp':

            		print('Timestamp(TSval):', wscale[1][0]) #prints timestamp (TSval)

           		print('Timestamp(TSecr):',wscale[1][1]) #prints timestamp (TSecr)

            	elif wscale[0]== 'NOP' and count ==0:

            		print('NOP             :', wscale[1])  #prints NOP

            		count+=1

            	elif wscale[0]== 'SAckOK':

            		print('SACK            : Permitted') #prints SACK permitted or not

            	

            print('\n\n\n----------------------------')





if __name__ == '__main__':

	parser = argparse.ArgumentParser(description='PCAP reader')

	parser.add_argument('--pcap', metavar='<pcap file name>',

			help='pcap file to parse', required=True)

	args = parser.parse_args()

	

	file_name = args.pcap

	if not os.path.isfile(file_name):

		print('"{}" does not exist'.format(file_name), file=sys.stderr)

		sys.exit(-1)



	process_pcap(file_name)
