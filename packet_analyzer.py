import argparse

import os

import sys

from scapy.utils import RawPcapReader

from scapy.layers.l2 import Ether

from scapy.layers.inet import IP, TCP

from scapy.all import *







def process_pcap(file_name):

    print('Opening {}...'.format(file_name))

    # rdpcap comes from scapy and loads in our pcap file

    packets = rdpcap(file_name)

    print('**********PACKET ANALYZER**********')

    count = 0

    i = 0

    tcp=0

    synack=sniff(offline=file_name,filter='tcp[tcpflags]  & tcp-syn!=0 and tcp-ack!=0')

    for pac in synack:

            i+=1

            pkt=pac[IP]

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
