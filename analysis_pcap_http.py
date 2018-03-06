import dpkt
import struct
import ipaddress
import math
from collections import defaultdict

# TCP control flags
FIN = 0x01  # end of data
SYN = 0x02  # synchronize sequence numbers
RST = 0x04  # reset connection
PSH = 0x08  # push
ACK = 0x10  # acknowledgment number set
URG = 0x20  # urgent pointer set
ECE = 0x40  # ECN-Echo
CWR = 0x80  # congestion window reduced
SYN_ACK = 0x12 # Syn-Ack packet

source_ip_address = '130.245.145.12'
destination_ip_address = '128.208.2.198'

class tcp_header:
    _fields_ =[ ("source_IP",'H'),      # Source IP address
                ("dest_IP", 'H'),       # Destination IP address
                ("source_port", 'H'),   # Source port
                ("dest_port",'H'),      # Destination port
                ("seq_num",'I'),        # Sequence Number
                ("ack_num",'I'),        # Acknowledgement number
                ("offset_resvd",'B'),   # Offset and Reserved field
                ("flags",'B'),          # flags
                ("window_size",'H'),    # Window size
                ("checksum",'H'),       # Checksum
                ("urgent_ptr",'H'),     # Urgent pointer
                ("max_segment",'H'),    # Maximum segment size
                ("if_get",'s')          # If http request / response
                ]

def congestion_control(header_fields):
    print "in function " + str(header_fields.source_port[0])

def calculate_average_rtt(packet_rtt_seq, packet_rtt_ack, total_rtt_time, packet_rtt_count):

    for seq_port_comb in packet_rtt_seq:
        if seq_port_comb in packet_rtt_ack:
            if seq_port_comb[0] not in total_rtt_time:
                total_rtt_time[seq_port_comb[0]] = packet_rtt_ack[seq_port_comb] - packet_rtt_seq[seq_port_comb]
                if seq_port_comb[0] not in packet_rtt_count:
                    packet_rtt_count[seq_port_comb[0]] = 1
                else:
                    packet_rtt_count[seq_port_comb[0]] += 1
            else:
                total_rtt_time[seq_port_comb[0]] += packet_rtt_ack[seq_port_comb] - packet_rtt_seq[seq_port_comb]
                packet_rtt_count[seq_port_comb[0]] += 1

    return total_rtt_time

def load_http(pcap_read):
    request_dict = defaultdict(list)
    response_dict = defaultdict(list)
    tcp_flows = 0

    for ts, buf in pcap_read:

        try:
            #print ts, len(buf)
            header_fields = tcp_header()
            header_fields.source_IP = struct.unpack('>I',buf[26:30])
            rcvd_source_ip = str(ipaddress.ip_address(header_fields.source_IP[0]))
            header_fields.dest_IP = struct.unpack('>I',buf[30:34])
            rcvd_dest_ip = str(ipaddress.ip_address(header_fields.dest_IP[0]))
            header_fields.source_port = struct.unpack('>H',buf[34:36])
            header_fields.dest_port = struct.unpack('>H',buf[36:38])
            header_fields.seq_num = struct.unpack('>I',buf[38:42])
            header_fields.ack_num = struct.unpack('>I',buf[42:46])
            header_fields.offset_resvd = struct.unpack('>B',buf[46:47])
            header_fields.flags = struct.unpack('B',buf[47:48])
            header_fields.window_size = struct.unpack('>H',buf[48:50])
            header_fields.checksum = struct.unpack('>H',buf[50:52])
            header_fields.urgent_ptr = struct.unpack('>H',buf[52:54])

            if header_fields.flags[0] & SYN_ACK == SYN_ACK:
                tcp_flows += 1
            # ------------------------------------------------------------------------------------------------------ #
            offset = ((header_fields.offset_resvd[0]) >> 4) * 4
            # Ethernet + IP +  TCP Header + Options field - To get the start of DATA field
            data_field = (14 + 20 + offset)

            if len(buf) > data_field:

                header_fields.if_get = (struct.unpack('>s', buf[data_field]))[0].decode("utf8",errors='ignore') + \
                                       (struct.unpack('>s', buf[data_field+1]))[0].decode("utf8",errors='ignore') + \
                                       (struct.unpack('>s', buf[data_field+2]))[0].decode("utf8", errors='ignore')

                if header_fields.if_get == 'GET':
                    get_request_ip = rcvd_source_ip

                    if header_fields.source_port[0] not in request_dict:
                        request_dict[header_fields.source_port[0]].append((rcvd_source_ip, header_fields.source_port[0],
                        rcvd_dest_ip, header_fields.dest_port[0], header_fields.seq_num[0], header_fields.ack_num[0]))

                header_fields.if_get += (struct.unpack('>s', buf[data_field + 3]))[0].decode("utf8", errors='ignore')

                # if header_fields.if_get == 'HTTP':

                if get_request_ip != 0 and rcvd_dest_ip == get_request_ip:
                    response_dict[header_fields.dest_port[0]].append((rcvd_source_ip, header_fields.source_port[0],
                    rcvd_dest_ip, header_fields.dest_port[0], header_fields.seq_num[0], header_fields.ack_num[0]))
        except:
            #print 'error'
            pass

    print 'Req' + str(len(request_dict))
    for key in request_dict:
        print request_dict[key]

    print 'Res' + str(len(response_dict))

    for key in response_dict:
        #print 'Nothing'
        for val in response_dict[key]:
            print val

    print tcp_flows


def calculate_stats(pcap_read):
    start_time_http = 0
    end_time_http = 0
    total_packets = 0
    total_data = 0

    for ts, buf in pcap_read:

        total_packets += 1
        end_time_http = ts
        total_data += len(buf)

        if start_time_http == 0:
            start_time_http = ts

    print 'Time to load = ' + str(end_time_http - start_time_http)
    print 'Total packets = ' + str(total_packets)
    print 'Total data sent = ' + str(total_data)
    print '-------------------------------------------------------'


def main():

    f = open('tcp_1080.pcap')
    pcap_read = dpkt.pcap.Reader(f)
    load_http(pcap_read)
    f.close()

    f = open('tcp_1080.pcap')
    pcap_read = dpkt.pcap.Reader(f)
    calculate_stats(pcap_read)
    f.close()

    f = open('tcp_1081.pcap')
    pcap_read = dpkt.pcap.Reader(f)
    load_http(pcap_read)
    #calculate_stats(pcap_read)
    f.close()

    f = open('tcp_1081.pcap')
    pcap_read = dpkt.pcap.Reader(f)
    calculate_stats(pcap_read)
    f.close()

    f = open('tcp_1082.pcap')
    pcap_read = dpkt.pcap.Reader(f)
    load_http(pcap_read)
    f.close()

    f = open('tcp_1082.pcap')
    pcap_read = dpkt.pcap.Reader(f)
    calculate_stats(pcap_read)
    f.close()

if __name__ == '__main__':
    main()