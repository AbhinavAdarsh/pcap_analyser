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
                ("max_segment",'H')     # Maximum segment size
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


def main():

    is_SYN_set = 0
    is_SYN_ACK_set = 0
    is_ACK_set = 0
    first_syn = 0
    time_diff = 0
    packets_lost = 0
    start_time = {}                 # port number : start time(ts)
    end_time = {}                   # port number : end time (ts)
    data_sent = {}
    packet_sent = {}
    packet_rcvd = {}

    packet_seq = {}                 # (source port, sequence number) : packet_count
    retransmitted_seq = {}          # (source port, retransmitted sequence) : packet_count
    total_packets_sent = {}         # source port : total  - For each TCP flow
    retran_packets_sent = {}         # source port : retransmitted - For each TCP flow

    packets_sent = {}               # source port : total packets sent
    packet_rtt_seq = {}             # (source port, sequence number) : timestamp
    packet_rtt_ack = {}             # (destination port, acknowledgement number) : timestamp
    total_rtt_time = {}             # port : rtt_time
    packet_rtt_count = {}           # port : packet_count

    seq_loss_type = {}              # (source port, sequence number) : packet count
    ack_loss_type = {}              # (source port, acknowledgement number) : packet count

    packet_ack = {}
    dup_ack = {}

    ack_num_win = 0                                 # Acknowledgement number sent by receiver to sender
    seq_num_win = 0                                 # Sequence number sent by sender to receiver
    congestion_window = defaultdict(list)           # Port : List to store window sizes

    total_packets_sent_source = 0
    total_packets_sent_dest = 0
    total_packets_rcvd_dest = 0
    total_packets_rcvd_source = 0
    MSS = 0

    # print 'start'
    f = open('assignment2.pcap')
    pcap_read = dpkt.pcap.Reader(f)
    i = 0
    tcp_flows = 0
    count = 0

    for ts, buf in pcap_read:

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

        if header_fields.flags[0] & SYN == SYN and header_fields.flags[0] & ACK == ACK:
            header_fields.max_segment = struct.unpack('>H', buf[56:58])
            print 'MAX Segment = ' + str(header_fields.max_segment[0])
            MSS = header_fields.max_segment[0]

        # Question 2
        # congestion_control(header_fields)
        # print 'Source IP Address' + " " + rcvd_source_ip
        # print 'Source Port' + " " + str(header_fields.source_port[0])

        if rcvd_source_ip == source_ip_address:

            # Store the start and end time for each TCP flow
            if header_fields.flags[0] & SYN == SYN:
                start_time[header_fields.source_port[0]] = ts
            elif header_fields.flags[0] & FIN == FIN:
                end_time[header_fields.source_port[0]] = ts
            # ------------------------------------------------------------------------------------------------------ #

            if header_fields.source_port[0] not in data_sent:
                data_sent[header_fields.source_port[0]] = len(buf)
                packet_sent[header_fields.source_port[0]] = 1
            else:
                data_sent[header_fields.source_port[0]] += len(buf)
                packet_sent[header_fields.source_port[0]] += 1

            # Find the total number of retransmissions (Include the retransmission for a sequence number only once)
            if (header_fields.source_port[0], header_fields.seq_num[0]) not in packet_seq:
                packet_seq[(header_fields.source_port[0], header_fields.seq_num[0])] = 1

                if header_fields.source_port[0] not in packets_sent:
                    packets_sent[header_fields.source_port[0]] = 1
                else:
                    packets_sent[header_fields.source_port[0]] += 1
            else:
                packet_seq[(header_fields.source_port[0], header_fields.seq_num[0])] += 1
                packets_sent[header_fields.source_port[0]] += 1
                if (header_fields.source_port[0], header_fields.seq_num[0]) not in retransmitted_seq:
                    retransmitted_seq[(header_fields.source_port[0], header_fields.seq_num[0])] = 1
                    packets_lost += 1

            # ------------------------------------------------------------------------------------------------------ #

        # Calculate average RTT for each TCP flow
        if rcvd_source_ip == source_ip_address:
            if (header_fields.source_port[0], header_fields.seq_num[0]) not in packet_rtt_seq:
                packet_rtt_seq[(header_fields.source_port[0], header_fields.seq_num[0])] = ts

        if rcvd_source_ip == destination_ip_address:
            if (header_fields.dest_port[0], header_fields.ack_num[0]) not in packet_rtt_ack:
                packet_rtt_ack[(header_fields.dest_port[0], header_fields.ack_num[0])] = ts
        # ---------------------------------------------------------------------------------------------------------- #
        # Calculate losses due to triple DUP ACK or timeout
        if rcvd_source_ip == source_ip_address:
            if (header_fields.source_port[0], header_fields.seq_num[0]) not in seq_loss_type:
                seq_loss_type[(header_fields.source_port[0], header_fields.seq_num[0])] = 1
            else:
                seq_loss_type[(header_fields.source_port[0], header_fields.seq_num[0])] += 1

        if rcvd_source_ip == destination_ip_address:
            if (header_fields.dest_port[0], header_fields.ack_num[0]) not in ack_loss_type:
                ack_loss_type[(header_fields.dest_port[0], header_fields.ack_num[0])] = 1
            else:
                ack_loss_type[(header_fields.dest_port[0], header_fields.ack_num[0])] += 1


        # ---------------------------------------------------------------------------------------------------------- #

        if rcvd_source_ip == destination_ip_address:
            ack_num_win = header_fields.ack_num[0]

        if rcvd_source_ip == source_ip_address and ack_num_win != 0:
            seq_num_win = header_fields.seq_num[0]
            # for value_list in congestion_window.values():
            #     if (seq_num_win - ack_num_win) not in value_list:
            congestion_window[header_fields.source_port[0]].append(seq_num_win - ack_num_win)
            ack_num_win = 0

        # ---------------------------------------------------------------------------------------------------------- #

        if header_fields.ack_num[0] not in packet_ack:
            packet_ack[header_fields.ack_num[0]] = header_fields.source_port[0]
        else:
            if header_fields.ack_num[0] not in dup_ack:
                dup_ack[header_fields.ack_num[0]] = header_fields.source_port[0]
                #packets_lost += 1
                #print 'Duplicate packet'

        if rcvd_dest_ip == destination_ip_address:
            if header_fields.dest_port[0] not in data_sent:
                packet_rcvd[header_fields.dest_port[0]] = 1
            else:
                packet_rcvd[header_fields.dest_port[0]] += 1

        if is_SYN_set and is_SYN_ACK_set and is_ACK_set:
            i = i+1
            print 'Packet #' + str(i)
            print 'Source IP Address' + " " + rcvd_source_ip
            print 'Destination IP Address' + " " + rcvd_dest_ip
            print 'Source Port' + " " + str(header_fields.source_port[0])
            print 'Destination Port' + " " + str(header_fields.dest_port[0])
            print 'Sequence Number' + " " + str(header_fields.seq_num[0])
            print 'Acknowledgement Number' + " " + str(header_fields.ack_num[0])
            print 'Window Size ' + str(header_fields.window_size[0])
            # print 'Checksum ' + str(header_fields.checksum[0])
            # print 'Urgent Pointer ' + str(header_fields.urgent_ptr[0])
            print '---------------------------------------------'
            count += 1
            if count is 2:
                is_SYN_set = 0
                is_ACK_set = 0
                is_SYN_ACK_set = 0
                count = 0

        if source_ip_address == rcvd_source_ip:
            #data_sent += len(buf)
            total_packets_sent_source += 1
        if source_ip_address == rcvd_dest_ip:
            total_packets_rcvd_source += 1
        if destination_ip_address == rcvd_source_ip:
            total_packets_sent_dest += 1
        if destination_ip_address == rcvd_dest_ip:
            total_packets_rcvd_dest += 1

        if header_fields.flags[0] & SYN == SYN:
            #print header_fields.flags[0]
            is_SYN_set = 1

        if header_fields.flags[0] & SYN_ACK == SYN_ACK:
            #print bin(SYN_ACK)
            #print bin(header_fields.flags[0])
            tcp_flows += 1
            if is_SYN_set:
                is_SYN_ACK_set = 1

        if header_fields.flags[0] & ACK == ACK:
            if is_SYN_set and is_SYN_ACK_set:
                is_ACK_set = 1

        # fields = struct.unpack('ddddHHHIIIIIIIIH', buf)
        # for j in range(5,14):
        #     print fields[j]
    start_time_set = set(start_time)
    end_time_set = set(end_time)
    print "Total TCP flows initiated = "+str(tcp_flows)
    for index in start_time_set.intersection(end_time_set):
        # print index, start_time[index], end_time[index]
        print 'For Port '+str(index) + ': ' + str(data_sent[index]) + ' bytes were sent for '+ \
              str(end_time[index] - start_time[index]) + ' seconds, Throughput = '+ \
              str(data_sent[index] / ((end_time[index] - start_time[index])*100)) + ' Bps'
        # + 'Packets Lost = ' + str(dup_ack[index])
        # print 'For Port '+str(index) +': ' + 'Packets Sent = ' + str(packet_sent[index]) + ', Packets received = '
        # + str(packet_rcvd[index])

    # for key in retransmitted_seq.items():
    #      print key
    #
    # for count in packets_sent.items():
    #     print count

    # print 'For Port: '+str(key) + ' Packets sent: ' + str(packet_sent[key]) + ' Packets lost: '+ str(k)

    # print 'Total packets lost = ' + str(packets_lost)
        # print 'Time = ' + str(end_time[index] - start_time[index])
        # print 'Throughput = ' + str(total_data_sent / ((end_time[index] - start_time[index])*1000))
    # print total_packets_rcvd_dest
    # print total_packets_sent_dest
    # print total_packets_rcvd_source
    # print total_packets_sent_source
    # print 'Packet Loss at '+str(source_ip_address) +' = '+str(total_packets_sent_source - total_packets_rcvd_dest)
    # print 'Packet Loss at'+str(destination_ip_address) +' = '+str(total_packets_sent_dest - total_packets_rcvd_source)

    # ---------------------------------------------------------------------------------------------------------------- #
    # Calculate Loss rate for each TCP flow
    for key in packet_seq:
        if key[0] not in total_packets_sent:
            total_packets_sent[key[0]] = packet_seq[key]
        else:
            total_packets_sent[key[0]] += packet_seq[key]

    for key in retransmitted_seq:
        if key[0] not in retran_packets_sent:
            retran_packets_sent[key[0]] = retransmitted_seq[key]
        else:
            retran_packets_sent[key[0]] += retransmitted_seq[key]

    total_packets_sent_set = set(total_packets_sent)
    retran_packets_sent_set = set(retran_packets_sent)

    for key in total_packets_sent_set.intersection(retran_packets_sent_set):
        print 'Loss Rate of TCP flow for Port: ' + str(key) + ' = ' + str(float(retran_packets_sent[key]*100) /
                                                                          float(total_packets_sent[key])) + '%'
    # ---------------------------------------------------------------------------------------------------------------- #
    # Calculate the Average RTT for each TCP flow
    calculate_average_rtt(packet_rtt_seq, packet_rtt_ack, total_rtt_time, packet_rtt_count)

    total_rtt_time_set = set(total_rtt_time)
    packet_rtt_count_set = set(packet_rtt_count)

    for key in total_rtt_time_set.intersection(packet_rtt_count_set):
        print 'Average RTT of TCP flow for Port: ' + str(key) + ' = ' + str(packet_rtt_count[key] / total_rtt_time[key])
    # ---------------------------------------------------------------------------------------------------------------- #
    # Calculate theoretical throughput and compare it with empirical throughput calculated
    # Formula for calculating throughput : (sqrt(3/2) * (MSS / (sqrt(p) * Average RTT)))

    for key in total_rtt_time_set.intersection(packet_rtt_count_set):

        if key in total_packets_sent_set.intersection(retran_packets_sent_set):
            p = float(retran_packets_sent[key]*100) / float(total_packets_sent[key])
            avg_rtt = (packet_rtt_count[key] / total_rtt_time[key])
            print 'Theoretical throughput for Port: ' + str(key) + ' = ' \
                  + str((math.sqrt(3/2) * (MSS / math.sqrt(p) * avg_rtt)))
    # ---------------------------------------------------------------------------------------------------------------- #
    # PART B.1: Initial 10 (if available) congestion window sizes for each TCP flow
    window_list = defaultdict(list)
    for key in congestion_window:
        for i in range(0, len(congestion_window[key])):
            if congestion_window[key][i] not in window_list[key] and congestion_window[key][i] > 0 and \
                    len(window_list[key]) < 10:
                window_list[key].append(congestion_window[key][i])

    for key in window_list:
        print 'First 10 Congestion Window sizes for Port: ' + str(key) + ' ' + str(window_list[key])

    # ---------------------------------------------------------------------------------------------------------------- #
    # PART B.2: Packet loss due to triple duplicate ACKs and timeout for each TCP flow
    retransmission_dup_ack = {}         # port : loss count
    retransmission_timeout = {}         # port : loss count

    for key in ack_loss_type:
        if ack_loss_type[key] > 2:
            if key[0] not in retransmission_dup_ack:
                retransmission_dup_ack[key[0]] = 1
            else:
                retransmission_dup_ack[key[0]] += 1

        elif ack_loss_type[key] == 2:
            if key[0] not in retransmission_timeout:
                retransmission_timeout[key[0]] = 1
            else:
                retransmission_timeout[key[0]] += 1

    for key in retransmission_timeout:
        print 'Packet loss due to timeout for Port: ' + str(key) + ' = ' + str(retransmission_timeout[key])
    for key in retransmission_dup_ack:
        print 'Packet loss due to triple duplicate ACKs for Port: ' + str(key) + ' = ' + \
              str(retransmission_dup_ack[key])
    # ---------------------------------------------------------------------------------------------------------------- #

    f.close()

if __name__ == '__main__':
    main()