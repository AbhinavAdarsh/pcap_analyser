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
                total_rtt_time[seq_port_comb[0]] += (packet_rtt_ack[seq_port_comb] - packet_rtt_seq[seq_port_comb])
                packet_rtt_count[seq_port_comb[0]] += 1

def main():

    packets_lost = 0
    start_time = {}                 # port number : start time(ts)
    end_time = {}                   # port number : end time (ts)
    data_sent = {}
    packet_sent = {}
    packet_rcvd = {}

    packet_seq = {}                 # (source port, sequence number) : packet_count
    retransmitted_seq = {}          # (source port, retransmitted sequence) : packet_count
    total_packets_sent = {}         # source port : total  - For each TCP flow
    retran_packets_sent = {}        # source port : retransmitted - For each TCP flow

    packets_sent = {}               # source port : total packets sent
    packet_rtt_seq = {}             # (source port, sequence number) : timestamp
    packet_rtt_ack = {}             # (destination port, acknowledgement number) : timestamp
    total_rtt_time = {}             # port : rtt_time
    packet_rtt_count = {}           # port : packet_count

    seq_loss_type = {}              # (source port, sequence number) : packet count
    ack_loss_type = {}              # (source port, acknowledgement number) : packet count

    packet_ack = {}
    dup_ack = {}

    ack_num_win = 0                 # Acknowledgement number sent by receiver to sender
    seq_num_win = 0                 # Sequence number sent by sender to receiver
    congestion_window = defaultdict(list)          # Port : List to store window sizes

    total_packets_sent_source = 0
    total_packets_sent_dest = 0
    total_packets_rcvd_dest = 0
    total_packets_rcvd_source = 0
    MSS = 0

    ##########################
    sender_to_receiver = defaultdict(list)         # {port,ipadress : (seq, ack, window size)}
    receiver_to_sender = defaultdict(list)         # {port,ipadress : (seq, ack, window size)}
    ##########################

    f = open('assignment2.pcap')
    pcapRead = dpkt.pcap.Reader(f)
    i = 0
    tcp_flows = 0
    count = 0

    # For Congestion window
    expected_data = {}             # {port : expected_data}
    total_data = {}                # {port : total_data}
    packet_count = {}              # {port : packet_count}
    window_list = defaultdict(list)

    for ts, buf in pcapRead:

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

        # ------------------------------------------------------------------------------------------------------ #
        offset = ((header_fields.offset_resvd[0]) >> 4) * 4
        # Ethernet + IP +  TCP Header + Options field - To get the start of DATA field
        data_field = (14 + 20 + offset)

        if rcvd_source_ip == source_ip_address:
            if len(buf) > data_field:
                if header_fields.source_port[0] not in expected_data:
                    expected_data[header_fields.source_port[0]] = header_fields.seq_num[0] + len(buf) - data_field
                    total_data[header_fields.source_port[0]] = len(buf)
                    packet_count[header_fields.source_port[0]] = 1
                else:
                    total_data[header_fields.source_port[0]] += len(buf)
                    packet_count[header_fields.source_port[0]] += 1

        if rcvd_source_ip == destination_ip_address:
            if header_fields.dest_port[0] in expected_data and header_fields.ack_num[0] == \
                    expected_data[header_fields.dest_port[0]]:
                window_list[header_fields.dest_port[0]].append(total_data[header_fields.dest_port[0]])
                del expected_data[header_fields.dest_port[0]]
        # ------------------------------------------------------------------------------------------------------ #
        # Count the total number of TCP flows
        if header_fields.flags[0] & SYN_ACK == SYN_ACK:
            tcp_flows += 1
        # ------------------------------------------------------------------------------------------------------ #

        if header_fields.flags[0] & SYN == SYN and header_fields.flags[0] & ACK == ACK:
            header_fields.max_segment = struct.unpack('>H', buf[56:58])
            # Store the 'MAX Segment Size'
            MSS = header_fields.max_segment[0]

        if rcvd_source_ip == destination_ip_address:
            # Store first two transactions sent by receiver after handshake for each TCP flow
            receiver_to_sender[(header_fields.dest_port[0], rcvd_source_ip)].append((
                header_fields.seq_num[0], header_fields.ack_num[0], header_fields.window_size[0]))
            # ------------------------------------------------------------------------------------------------------ #

        if rcvd_source_ip == source_ip_address:
            # Store first two transactions sent by sender after handshake for each TCP flow
            sender_to_receiver[(header_fields.source_port[0], rcvd_source_ip)].append((
                header_fields.seq_num[0], header_fields.ack_num[0], header_fields.window_size[0]))
            # ------------------------------------------------------------------------------------------------------ #

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
            congestion_window[header_fields.source_port[0]].append(seq_num_win - ack_num_win)
            ack_num_win = 0

        # ---------------------------------------------------------------------------------------------------------- #

        if header_fields.ack_num[0] not in packet_ack:
            packet_ack[header_fields.ack_num[0]] = header_fields.source_port[0]
        else:
            if header_fields.ack_num[0] not in dup_ack:
                dup_ack[header_fields.ack_num[0]] = header_fields.source_port[0]

        if rcvd_dest_ip == destination_ip_address:
            if header_fields.dest_port[0] not in packet_rcvd:
                packet_rcvd[header_fields.dest_port[0]] = 1
            else:
                packet_rcvd[header_fields.dest_port[0]] += 1

        if source_ip_address == rcvd_source_ip:
            total_packets_sent_source += 1
        if source_ip_address == rcvd_dest_ip:
            total_packets_rcvd_source += 1
        if destination_ip_address == rcvd_source_ip:
            total_packets_sent_dest += 1
        if destination_ip_address == rcvd_dest_ip:
            total_packets_rcvd_dest += 1

    start_time_set = set(start_time)
    end_time_set = set(end_time)

    # ---------------------------------------------------------------------------------------------------------------- #
    # Part A.1 : Number of TCP flows initiated form the sender
    print "Total TCP flows initiated = "+str(tcp_flows)
    print '--------------------------------------------'

    # ---------------------------------------------------------------------------------------------------------------- #
    # Part A.2 : For each TCP flow - First two transactions after connection set up
    # (Sequence number, Acknowledgement number, Window size) values
    print 'Sender to Receiver:'
    for key in sender_to_receiver:
        items = 0
        for val in sender_to_receiver[key]:
            items += 1
            if 2 < items < 5:
                print 'For flow on port: ' + str(key[0]) + ' ' + str(val)

    print '-------------------------------------------------------------'
    print 'Receiver to Sender:'
    for key in receiver_to_sender:
        items = 0
        for val in receiver_to_sender[key]:
            items += 1
            if 1 < items < 4:
                print 'For flow on port: ' + str(key[0]) + ' ' + str(val)
    print '-------------------------------------------------------------'

    # ---------------------------------------------------------------------------------------------------------------- #

    for index in start_time_set.intersection(end_time_set):
        # print index, start_time[index], end_time[index]
        print 'For Port '+str(index) + ': ' + str(data_sent[index]) + ' bytes were sent for '+ \
              str(end_time[index] - start_time[index]) + ' seconds, Throughput = '+ \
              str((data_sent[index]/1024) / (end_time[index] - start_time[index]))
    print '-------------------------------------------------------------------------------------'

    # ---------------------------------------------------------------------------------------------------------------- #
    # Part A.2. (c) Calculate Loss rate for each TCP flow

    loss_rate_dict = {}        # {port : loss_rate}
    print 'Sender to Receiver:'
    for key in sender_to_receiver:
        unique_seq_num = set()
        for val in sender_to_receiver[key]:
            unique_seq_num.add(val[0])
        print 'Loss Rate of TCP flow for Port: ' + str(key[0]) + ' = ' + str(float(len(sender_to_receiver[key])
              - (len(unique_seq_num) + 1)) / len(sender_to_receiver[key]))
    print '-------------------------------------------------------------------------------------'

    print 'Receiver to Sender:'
    for key in receiver_to_sender:
        unique_ack_num = set()
        for val in receiver_to_sender[key]:
            unique_ack_num.add(val[1])
        print 'Loss Rate of TCP flow for Port: ' + str(key[0]) + ' = ' + str(float(len(receiver_to_sender[key]) -
                                                     len(unique_ack_num)) / len(receiver_to_sender[key]))
    print '-------------------------------------------------------------------------------------'
    # ---------------------------------------------------------------------------------------------------------------- #

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
    #
    # for key in total_packets_sent_set.intersection(retran_packets_sent_set):
    #     print 'Loss Rate of TCP flow for Port: ' + str(key) + ' = ' + str(float(retran_packets_sent[key]*100) /
    #                                                                       float(total_packets_sent[key])) + '%'
    # ---------------------------------------------------------------------------------------------------------------- #
    # Part A.2. (d) Calculate the Average RTT for each TCP flow
    calculate_average_rtt(packet_rtt_seq, packet_rtt_ack, total_rtt_time, packet_rtt_count)

    total_rtt_time_set = set(total_rtt_time)
    packet_rtt_count_set = set(packet_rtt_count)
    average_rtt_dict = {}       # {port : average_rtt}

    for key in total_rtt_time_set.intersection(packet_rtt_count_set):
        average_rtt_dict[key] = (total_rtt_time[key] / packet_rtt_count[key])
        print 'Average RTT of TCP flow for Port: ' + str(key) + ' = ' + str(average_rtt_dict[key])
    print '-------------------------------------------------------------------------------------'
    # ---------------------------------------------------------------------------------------------------------------- #
    # Calculate theoretical throughput and compare it with empirical throughput calculated
    # Formula for calculating throughput : (sqrt(3/2) * (MSS / (sqrt(p) * Average RTT)))

    print 'Sender to Receiver:'
    for key in sender_to_receiver:
        unique_seq_num = set()
        for val in sender_to_receiver[key]:
            unique_seq_num.add(val[0])
        p = (float(len(sender_to_receiver[key])
              - (len(unique_seq_num) + 1)) / len(sender_to_receiver[key]))

        if key[0] in average_rtt_dict:
            if p != 0:
                #print key[0], average_rtt_dict[key[0]]
                print 'Theoretical throughput for Port: ' + str(key[0]) + ' = ' \
                      + str((math.sqrt(3 / 2) * ((MSS/1024) / (math.sqrt(p) * average_rtt_dict[key[0]]))))
            else:
                print 'Theoretical throughput for Port: ' + str(key[0]) + ' = infinity'
    print '-------------------------------------------------------------------------------------'

    # ---------------------------------------------------------------------------------------------------------------- #
    # PART B.1: Initial 10 (if available) congestion window sizes for each TCP flow

    for key in window_list:
        print 'First 10 Congestion Window sizes for Port: ' + str(key) + ' ' + str(window_list[key])
    print '-------------------------------------------------------------------------------------'
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
    # for key in sender_to_receiver:
    #     unique_seq_num = set()
    #     for val in sender_to_receiver[key]:
    #         unique_seq_num.add(val[0])
    #     print 'Loss Rate of TCP flow for Port: ' + str(key[0]) + ' = ' + str(float(len(sender_to_receiver[key])
    #           - (len(unique_seq_num) + 1)) / len(sender_to_receiver[key]))
    ret_packet_dict = {}        # {(port, ack_num) : packet_count}
    send_packet_dict = {}       # {(port, seq_num) : packet_count}

    # for key in receiver_to_sender:
    #     for val in receiver_to_sender[key]:
    #         #print val
    #         if (key[0], val[1]) not in ret_packet_dict:
    #             ret_packet_dict[(key[0], val[1])] = 1
    #         else:
    #             ret_packet_dict[(key[0], val[1])] += 1
    #
    # for key in sender_to_receiver:
    #     for val in sender_to_receiver[key]:
    #         #print val
    #         if (key[0], val[0]) not in send_packet_dict:
    #             send_packet_dict[(key[0], val[0])] = 1
    #         else:
    #             send_packet_dict[(key[0], val[0])] += 1
    #
    # cnt = 0
    # for key in ret_packet_dict:
    #     if ret_packet_dict[key] > 3:
    #         if key in send_packet_dict:
    #             if send_packet_dict[key] > 1:
    #                 cnt += 1
    # print cnt

    f.close()


if __name__ == '__main__':
    main()