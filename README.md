# pcap_analyser

1. Wireshark Programming: Extract all the information from network bytes received based on TCP header and data part.
   Compute throughput, loss rate and average RTT for the pcap captured.

2. Congestion control: Estimation of initial congestion window size and look at it's variation. Extract retransmissions
   and segregate them in two parts: Due to triple duplicate acks and timeout.

3. HTTP Analysis: Reassemble each unique HTTP Request/Response and identify which HTTP protocol is being used for each
   PCAP collected file. Perform comparitive analysis on the basis of load speed and bytes sent out to network.
   
   Language: Python
   Library: dpkt
