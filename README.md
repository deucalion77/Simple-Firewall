# Simple-Firewall
Simple firewall with capability to block IP addresses and monitor traffic


V22 is Monitoring part
V4 is the up and running firewall


before running install the nessesary libries
* prettytable
* netfilterqueue
* scapy



Add following command before running
 iptables -I INPUT -d 192.168.0.0/16 -j NFQUEUE --queue-num 1





This firewall gives the functinality to monitor live traffic and also it is capable of blocking ports , IP Addresses
and if a ping is send to the host firewall will detect it and show it to the user 
if a ping request is more than 10 request firewall will ask user for blocking IP address
if user didnt block the IP address that sending ping requests firewall will automaticly block the IP after 20 requests





 I used some code parts from this github repo
 https://github.com/naklecha/firewall
