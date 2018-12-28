# Wireless Quality Monitor - NetTracker

## Introduction
This project was born from the need to perform automated monitoring and
diagnostics across the University of Southampton eduroam network as part of 
our ongoing investigations into a number of issues that were reported by 
students.

NetTracker is part of the suite of tools we wrote to perform passive analysis
of the eduroam network, in particular relating to out-of-subnet ARP traffic
which has been seen on some captures.

## What does NetTracker do
NetTracker tracks counts of ARP and ICMP6 traffic and optionally can report the
data that it sees back to a centralised server for further analysis.  If no
remote upload target is given, NetTracker logs all information to stdout in
either human (-H) or machine readable (default) format.

By default, it reports over ARP traffic and ICMPv6 traffic.

## Output format

All output lines are prepended with a date and timestamp (in square brackets for human readable, and without the brackets for computer readable).

Approximately once a minute, NetTracker will output a Statistics line (machine
format) or Statistics report (human format).

The statistics line is a line that starts with the word "STAT", followed by a
key=value pair string.

All values are values since the last stats dump.

Valid keys are:
 - arp (Total number of ARP packets seen)
 - arp\_wrongnet (Number of ARP packets seen in the wrong network)
 - arp\_mac\_changed (Number of ARP packets seen with a changed MAC address)
 - arp\_gratuitous (Number of gratuitous ARP packets seen)
 - icmp6 (Total number of ICMPv6 packets seen)
 - icmp6\_ns\_wrongnet (Neighbour solicitations seen in the wrong subnet)
 - icmp6\_na\_wrongnet (Neighbour advertisements seen in the wrong subnet)
 - icmp6\_ra\_wrongnet (Router advertisements seen for a subnet not present locally)

In addition to the STAT lines, nettracker will print alerts for every packet
received that it has reason to object to.  You can tune these by specifying
various collections of the -A? and -I? options to enable and disable specific
alerts.

Alert lines start with the word "ALERT", a space, the type of packet, a space
the specific alert type and then finally the packet headers.

For example, an ICMPv6 out-of-subnet NS may show up as follows:

> ALERT ICMPv6 ns\_wrongnet smac=00:11:22:33:44:55,dmac=FF:EE:DD:CC:BB:AA,sip=2001:630:d0:5000::2,dip=2001:630:d0:5000:FDEE:DDFF:FECC:BBAA
