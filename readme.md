# Onomondo Traffic Analyzer

Analyze the traffic from a pcap file and learn if there's something that stands out or if you could save something

## Installation

```
$ npm install -g onomondo-traffic-analyzer
$ onomondo-traffic-analyzer somefile.pcap
```

## Parameters

### type=[ethernet | ip]

Specify the type of the pcap file. Either it's `ip` or `ethernet`.

Optional, defaults to `ip`.

## Example on how to run

You need a pcap file somewhere. It's supposed to be a couple (or more) from one fleet.

```
$ onomondo-traffic-analyzer --type=ip somefile.pcap
```

which would return

```
🌎 Overall information
======================
Total traffic:    184.63 kB
TCP traffic:      174.79 kB (94% of all traffic)
UDP traffic:        9.84 kB (5% of all traffic)


👯‍♀️ TCP Retransmission information
=================================
Total TCP traffic:     159.89 kB (745 packets)
Resent TCP traffic:     11.11 kB (155 packets)
TCP retransmisisons count for 6% of all TCP traffic

The TCP retransmission says something about how much TCP traffic is resent.
It is not necesarrily a bad thing, but if the percentage is above 30% you could
mention to the customer that there is a lot of TCP retransmissions and that they
might want to look into that by using live monitor.


🔒 TLS Information
==================
Total traffic sent over TLS:    174.79 kB (94% of all traffic)
Meta traffic sent over TLS:     114.09 kB (61% of all traffic [potential removal if using connectors])

The TLS information is a good indicator on whether or not the customer might
gain from using connectors. If the meta traffic is above 50%, it means that they
could at least save 50% of that part of the traffic sent over the TLS.


🚦 Hosts information
====================
10.20.30.400         3.89 kB⬆      5.96 kB⬇  (5% of all traffic)
100.200.300.40      40.52 kB⬆    134.27 kB⬇  (94% of all traffic)

The information about hosts is something that could be shared with the customer
It can help them visualize if there are any hosts that shouldn't be there, or
if any of them use too much traffic.
```
