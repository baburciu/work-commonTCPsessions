# work-commonTCPsessions
Return common TCP source &amp; destination ports and IP header ID of two PCAPs, even if one has the IP payload encapsulated in L2GRE.
Comes handy when analyzing PCAPs pre- and post- a TCP stack endpoint or MTU-changing device.

Allows for determining packet reordering:
:
Frame#12 of 'Wireshark Capture VM1 - Originating Server.pcapng' <= same TCP Session src.port=53251 & dst.port=102 & ip.id==0x3108 => Frame#12 of 'Wireshark_Capture New Test Vm.pcapng'
Frame#13 of 'Wireshark Capture VM1 - Originating Server.pcapng' <= same TCP Session src.port=102 & dst.port=53251 & ip.id==0xda2 => Frame#14 of 'Wireshark_Capture New Test Vm.pcapng'
Frame#14 of 'Wireshark Capture VM1 - Originating Server.pcapng' <= same TCP Session src.port=102 & dst.port=53251 & ip.id==0xda3 => Frame#15 of 'Wireshark_Capture New Test Vm.pcapng'
Frame#15 of 'Wireshark Capture VM1 - Originating Server.pcapng' <= same TCP Session src.port=102 & dst.port=53251 & ip.id==0xda4 => Frame#16 of 'Wireshark_Capture New Test Vm.pcapng'
Frame#16 of 'Wireshark Capture VM1 - Originating Server.pcapng' <= same TCP Session src.port=53251 & dst.port=102 & ip.id==0x3109 => Frame#13 of 'Wireshark_Capture New Test Vm.pcapng'
Frame#17 of 'Wireshark Capture VM1 - Originating Server.pcapng' <= same TCP Session src.port=102 & dst.port=53251 & ip.id==0xda5 => Frame#17 of 'Wireshark_Capture New Test Vm.pcapng'
