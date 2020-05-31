# Return common TCP source & destination ports and IP header ID of two PCAPs, even if one has IP encapsulated in GRE
# Wireshark task automation: read PCAPs, if GRE included read pcap[frameNr][GRE][IP].proto to confirm TCP, then pcap[frameNr][GRE][IP].id/sport/dport 
# Bogdan Adrian Burciu (https://github.com/bogdanadrian-burciu/) 25/05/2020 vers 500

#!/usr/bin/python3

from scapy.all import *  # to filter frames with the Scapy library, sniff() method
import os  # just to get the file name from the absolute path, os.path.basename() method
from termcolor import colored  # to be able to color text in console, method colored()


def getFrameNrIdPorts(PCAPpath):  # returneaza un dictionar cu cheie = frameNr si valoarea o lista de elemente (ip.ip, tcp.srcport, tcp.dstport)
    listHeader = []
    dictFrame = {}
    dictID = {}
    dictSport = {}
    dictDport = {}
    listFrame = []
    pcap = sniff(offline=PCAPpath)  # sniff(offline="/root/PCAP.pcapng", filter="tcp") filtering only TCP frames in PCAP file
    for frameNr in range(0, len(pcap), 1):
        if GRE in pcap[frameNr]:	# if GRE header is preset in frame x of PCAP, read its [GRE][IP] values
            if pcap[frameNr][GRE][IP].proto == 6:
                listHeader = [ pcap[frameNr][GRE][IP].id, pcap[frameNr][GRE][IP].sport, pcap[frameNr][GRE][IP].dport ]
                dictFrame[frameNr] = listHeader  # dictFrame e un dictFrameionar cu key=frame number si value=lista de (IP ID, TCP S port, TCP D port)
                dictID[frameNr] = pcap[frameNr][GRE][IP].id		# dictID = {frameNr: IP ID of frameNr}
                dictSport[frameNr] = pcap[frameNr][GRE][IP].sport
                dictDport[frameNr] = pcap[frameNr][GRE][IP].dport
                listFrame = [dictID, dictSport, dictDport]		# listaFrame = [{1:0x2345}, {1:54321}, {1:443}]
            else:
                continue
        else:
            if pcap[frameNr].proto == 6: # if GRE header is NOT preset in frame x of PCAP, read its values drectly from regular offsets
                listHeader = [pcap[frameNr].id, pcap[frameNr].sport, pcap[frameNr].dport]
                dictFrame[
                    frameNr] = listHeader  # dictFrame e un dictFrameionar cu key=frame number si value=lista de (IP ID, TCP S port, TCP D port)
                dictID[frameNr] = pcap[frameNr].id
                dictSport[frameNr] = pcap[frameNr].sport
                dictDport[frameNr] = pcap[frameNr].dport
                listFrame = [dictID, dictSport, dictDport]
            else:
                continue

        #     print(f"Lungimea capturii e de {len(pcap)} frame uri.")
    for key in dictFrame:
        print(f"The frame number {key + 1} of '{os.path.basename(PCAP1path)}' has: \n\t\t IP header identification id ==> {hex(dictFrame[key][0])}, \n\t\t TCP source port ==> {dictFrame[key][1]}, \n\t\t TCP destination port ==> {dictFrame[key][2]} \n")

    return listFrame

# listF=getFrameNrIdPorts("/root/Downloads/TCP_ACK#1+2.pcapng")
# print(listF)	# dictFrame is not global, so need to assign it to module level to get its value

while (True):
    print("""\n
0 - For returning frames with IP header ID and TCP S&D identical port between captures before and after an MTU / TCP stack end (eg input and output vTap SVM);
1 - For returning frames with identical IP header ID between captures before and after a TCP stack (eg ASSL P85 browser side vs ASSL P86);
Anything else - For the exit;
### Note1: The compared captures can even be encapsulated in L2GRE, in which case the TCP and IP headers carried by GRE will be read. ###
### Note2: The PCAPs compared should not contain any non-IP frames, like ARPs, case in which the scapy filtering sniff(offline="/root/PCAP.pcapng", filter="tcp") needs to be used to ensure no 'AttributeError: proto' gets returned ###
""")
    choice = input("\nPlease choose a menu option:\t")

    if (choice == "0"):
        PCAP1path = input("Please input absolute path to the file \n(like: '/root/Downloads/TCP_ACK.pcapng' for Linux \nor 'C:\\Users\\boburciu\\Desktop\\Viorel_Wireshark Captures_25May\\Wireshark Captures\\Wireshark_Capture New Test Vm.pcapng' for Win):")
        PCAP2path = input("Please input absolute path to the file \n(like: '/root/Downloads/TCP_ACK#1+2.pcapng for Linux' \nor 'C:\\Users\\boburciu\\Desktop\\Viorel_Wireshark Captures_25May\\Wireshark Captures\\Wireshark Capture VM1 - Originating Server.pcapng' for Win):")
        listPCAP1 = getFrameNrIdPorts(PCAP1path)
        listPCAP2 = getFrameNrIdPorts(PCAP2path)
        counterSport = 0
        for e1 in range(0, len(listPCAP1[0]), 1):
            for e2 in range(0, len(listPCAP2[0]), 1):
                if listPCAP1[1][e1] == listPCAP2[1][e2] and listPCAP1[2][e1] == listPCAP2[2][e2]:  # S port (prima pereche) si D port identic intre capturi diferite
                    counterSport = counterSport + listPCAP1[1][e1]
                    if counterSport == listPCAP1[1][e1]:  # only the first occurence of TCP session for given tcp.srcport && tcp.dstport comb
                        print(colored(f"\nPCAP '{os.path.basename(PCAP1path)}' ", "green"), (f"<= has common TCP Session src.port={listPCAP1[1][e2]} & dst.port={listPCAP1[2][e1]} =>"),colored(f"with '{os.path.basename(PCAP2path)}' ", "red"),"\n")  # os.path.basename(/root/Downloads/TCP_ACK.pcapng) = TCP_ACK.pcapng
                        if listPCAP1[0][e1] == listPCAP2[0][e2]:  # if ip.id identic intre frame uri din PCAPuri diferite
                            print(colored(f"\t\tFrame#{e1 + 1} ", "green"),(f"<= same ip.id=={hex(listPCAP1[0][e1])} =>"), colored(f"\t\tFrame#{e2 + 1}","red"), )  # os.path.basename(/root/Downloads/TCP_ACK.pcapng) = TCP_ACK.pcapng

    elif choice == "1":
        PCAP1path = input("Please input absolute path to the file \n(like: '/root/Downloads/TCP_ACK.pcapng' for Linux \nor 'C:\\Users\\boburciu\\Desktop\\Viorel_Wireshark Captures_25May\\Wireshark Captures\\Wireshark_Capture New Test Vm.pcapng' for Win):")
        PCAP2path = input("Please input absolute path to the file \n(like: '/root/Downloads/TCP_ACK#1+2.pcapng for Linux' \nor 'C:\\Users\\boburciu\\Desktop\\Viorel_Wireshark Captures_25May\\Wireshark Captures\\Wireshark Capture VM1 - Originating Server.pcapng' for Win):")
        listPCAP1 = getFrameNrIdPorts(PCAP1path)
        listPCAP2 = getFrameNrIdPorts(PCAP2path)
        for e1 in range(0, len(listPCAP1[0]), 1):
            for e2 in range(0, len(listPCAP2[0]), 1):
                if listPCAP1[0][e1] == listPCAP2[0][e2]:
                    print(colored(f"Frame#{e1 + 1} of '{os.path.basename(PCAP1path)}'", "green"), (f"<= same TCP Session src.port={listPCAP1[1][e1]} & dst.port={listPCAP1[2][e1]} & ip.id=={hex(listPCAP1[0][e1])} =>"), colored(f"Frame#{e2 + 1} of '{os.path.basename(PCAP2path)}'", "red"))

    elif (choice != '0' or choice != '1'):
        break

