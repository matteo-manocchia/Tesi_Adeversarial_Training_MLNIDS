from scapy.all import *
import random
import string
import time
from datetime import datetime
from tqdm import tqdm
import sys
import os

if len(sys.argv) < 6:
    print("Usage: python programma.py <input_folder> <output_folder> <lower_padding> <upper_padding> <run>")
    sys.exit(1)

input_folder = sys.argv[1]
output_folder = sys.argv[2]
lower_padding = sys.argv[3]
upper_padding = sys.argv[4]
numero_run = sys.argv[5]

filters = [] #filters = ['DHCP', 'DNS'] 

max_len = 1500 
trigger = 100000 

lower_padding = int(lower_padding)
upper_padding = int(upper_padding)
numero_run = int(numero_run)

seed = numero_run * 10000 + upper_padding
random.seed(seed)



def randStr(chars = string.ascii_uppercase + string.digits, lower=0, upper=100):
    # pacchetto già sopra MTU
    if upper < 0:
        upper = lower = 0
    # paddiamo solo per lo spazio che abbiamo
    if upper < lower:
        lower = upper
    padding = random.randint(lower, upper)
    return ''.join(random.choice(chars) for _ in range(padding))



def byte_tcp(input_file, output_file, lower=0, upper=100, max_size = 1500):
    start = time.time()
    print("Start Time\n{}".format(datetime.now()))

    input_pcap_size = int(os.path.getsize(input_file) / (1024*1024))
    print("Reading {}MB from {}".format(input_pcap_size, input_file))
    read = 0
    manipulated = 0
    
    with PcapReader(input_file) as pr, PcapWriter(output_file) as pw:
        print("Manipulating...")
        for pkt in pr:
            read += 1
            if ((read%trigger) == 0):
                print("...read {} packets...".format(int(read)))
            if 'error' in pkt.summary():
                pw.write(pkt)

            elif 'UDP' in pkt.summary():
                pw.write(pkt)

            elif 'TCP' in pkt.summary():
                if "P" not in pkt['TCP'].flags: 
                    pw.write(pkt)
                    continue
                
                if len(filters)>0:
                    if any(f in pkt.summary() for f in filters):
                        pw.write(pkt)
                        continue
                  
                manipulated += 1
                padding = randStr(lower=lower, upper=min((max_size - pkt.len), upper))

                new_pkt = (pkt['Ether'] / padding)

                if 'IPv6' in pkt.summary():
                    del new_pkt['IPv6'].len
                    del new_pkt['IPv6'].chksum
                else:
                    del new_pkt['IP'].len
                    del new_pkt['IP'].chksum
                del new_pkt['TCP'].chksum
                new_pkt = Ether(new_pkt.build())
                new_pkt.time = pkt.time
                pw.write(new_pkt)

            else:
                pw.write(pkt)

    print("Total packets read: {}".format(read))
    print("Manipulated {} ".format(manipulated))

    end = time.time() - start
    print("End Time:\n{}".format(datetime.now()))

    output_pcap_size = int(os.path.getsize(output_file) / (1024*1024))
    diff = output_pcap_size - input_pcap_size
    print("Wrote a total of {}MB (diff: {}MB) to file: {}".format(output_pcap_size, diff, output_file))


for malware in tqdm(sorted(os.listdir(input_folder))):
    malware_path = os.path.join(input_folder, malware)
    
    if not os.path.isdir(malware_path):
        continue

    os.makedirs(os.path.join(output_folder, malware), exist_ok=True)

    for original_pcap in tqdm(sorted(os.listdir(malware_path))):
        if not original_pcap.endswith(".pcap"):
            continue  

        n = original_pcap.replace(".pcap", "_pert.pcap")
        input_file  = os.path.join(input_folder, malware, original_pcap)
        output_file = os.path.join(output_folder, malware, n)
        byte_tcp(input_file, output_file, lower=lower_padding, upper=upper_padding)
