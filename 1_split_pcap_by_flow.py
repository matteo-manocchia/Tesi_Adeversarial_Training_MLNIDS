from scapy.all import PcapReader, PcapWriter, IP, TCP, UDP
import random
import sys


if len(sys.argv) < 5:
    print("Usage: python split_pcap_by_flow.py <input_pcap> <output_training> <output_validation> <output_test>")
    sys.exit(1)

input_pcap = sys.argv[1]
output_training = sys.argv[2]
output_validation = sys.argv[3]
output_test = sys.argv[4]


# andiamo ad estrarre la chiave di flusso da ogni pacchetto -> (IP srg, PORT srg, IP dst, PORT dst, PROTO)
def get_flow_key(pkt):
    if IP not in pkt:
        return None
    proto = pkt[IP].proto #estraggo protocollo dall'header
    src, dst = pkt[IP].src, pkt[IP].dst
    sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
    dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
    # così gestiamo la bidirezionalità del flusso
    # sia A->B che B->A fanno aprte dello stesso flusso
    return tuple(sorted([(src, sport), (dst, dport)])) + (proto,)



# per ogni pacchetto estrae la chiave di flusso e la mette nel set
# serve per capire quanti flussi distinti ci sono nel pcap
flow_keys_seen = set()
with PcapReader(input_pcap) as reader:
    for pkt in reader:
        key = get_flow_key(pkt)
        if key:
            flow_keys_seen.add(key)


# mescola i flussi li assegna a train/val/test 
flow_keys = list(flow_keys_seen)
random.seed(0)
random.shuffle(flow_keys)

n = len(flow_keys)
cut1 = int(n * 0.70)
cut2 = int(n * 0.85)

flow_assignment = {}
for k in flow_keys[:cut1]:
    flow_assignment[k] = "train"
for k in flow_keys[cut1:cut2]:
    flow_assignment[k] = "val"
for k in flow_keys[cut2:]:
    flow_assignment[k] = "test"


# assegno ogni pacchetto ad un set
writers = {
    "train": PcapWriter(output_training, append=False, sync=True),
    "val": PcapWriter(output_validation, append=False, sync=True),
    "test": PcapWriter(output_test, append=False, sync=True),
}

# scrittura su file
with PcapReader(input_pcap) as reader:
    for pkt in reader:
        key = get_flow_key(pkt)
        if key and key in flow_assignment:
            writers[flow_assignment[key]].write(pkt)

for w in writers.values():
    w.close()
