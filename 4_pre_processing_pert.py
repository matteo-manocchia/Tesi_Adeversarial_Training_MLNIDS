import ipaddress
import sys
import os
import numpy as np
import pandas as pd


if len(sys.argv) < 4:
    print("Usage: python programma.py <input_malevoli> <out_directoy> <scenario>")
    sys.exit(1)

input_malevoli = sys.argv[1]
out_directoy = sys.argv[2]
scenario = sys.argv[3].lower()

nome_file = os.path.splitext(os.path.basename(input_malevoli))[0]

BOTNET_CONFIG = {
    'neris':   ['147.32.84.165', '147.32.84.191', '147.32.84.192', '147.32.84.193',
                '147.32.84.204', '147.32.84.205', '147.32.84.206', '147.32.84.207',
                '147.32.84.208', '147.32.84.209'],
    'rbot':    ['147.32.84.165', '147.32.84.191', '147.32.84.192', '147.32.84.193',
                '147.32.84.204', '147.32.84.205', '147.32.84.206', '147.32.84.207',
                '147.32.84.208', '147.32.84.209'],
    'virut':   ['147.32.84.165'],
    'menti':   ['147.32.84.165'],
    'sogou':   ['147.32.84.165'],
    'murlo':   ['147.32.84.165'],
    'nsis':    ['147.32.84.165', '147.32.84.191', '147.32.84.192'],
}


if scenario not in BOTNET_CONFIG:
    print(f"[ERRORE] Scenario '{scenario}' non riconosciuto. Valori validi: {list(BOTNET_CONFIG.keys())}")
    sys.exit(1)

infected_ips = BOTNET_CONFIG[scenario]

print("Lettura csv")
data = pd.read_csv(input_malevoli,   low_memory=False)

data['Label'] = 1

data['infect'] = data['SrcAddr'].isin(infected_ips)

print("Inizio processing")
data = data.drop("StartTime", axis=1)

data = data[data.Proto == "tcp"]
data.Proto = data.Proto.replace("tcp", "0").astype(int)

data.sTos = data.sTos.replace(np.nan, 0.0)

data.dTos = data.dTos.replace(np.nan, 0.0)

data = data.dropna()

ipsrctype = data.SrcAddr.apply(
    lambda addr: (
        1
        if (ipaddress.ip_address(addr) in ipaddress.ip_network("147.32.0.0/16"))
        else 0
    )
)
data.insert(2, "IPSrcType", ipsrctype)
data = data.drop("SrcAddr", axis=1)

ipdsttype = data.DstAddr.apply(
    lambda addr: (
        1
        if (ipaddress.ip_address(addr) in ipaddress.ip_network("147.32.0.0/16"))
        else 0
    )
)
data.insert(3, "IPDstType", ipdsttype)
data = data.drop("DstAddr", axis=1)

print("Calcolo tipologia di porte")
sport = data.Sport.astype(int)
srcportwellknown = (sport >= 0) & (sport <= 1023)
srcportwellknown = srcportwellknown.astype(int)
srcportregistered = (sport >= 1024) & (sport <= 49151)
srcportregistered = srcportregistered.astype(int)
srcportprivate = sport >= 49152
srcportprivate = srcportprivate.astype(int)
data.insert(4, "SrcPortWellKnown", srcportwellknown)
data.insert(5, "SrcPortRegistered", srcportregistered)
data.insert(6, "SrcPortPrivate", srcportprivate)
data = data.drop("Sport", axis=1)

dport = data.Dport.astype(int)
dstportwellknown = (dport >= 0) & (dport <= 1023)
dstportwellknown = dstportwellknown.astype(int)
dstportregistered = (dport >= 1024) & (dport <= 49151)
dstportregistered = dstportregistered.astype(int)
dstportprivate = dport >= 49152
dstportprivate = dstportprivate.astype(int)
data.insert(7, "DstPortWellKnown", dstportwellknown)
data.insert(8, "DstPortRegistered", dstportregistered)
data.insert(9, "DstPortPrivate", dstportprivate)
data = data.drop("Dport", axis=1)

expected = ["->", "?>", "<?", "<?>"]
dir = pd.get_dummies(data.Dir.str.strip()).reindex(columns=expected, fill_value=0)
data.insert(10, "->", dir["->"].astype(int))
data.insert(11, "?>", dir["?>"].astype(int))
data.insert(12, "<?", dir["<?"].astype(int))
data.insert(13, "<?>", dir["<?>"].astype(int))
data = data.drop("Dir", axis=1)

state = data.State.str.split("_", expand=True)
state.columns = ["SrcState", "DstState"]
data.insert(
    14, "SrcStateA", state["SrcState"].str.contains("A", regex=False).astype(int)
)
data.insert(
    15, "SrcStateC", state["SrcState"].str.contains("C", regex=False).astype(int)
)
data.insert(
    16, "SrcStateE", state["SrcState"].str.contains("E", regex=False).astype(int)
)
data.insert(
    17, "SrcStateF", state["SrcState"].str.contains("F", regex=False).astype(int)
)
data.insert(
    18, "SrcStateP", state["SrcState"].str.contains("P", regex=False).astype(int)
)
data.insert(
    19, "SrcStateR", state["SrcState"].str.contains("R", regex=False).astype(int)
)
data.insert(
    20, "SrcStateS", state["SrcState"].str.contains("S", regex=False).astype(int)
)
data.insert(
    21, "SrcStateU", state["SrcState"].str.contains("U", regex=False).astype(int)
)
data.insert(
    22, "DstStateA", state["DstState"].str.contains("A", regex=False).astype(int)
)
data.insert(
    23, "DstStateC", state["DstState"].str.contains("C", regex=False).astype(int)
)
data.insert(
    24, "DstStateE", state["DstState"].str.contains("E", regex=False).astype(int)
)
data.insert(
    25, "DstStateF", state["DstState"].str.contains("F", regex=False).astype(int)
)
data.insert(
    26, "DstStateP", state["DstState"].str.contains("P", regex=False).astype(int)
)
data.insert(
    27, "DstStateR", state["DstState"].str.contains("R", regex=False).astype(int)
)
data.insert(
    28, "DstStateS", state["DstState"].str.contains("S", regex=False).astype(int)
)
data.insert(
    29, "DstStateU", state["DstState"].str.contains("U", regex=False).astype(int)
)
data = data.drop("State", axis=1)
data.loc[(data['infect'] == True) & (data['SrcStateP'] == 0), 'infect'] = False


def processing_clean(data):
    data = data[data.Dur < 300]
    data = data[data.TotPkts < 100]
    data = data[data.SrcBytes < 10000]
    data = data[data.DstBytes < 60000]

    data.to_csv(f"{out_directoy}/NO_FD/{nome_file}_no_fd.csv", index=False)
    del data



def processing_feature_derivate(data):
    bytesperpkt = data.TotBytes / data.TotPkts
    data.insert(36, 'BytesPerPkt', bytesperpkt)

    bytespersec = data.TotBytes / data.Dur
    data.insert(37, 'BytesPerSec', bytespersec)
    max = data.loc[data.BytesPerSec != np.inf, 'BytesPerSec'].max()
    print(f"BytesPerSec max totale: {max}")
    data.BytesPerSec = data.BytesPerSec.replace(np.inf, max)

    pktspersec = data.TotPkts / data.Dur
    data.insert(38, 'PktsPerSec', pktspersec)
    max = data.loc[data.PktsPerSec != np.inf, 'PktsPerSec'].max()
    print(f"PktsPerSec max totale: {max}")
    data.PktsPerSec = data.PktsPerSec.replace(np.inf, max)

    ratiooutin = data.SrcBytes / data.DstBytes
    data.insert(39, 'RatioOutIn', ratiooutin)
    max = data.loc[data.RatioOutIn != np.inf, 'RatioOutIn'].max()
    print(f"RatioOutIn max totale: {max}")
    data.RatioOutIn = data.RatioOutIn.replace(np.inf, max)

    data = data[data.Dur < 300]
    data = data[data.TotPkts < 100]
    data = data[data.SrcBytes < 10000]
    data = data[data.DstBytes < 60000]
    data = data[data.BytesPerSec < 400000]
    data = data[data.PktsPerSec < 10000]

    data.to_csv(f"{out_directoy}/FD/{nome_file}_fd.csv", index=False)
    del data


data_fd = data.copy()
data_clean = data.copy()
del data

processing_feature_derivate(data_fd)
processing_clean(data_clean)
