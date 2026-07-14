import ipaddress
import sys

import numpy as np
import pandas as pd


if len(sys.argv) < 7:
    print("Usage: python programma.py <input_benevoli> <input_training> <input_valutation> <input_test> <out_directoy> <scenario>")
    sys.exit(1)

input_benevoli = sys.argv[1]
input_training = sys.argv[2]
input_valutation = sys.argv[3]
input_test = sys.argv[4]
out_directoy = sys.argv[5]
scenario = sys.argv[6].lower()


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
df_benevoli   = pd.read_csv(input_benevoli,   low_memory=False)
df_training   = pd.read_csv(input_training,   low_memory=False)
df_valutation = pd.read_csv(input_valutation, low_memory=False)
df_test       = pd.read_csv(input_test,       low_memory=False)

print("Operazioni pre-concatenazione")
# aggiungo etichetta per provenienza sample
df_benevoli['_source']   = 'benevoli'
df_training['_source']   = 'training'
df_valutation['_source'] = 'valutation'
df_test['_source']       = 'test'

df_benevoli['Label'] = 0
df_training['Label'] = 1
df_valutation['Label'] = 1
df_test['Label'] = 1

df_benevoli['DstBytes'] = df_benevoli['TotBytes'] - df_benevoli['SrcBytes']

print("Concatenazione")
data = pd.concat([df_benevoli, df_training, df_valutation, df_test], ignore_index=True)

# aggiunge colonna infect prima di droppare SrcAddr
# questa colonna serve per capire se il sample è interessato dalle perturbazioni o meno
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

dir = pd.get_dummies(data.Dir)
dir.columns = ["->", "?>", "<?", "<?>"]
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

    df_benevoli_proc   = data[data['_source'] == 'benevoli'].drop(columns=['_source'])
    df_training_proc   = data[data['_source'] == 'training'].drop(columns=['_source'])
    df_valutation_proc = data[data['_source'] == 'valutation'].drop(columns=['_source'])
    df_test_proc       = data[data['_source'] == 'test'].drop(columns=['_source'])

    df_training_proc.to_csv(f"{out_directoy}/NO_FD/solo_malevoli_training_out_no_fd.csv",   index=False)
    df_valutation_proc.to_csv(f"{out_directoy}/NO_FD/solo_malevoli_validation_out_no_fd.csv", index=False)
    df_test_proc.to_csv(f"{out_directoy}/NO_FD/solo_malevoli_test_out_no_fd.csv",           index=False)

    df_benevoli_proc = df_benevoli_proc.drop("infect", axis=1)
    df_training_proc = df_training_proc.drop("infect", axis=1)
    df_valutation_proc = df_valutation_proc.drop("infect", axis=1)
    df_test_proc = df_test_proc.drop("infect", axis=1)
	
    n_train = len(df_training_proc)
    n_val   = len(df_valutation_proc)
    n_test  = len(df_test_proc)

    total_benevoli_needed = n_train * 10 + n_val * 10 + n_test * 10

    if len(df_benevoli_proc) < total_benevoli_needed:
        raise ValueError(
            f"Benevoli insufficienti: ne servono {total_benevoli_needed}, "
            f"ne sono rimasti {len(df_benevoli_proc)} dopo l'elaborazione."
            )

    df_benevoli_shuffled = df_benevoli_proc.sample(frac=1, random_state=0).reset_index(drop=True)

    ben_for_train = df_benevoli_shuffled.iloc[:n_train * 10]
    ben_for_val   = df_benevoli_shuffled.iloc[n_train * 10 : n_train * 10 + n_val * 10]
    ben_for_test = df_benevoli_shuffled.iloc[n_train * 10 + n_val * 10 : n_train * 10 + n_val * 10 + n_test * 10]

    out_training   = pd.concat([df_training_proc,   ben_for_train], ignore_index=True)
    out_valutation = pd.concat([df_valutation_proc, ben_for_val],   ignore_index=True)
    out_test       = pd.concat([df_test_proc,       ben_for_test],  ignore_index=True)

    out_training.to_csv(f"{out_directoy}/NO_FD/training_out_no_fd.csv",   index=False)
    out_valutation.to_csv(f"{out_directoy}/NO_FD/validation_out_no_fd.csv", index=False)
    out_test.to_csv(f"{out_directoy}/NO_FD/test_out_no_fd.csv",           index=False)

    del out_training, out_valutation, out_test, df_training_proc, df_valutation_proc, df_test_proc, df_benevoli_proc,df_benevoli_shuffled, ben_for_train, ben_for_val, ben_for_test



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

    df_benevoli_proc   = data[data['_source'] == 'benevoli'].drop(columns=['_source'])
    df_training_proc   = data[data['_source'] == 'training'].drop(columns=['_source'])
    df_valutation_proc = data[data['_source'] == 'valutation'].drop(columns=['_source'])
    df_test_proc       = data[data['_source'] == 'test'].drop(columns=['_source'])

    df_training_proc.to_csv(f"{out_directoy}/FD/solo_malevoli_training_out_fd.csv",   index=False)
    df_valutation_proc.to_csv(f"{out_directoy}/FD/solo_malevoli_validation_out_fd.csv", index=False)
    df_test_proc.to_csv(f"{out_directoy}/FD/solo_malevoli_test_out_fd.csv",           index=False)
    
    df_benevoli_proc = df_benevoli_proc.drop("infect", axis=1)
    df_training_proc = df_training_proc.drop("infect", axis=1)
    df_valutation_proc = df_valutation_proc.drop("infect", axis=1)
    df_test_proc = df_test_proc.drop("infect", axis=1)

    n_train = len(df_training_proc)
    n_val   = len(df_valutation_proc)
    n_test  = len(df_test_proc)

    total_benevoli_needed = n_train * 10 + n_val * 10 + n_test * 10

    if len(df_benevoli_proc) < total_benevoli_needed:
        raise ValueError(
            f"Benevoli insufficienti: ne servono {total_benevoli_needed}, "
            f"ne sono rimasti {len(df_benevoli_proc)} dopo l'elaborazione."
            )

    df_benevoli_shuffled = df_benevoli_proc.sample(frac=1, random_state=0).reset_index(drop=True)

    ben_for_train = df_benevoli_shuffled.iloc[:n_train * 10]
    ben_for_val   = df_benevoli_shuffled.iloc[n_train * 10 : n_train * 10 + n_val * 10]
    ben_for_test = df_benevoli_shuffled.iloc[n_train * 10 + n_val * 10 : n_train * 10 + n_val * 10 + n_test * 10]

    out_training   = pd.concat([df_training_proc,   ben_for_train], ignore_index=True)
    out_valutation = pd.concat([df_valutation_proc, ben_for_val],   ignore_index=True)
    out_test       = pd.concat([df_test_proc,       ben_for_test],  ignore_index=True)

    out_training.to_csv(f"{out_directoy}/FD/training_out_fd.csv",   index=False)
    out_valutation.to_csv(f"{out_directoy}/FD/validation_out_fd.csv", index=False)
    out_test.to_csv(f"{out_directoy}/FD/test_out_fd.csv",           index=False)

    del out_training, out_valutation, out_test, df_training_proc, df_valutation_proc, df_test_proc, df_benevoli_proc,df_benevoli_shuffled, ben_for_train, ben_for_val, ben_for_test


data_fd = data.copy()
data_clean = data.copy()
del data

processing_feature_derivate(data_fd)
processing_clean(data_clean)
