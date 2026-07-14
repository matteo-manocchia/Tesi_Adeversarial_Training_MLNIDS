import gc
import ipaddress
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier


if len(sys.argv) < 4:
    print("Usage: python preproc_modl_adv_tra.py <input_benevoli> <csv_partenza_dir> <perturbati_dir>")
    sys.exit(1)

input_benevoli   = sys.argv[1]
csv_partenza_dir = sys.argv[2]
perturbati_dir   = sys.argv[3]

OUTPUT_BASE = "./Modelli_adversarial"

BOTNETS = ['Murlo', 'Neris', 'Virut']

PADDINGS = [
    'Random_1_100', 'Random_100_1024', 'Random_1_1500',
    '1_bytes', '8_bytes', '16_bytes', '32_bytes', '64_bytes',
    '96_bytes', '128_bytes', '256_bytes', '352_bytes', '512_bytes', '1024_bytes',
]


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


def processing_clean(data, model_filename):
    data = data[data.Dur < 300]
    data = data[data.TotPkts < 100]
    data = data[data.SrcBytes < 10000]
    data = data[data.DstBytes < 60000]

    df_malevoli_proc = data[data['_source'] == 'malevoli'].drop(columns=['_source', 'infect'])
    df_benevoli_proc = data[data['_source'] == 'benevoli'].drop(columns=['_source', 'infect'])
    del data
    gc.collect()

    n_mal = len(df_malevoli_proc)
    n_ben_needed = n_mal * 10

    if len(df_benevoli_proc) < n_ben_needed:
        raise ValueError(
            f"Benevoli insufficienti (NO_FD): ne servono {n_ben_needed}, "
            f"ne sono rimasti {len(df_benevoli_proc)} dopo l'elaborazione."
        )

    ben_for_train = df_benevoli_proc.sample(frac=1, random_state=0).reset_index(drop=True).iloc[:n_ben_needed]
    training_set  = pd.concat([df_malevoli_proc, ben_for_train], ignore_index=True)
    del df_malevoli_proc, df_benevoli_proc, ben_for_train
    gc.collect()

    X_train = training_set.drop(columns=['Label'])
    y_train = training_set['Label']
    del training_set
    gc.collect()

    model = RandomForestClassifier(
        n_estimators=200, criterion='gini', max_depth=None,
        min_samples_split=2, min_samples_leaf=1,
        min_weight_fraction_leaf=0.0, max_features='sqrt',
        max_leaf_nodes=None, min_impurity_decrease=0.0,
        bootstrap=True, oob_score=False, n_jobs=2,
        random_state=0, verbose=0, warm_start=False,
        class_weight=None, ccp_alpha=0.0, max_samples=None
    )
    model.fit(X_train, y_train)
    del X_train, y_train
    gc.collect()

    joblib.dump(model, model_filename)
    del model
    gc.collect()


def processing_feature_derivate(data, model_filename):
    data.insert(36, 'BytesPerPkt', data.TotBytes / data.TotPkts)

    bytespersec = data.TotBytes / data.Dur
    data.insert(37, 'BytesPerSec', bytespersec)
    max_bps = data.loc[data.BytesPerSec != np.inf, 'BytesPerSec'].max()
    data.BytesPerSec = data.BytesPerSec.replace(np.inf, max_bps)

    pktspersec = data.TotPkts / data.Dur
    data.insert(38, 'PktsPerSec', pktspersec)
    max_pps = data.loc[data.PktsPerSec != np.inf, 'PktsPerSec'].max()
    data.PktsPerSec = data.PktsPerSec.replace(np.inf, max_pps)

    ratiooutin = data.SrcBytes / data.DstBytes
    data.insert(39, 'RatioOutIn', ratiooutin)
    max_roi = data.loc[data.RatioOutIn != np.inf, 'RatioOutIn'].max()
    data.RatioOutIn = data.RatioOutIn.replace(np.inf, max_roi)

    data = data[data.Dur         < 300]
    data = data[data.TotPkts     < 100]
    data = data[data.SrcBytes    < 10000]
    data = data[data.DstBytes    < 60000]
    data = data[data.BytesPerSec < 400000]
    data = data[data.PktsPerSec  < 10000]

    df_malevoli_proc = data[data['_source'] == 'malevoli'].drop(columns=['_source', 'infect'])
    df_benevoli_proc = data[data['_source'] == 'benevoli'].drop(columns=['_source', 'infect'])
    del data
    gc.collect()

    n_mal = len(df_malevoli_proc)
    n_ben_needed = n_mal * 10

    if len(df_benevoli_proc) < n_ben_needed:
        raise ValueError(
            f"Benevoli insufficienti (FD): ne servono {n_ben_needed}, "
            f"ne sono rimasti {len(df_benevoli_proc)} dopo l'elaborazione."
        )

    ben_for_train = df_benevoli_proc.sample(frac=1, random_state=0).reset_index(drop=True).iloc[:n_ben_needed]
    training_set  = pd.concat([df_malevoli_proc, ben_for_train], ignore_index=True)
    del df_malevoli_proc, df_benevoli_proc, ben_for_train
    gc.collect()

    X_train = training_set.drop(columns=['Label'])
    y_train = training_set['Label']
    del training_set
    gc.collect()

    model = RandomForestClassifier(
        n_estimators=200, criterion='gini', max_depth=None,
        min_samples_split=2, min_samples_leaf=1,
        min_weight_fraction_leaf=0.0, max_features='sqrt',
        max_leaf_nodes=None, min_impurity_decrease=0.0,
        bootstrap=True, oob_score=False, n_jobs=2,
        random_state=0, verbose=0, warm_start=False,
        class_weight=None, ccp_alpha=0.0, max_samples=None
    )
    model.fit(X_train, y_train)
    del X_train, y_train
    gc.collect()

    joblib.dump(model, model_filename)
    del model
    gc.collect()


print("Lettura sample benigni")
df_benevoli_raw = pd.read_csv(input_benevoli, low_memory=False)
df_benevoli_raw['Label']   = 0
df_benevoli_raw['DstBytes'] = df_benevoli_raw['TotBytes'] - df_benevoli_raw['SrcBytes']
df_benevoli_raw['_source'] = 'benevoli'


for botnet_name in BOTNETS:
    botnet_lower = botnet_name.lower()
    scenario     = botnet_lower

    if scenario not in BOTNET_CONFIG:
        print(f"[ERRORE] Botnet '{botnet_name}' non presente in BOTNET_CONFIG, saltata.")
        continue

    training_path = os.path.join(csv_partenza_dir, botnet_name, f"{botnet_name}_tcp_training.csv")
    if not os.path.isfile(training_path):
        print(f"[ERRORE] Training non trovato: {training_path}, salto intera botnet.")
        continue

    df_training_raw = pd.read_csv(training_path, low_memory=False)

    for padding in PADDINGS:

        validation_path = os.path.join(perturbati_dir, padding, botnet_name,
                                       f"{botnet_name}_tcp_validation_pert.csv")

        model_dir_fd    = os.path.join(OUTPUT_BASE, "FD",    padding, botnet_name)
        model_dir_no_fd = os.path.join(OUTPUT_BASE, "NO_FD", padding, botnet_name)
        model_filename_fd    = os.path.join(model_dir_fd,    f"{botnet_lower}_adv_model.joblib")
        model_filename_no_fd = os.path.join(model_dir_no_fd, f"{botnet_lower}_adv_model.joblib")

        if os.path.isfile(model_filename_fd) and os.path.isfile(model_filename_no_fd):
            print(f"Entrambi i modelli già presenti per {padding} / {botnet_name}")
            continue

        if not os.path.isfile(validation_path):
            print(f"File non trovato: {validation_path}")
            continue

        os.makedirs(model_dir_fd,    exist_ok=True)
        os.makedirs(model_dir_no_fd, exist_ok=True)

        try:
            infected_ips = BOTNET_CONFIG[scenario]

            df_training   = df_training_raw.copy()
            df_validation = pd.read_csv(validation_path, low_memory=False)

            df_training['Label']   = 1
            df_validation['Label'] = 1
            df_training['_source']   = 'malevoli'
            df_validation['_source'] = 'malevoli'

            df_benevoli = df_benevoli_raw.copy()

            print("  Concatenazione")
            data = pd.concat([df_benevoli, df_training, df_validation], ignore_index=True)
            del df_benevoli, df_training, df_validation
            gc.collect()

            data['infect'] = data['SrcAddr'].isin(infected_ips)

            print("  Inizio preprocessing")
            data = data.drop("StartTime", axis=1)

            data = data[data.Proto == "tcp"]
            data.Proto = data.Proto.replace("tcp", "0").astype(int)

            data.sTos = data.sTos.replace(np.nan, 0.0)
            data.dTos = data.dTos.replace(np.nan, 0.0)

            data = data.dropna()

            ipsrctype = data.SrcAddr.apply(
                lambda addr: (
                    1 if (ipaddress.ip_address(addr) in ipaddress.ip_network("147.32.0.0/16"))
                    else 0
                )
            )
            data.insert(2, "IPSrcType", ipsrctype)
            data = data.drop("SrcAddr", axis=1)

            ipdsttype = data.DstAddr.apply(
                lambda addr: (
                    1 if (ipaddress.ip_address(addr) in ipaddress.ip_network("147.32.0.0/16"))
                    else 0
                )
            )
            data.insert(3, "IPDstType", ipdsttype)
            data = data.drop("DstAddr", axis=1)

            print("  Calcolo tipologia di porte")
            sport = data.Sport.astype(int)
            data.insert(4, "SrcPortWellKnown",  ((sport >= 0)     & (sport <= 1023)).astype(int))
            data.insert(5, "SrcPortRegistered", ((sport >= 1024)  & (sport <= 49151)).astype(int))
            data.insert(6, "SrcPortPrivate",    (sport >= 49152).astype(int))
            data = data.drop("Sport", axis=1)

            dport = data.Dport.astype(int)
            data.insert(7, "DstPortWellKnown",  ((dport >= 0)     & (dport <= 1023)).astype(int))
            data.insert(8, "DstPortRegistered", ((dport >= 1024)  & (dport <= 49151)).astype(int))
            data.insert(9, "DstPortPrivate",    (dport >= 49152).astype(int))
            data = data.drop("Dport", axis=1)

            expected = ["->", "?>", "<?", "<?>"]
            dir_dummies = pd.get_dummies(data.Dir.str.strip()).reindex(columns=expected, fill_value=0)
            data.insert(10, "->",  dir_dummies["->"].astype(int))
            data.insert(11, "?>",  dir_dummies["?>"].astype(int))
            data.insert(12, "<?",  dir_dummies["<?"].astype(int))
            data.insert(13, "<?>", dir_dummies["<?>"].astype(int))
            data = data.drop("Dir", axis=1)
            del dir_dummies

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
            del state

            data.loc[(data['infect'] == True) & (data['SrcStateP'] == 0), 'infect'] = False

            data_fd = data.copy()
            data_clean = data.copy()
            del data
            gc.collect()

            processing_feature_derivate(data_fd, model_filename_fd)
            del data_fd
            gc.collect()

            processing_clean(data_clean, model_filename_no_fd)
            del data_clean
            gc.collect()

        except Exception as e:
            print(f"  [ERRORE] {padding} / {botnet_name}: {e}")
            gc.collect()
            continue

    del df_training_raw
