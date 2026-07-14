# Adversarial Training in Problem Space per ML-NIDS

Codice sperimentale associato alla tesi di laurea magistrale *"Adversarial Training in Problem Space per ML-NIDS"* (Università di Modena e Reggio Emilia).

Il lavoro definisce e valuta una strategia difensiva basata su **adversarial training in problem space** per rilevatori di intrusioni basati su machine learning (ML-NIDS). A differenza degli approcci in *feature space*, che perturbano direttamente il vettore di feature, le perturbazioni adversariali vengono qui applicate al **traffico di rete a livello di pacchetto** (file PCAP), nel rispetto dei vincoli protocollari del dominio, e sono poi usate per addestrare modelli più robusti. L'obiettivo è duplice: verificare se questa forma di adversarial training conferisca al rilevatore una robustezza misurabile contro traffico adversarial, e accertare che tale robustezza non comporti una regressione delle prestazioni su traffico ordinario.

* **Dataset**: [CTU-13](https://www.stratosphereips.org/datasets-ctu13) (Stratosphere IPS)
* **Classificatore**: Random Forest (Scikit-learn)
* **Rappresentazione del traffico**: NetFlow (via Argus)
* **Manipolazione dei pacchetti**: Scapy

\---

## Indice

* [Panoramica della pipeline](#panoramica-della-pipeline)
* [Requisiti](#requisiti)
* [Struttura della repository](#struttura-della-repository)
* [Descrizione degli script](#descrizione-degli-script)
* [Esecuzione della pipeline](#esecuzione-della-pipeline)
* [Note metodologiche](#note-metodologiche)
* [Limitazioni](#limitazioni)
* [Citazione](#citazione)

\---

## Panoramica della pipeline

Il lavoro sperimentale si articola in tre fasi. Gli script Python coprono i passi che operano su PCAP e su CSV; i passi di conversione `PCAP → NetFlow` sono affidati a strumenti a riga di comando (`mergecap`, `pcapfix`, `tcpdump`, Argus).

**Fase 1 — Baseline clean**
Aggregazione e filtraggio dei PCAP malevoli, split a livello di flusso, conversione in NetFlow, preprocessing e addestramento dei modelli baseline su traffico non perturbato.

**Fase 2 — Perturbazioni e valutazione della vulnerabilità**
Applicazione di perturbazioni di tipo *padding* ai pacchetti TCP con flag PSH provenienti dagli host infetti, riconversione in NetFlow, preprocessing e valutazione del calo di recall dei modelli baseline.

**Fase 3 — Adversarial training e valutazione finale**
Riaddestramento dei modelli includendo traffico perturbato nel training set (*modelli hardened*), generazione di run multipli per le perturbazioni randomiche e confronto sistematico baseline vs hardened.

\---

## Requisiti

### Librerie Python

```bash
pip install scapy scikit-learn pandas numpy joblib tqdm
```

Versioni di riferimento usate nel lavoro: Scikit-learn 1.8.0, Pandas 3.0.0, joblib 1.5.3. Python 3.

### Strumenti di sistema

Non richiamati dagli script ma necessari per i passi di preparazione e conversione del traffico:

|Strumento|Ruolo|Provenienza|
|-|-|-|
|`mergecap`|Aggregazione dei PCAP dei 13 scenari in 7 PCAP per famiglia|suite Wireshark|
|`pcapfix`|Verifica e correzione dell'integrità dei PCAP|pacchetto `pcapfix`|
|`tcpdump`|Filtraggio del solo traffico TCP|pacchetto `tcpdump`|
|Argus / `ra`|Conversione dei PCAP in record NetFlow (CSV)|Argus 3.0.8.2|

La conversione NetFlow usa due file di configurazione Argus, `argus\_paper.conf` e `ra\_paper.conf`, che definiscono l'insieme di feature estratte. **Questi file non sono inclusi in questa repository** e vanno predisposti separatamente per riprodurre la pipeline (vedi comandi nella sezione [Esecuzione](#esecuzione-della-pipeline)).

### Dataset

Il dataset CTU-13 non è incluso nella repository. Vanno reperiti sia i file `.binetflow` (traffico benigno) sia i PCAP originali (traffico malevolo) dal sito di Stratosphere IPS.

\---

## Struttura della repository

```
.
├── 1\_split\_pcap\_by\_flow.py       # Fase 1 — split PCAP per flusso (70/15/15)
├── 2\_pre\_processing.py           # Fase 1 — preprocessing NetFlow + baseline dataset
├── 3\_creazione\_modelli.py        # Fase 1 — addestramento modello baseline
├── 4\_perturbazioni.py            # Fase 2 — padding su TCP-PSH (singolo run)
├── 4\_pre\_processing\_pert.py      # Fase 2 — preprocessing dei PCAP perturbati
├── 6\_preproc\_modl\_adv\_tra.py     # Fase 3 — preprocessing + adversarial training
├── 8\_perturbazioni.py            # Fase 3 — padding randomico su run multipli
└── valutazione\_modello.py        # Valutazione (recall/TPR/TNR) su sample perturbabili
```

I passi di conversione NetFlow (numerati 5 e 7 nel racconto cronologico del lavoro) non hanno uno script dedicato: sono eseguiti direttamente con Argus.

\---

## Descrizione degli script

### `1\_split\_pcap\_by\_flow.py`

Suddivide un PCAP malevolo negli split di training, validation e test secondo la proporzione 70/15/15. Lo split opera a livello di **conversazione bidirezionale**: due pacchetti appartengono alla stessa conversazione se producono la stessa chiave canonica, costruita ordinando lessicograficamente la coppia di endpoint e aggiungendo il protocollo:

```python
key = tuple(sorted(\[(src\_ip, src\_port), (dst\_ip, dst\_port)])) + (proto,)
```

Tutti i pacchetti di una stessa conversazione finiscono nello stesso split, prevenendo forme di *data leakage* intra-conversazione. Il seed del generatore casuale è fissato a `0` per garantire riproducibilità.

```bash
python 1\_split\_pcap\_by\_flow.py <input.pcap> <out\_train.pcap> <out\_val.pcap> <out\_test.pcap>
```

### `2\_pre\_processing.py`

Preprocessing dei CSV NetFlow e costruzione dei dataset baseline. Unisce benigni, training, validation e test; applica le trasformazioni sulle feature (codifica di indirizzi, porte, direzione, flag di stato TCP), filtra il traffico su soglie di dominio e campiona i benigni in rapporto **10:1** rispetto ai malevoli in ciascuno split. Produce due rappresentazioni di feature:

* **NO\_FD** — feature di base derivate direttamente dal NetFlow;
* **FD** — rappresentazione estesa con quattro feature derivate: `BytesPerPkt`, `BytesPerSec`, `PktsPerSec`, `RatioOutIn`.

Per ogni rappresentazione salva i set completi (benigni + malevoli) e i set con soli malevoli, mantenendo una colonna `infect` che marca i flussi effettivamente perturbabili. Gli IP degli host infetti per famiglia sono definiti nel dizionario `BOTNET\_CONFIG`.

```bash
python 2\_pre\_processing.py <benigni.csv> <train.csv> <val.csv> <test.csv> <out\_dir> <scenario>
```

### `3\_creazione\_modelli.py`

Addestra un modello Random Forest sul training set completo di una rappresentazione e ne stampa le prestazioni su validation e test set. Iperparametri: `n\_estimators=200`, `criterion='gini'`, `max\_features='sqrt'`, `random\_state=0`. Il modello viene serializzato via joblib. Gli stessi iperparametri sono usati per i modelli hardened, così che baseline e hardened differiscano per la sola composizione del training set.

```bash
python 3\_creazione\_modelli.py <train.csv> <val.csv> <test.csv> <out\_dir\_modello>
```

### `4\_perturbazioni.py`

Applica le perturbazioni di *padding* ai PCAP di validation e test. Itera su tutti i pacchetti e perturba **esclusivamente i pacchetti TCP con flag PSH**, lasciando invariati gli altri (UDP, TCP senza PSH, non-IP, pacchetti con errori di parsing). Il padding è generato in modo che la dimensione totale del pacchetto non superi l'MTU (1500 byte); dopo l'aggiunta del payload, lunghezza IP e checksum IP/TCP vengono ricalcolati. Passando `lower == upper` si ottiene il **padding fisso**, passando un intervallo `\[lower, upper]` il **padding randomico**. Il seed è derivato dai parametri di padding.

```bash
python 4\_perturbazioni.py <input\_folder> <output\_folder> <lower\_padding> <upper\_padding>
```

### `4\_pre\_processing\_pert.py`

Preprocessing dei CSV NetFlow ottenuti dai PCAP perturbati. Applica le stesse trasformazioni di `2\_pre\_processing.py` ma opera sui **soli sample malevoli** (nessun campionamento di benigni), producendo validation e test set perturbati per entrambe le rappresentazioni.

```bash
python 4\_pre\_processing\_pert.py <input\_malevoli.csv> <out\_dir> <scenario>
```

### `6\_preproc\_modl\_adv\_tra.py`

Realizza l'adversarial training. Per ciascuna famiglia (`Murlo`, `Neris`, `Virut`) e ciascuna tipologia di padding, unisce il training set malevolo clean, il validation set perturbato e i sample benigni; applica il preprocessing e addestra un nuovo modello (*hardened*) con gli stessi iperparametri della baseline, per entrambe le rappresentazioni. Le tipologie di padding sono elencate nella lista `PADDINGS`: tre randomiche (`\[1,100]`, `\[100,1024]`, `\[1,1500]`) e undici fisse (1, 8, 16, 32, 64, 96, 128, 256, 352, 512, 1024 byte).

```bash
python 6\_preproc\_modl\_adv\_tra.py <benigni.csv> <csv\_partenza\_dir> <perturbati\_dir>
```

### `8\_perturbazioni.py`

Variante di `4\_perturbazioni.py` per le sole perturbazioni randomiche, con un parametro aggiuntivo `run`. Poiché il padding randomico è stocastico, per ciascuna tipologia vengono generati 10 run indipendenti, ciascuno con un seed diverso (`seed = run \* 10000 + upper`), producendo 10 PCAP di test set per tipologia. Le medie sui 10 run rendono stabili le stime di recall.

```bash
python 8\_perturbazioni.py <input\_folder> <output\_folder> <lower\_padding> <upper\_padding> <run>
```

### `valutazione\_modello.py`

Valuta un modello serializzato su un CSV. Restringe la valutazione ai soli flussi perturbabili (`infect == True`), riordina le colonne secondo quelle attese dal modello e stampa classification report, matrice di confusione e i valori di **TPR** (recall sui malevoli) e **TNR**. La recall sui soli flussi perturbabili è la metrica centrale del confronto baseline vs hardened.

```bash
python valutazione\_modello.py <modello.joblib> <input.csv>
```

\---

## Esecuzione della pipeline

I passi di conversione NetFlow, comuni a più fasi, usano Argus con la configurazione di riferimento:

```bash
argus -F argus\_paper.conf -r file.pcap -w tmp.argus
ra    -F ra\_paper.conf -n -Z b -r tmp.argus > output.csv
```

Sequenza completa (schematica):

```text
# --- Fase 1: baseline ---
mergecap -w merged.pcap scenario\_\*.pcap        # aggregazione per famiglia
pcapfix merged.pcap
tcpdump -r merged.pcap -w tcp.pcap tcp          # solo TCP
python 1\_split\_pcap\_by\_flow.py tcp.pcap train.pcap val.pcap test.pcap
#   -> conversione NetFlow di ciascuno split con Argus
python 2\_pre\_processing.py benigni.csv train.csv val.csv test.csv out/ <scenario>
python 3\_creazione\_modelli.py out/FD/training\_out\_fd.csv out/FD/validation\_out\_fd.csv out/FD/test\_out\_fd.csv modelli/

# --- Fase 2: vulnerabilità ---
python 4\_perturbazioni.py val\_test\_pcap/ perturbati/ <lower> <upper>
#   -> riconversione NetFlow con Argus
python 4\_pre\_processing\_pert.py perturbati.csv out\_pert/ <scenario>
python valutazione\_modello.py modelli/paper\_model.joblib out\_pert/FD/...\_fd.csv

# --- Fase 3: adversarial training ---
python 6\_preproc\_modl\_adv\_tra.py benigni.csv csv\_partenza/ perturbati/
python 8\_perturbazioni.py val\_test\_pcap/ perturbati\_run/ <lower> <upper> <run>
#   -> riconversione + 4\_pre\_processing\_pert.py per ogni run
python valutazione\_modello.py Modelli\_adversarial/FD/<padding>/<botnet>/\*.joblib <test\_pert.csv>
```

\---

## Note metodologiche

* **Criterio di perturbabilità.** Un flusso è considerato perturbabile (`infect = True`) solo se soddisfa due condizioni congiunte: l'IP sorgente appartiene alla whitelist degli host infetti della famiglia, e il flusso contiene almeno un pacchetto TCP con flag PSH in direzione sorgente. La recall di riferimento è calcolata sui soli flussi perturbabili.
* **Famiglie valutate.** La valutazione adversarial è circoscritta a **Murlo, Neris e Virut**, le uniche tre famiglie del CTU-13 con più di 100 flussi perturbabili nel test set; sotto questa soglia la stima della recall non è statisticamente affidabile. Le restanti quattro famiglie (Menti, NSIS, Rbot, Sogou) sono incluse solo nella valutazione su traffico non perturbato.
* **Realismo delle perturbazioni.** Le perturbazioni sono *protocol-compliant*: i pacchetti restano IP/TCP ben formati (header e checksum coerenti) e rispettano il limite MTU, così da essere realizzabili da un attaccante reale senza introdurre artefatti di frammentazione facilmente rilevabili.
* **Riproducibilità.** Split, campionamento dei benigni e addestramento usano `random\_state=0`; le perturbazioni randomiche usano seed deterministici derivati dai parametri, con 10 run per tipologia.

\---

## Limitazioni

* L'approccio opera su PCAP pre-raccolti (*traffic-space perturbations*), non su perturbazioni eseguite direttamente sull'host compromesso (*host-space*); l'estensione a queste ultime è una direzione di ricerca futura.
* La valutazione adversarial copre 3 delle 7 famiglie del CTU-13; l'estensione a famiglie con traffico perturbabile limitato richiede tecniche complementari (data augmentation, dataset integrativi).
* Le perturbazioni implementate sono deliberatamente semplici (padding *blind*): l'obiettivo è mostrare che perturbazioni realistiche in problem space bastano a degradare un detector standard e che un adversarial training mirato ne recupera la robustezza, non costruire l'attacco più forte possibile.

\---

