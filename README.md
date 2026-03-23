# LDAPS sync per vCenter: controllo certificati e riconfigurazione automatica dell'Identity Source

## Scopo

Questo repository descrive un piccolo sistema operativo per mantenere allineata la configurazione **LDAPS di vCenter** con i **certificati realmente esposti dai Domain Controller**.

L'obiettivo è evitare che l'Identity Source AD/LDAP configurata in vCenter resti legata a una chain ormai cambiata o scaduta, situazione che può rompere autenticazione, lookup utenti/gruppi o login federato via Active Directory.

Il materiale incluso copre **due modalità complementari**:

1. **Procedura manuale guidata** sul vCenter Appliance, tramite script Bash.
2. **Automazione su Kubernetes/RKE2**, composta da un checker periodico e da un reconciler che aggiorna vCenter quando il certificato LDAPS cambia.

In altre parole:
- lo **script Bash** serve per fare un refresh manuale, controllato e tracciato dell'Identity Source;
- i **manifest Kubernetes** servono a trasformare quel refresh in un processo continuo e automatizzato.

---

## Architettura logica

Il flusso previsto è questo:

1. Un componente **checker** interroga i Domain Controller via `openssl s_client` sugli endpoint LDAPS configurati.
2. Il checker confronta la chain letta dai DC con quella salvata nella Secret Kubernetes considerata "corrente".
3. Se rileva una differenza, crea una Secret storica e aggiorna la Secret corrente.
4. Un componente **reconciler** osserva la Secret corrente e, quando cambia, aggiorna il provider/identity source LDAPS su vCenter usando le API o la logica implementata nel container applicativo.
5. Il reconciler usa anche le credenziali di bind LDAP e le credenziali amministrative di vCenter per ricreare o aggiornare la configurazione lato SSO.

Questo comportamento emerge dai commenti operativi del `CronJob`, del `Deployment`, dalla `ConfigMap` e dalle `Secret` incluse nel bundle.

---

## Cosa è incluso

### 1) Strumento manuale: `vcenter_ldaps_refresh.sh`

Script Bash da eseguire **direttamente sul vCenter** come `root`.

Serve per:
- raccogliere i certificati live dei DC da `PRIMARY_LDAPS_URL` e `SECONDARY_LDAPS_URL`;
- salvare lo stato attuale della configurazione SSO prima della modifica;
- riepilogare subject, issuer, date di validità, fingerprint SHA256 e SAN dei certificati trovati;
- chiedere conferma prima di ogni passaggio distruttivo;
- cancellare l'identity source esistente;
- ricrearlo in modalità `adldap` con `-useSSL true` e con i certificati appena letti;
- tentare di reimpostare anche il default identity source;
- salvare log, chain PEM e configurazione pre/post in una directory timestampata.

Lo script usa `sso-config.sh` del vCenter e richiede interazione per:
- eventuali variabili non compilate;
- password del bind user LDAP;
- credenziali SSO richieste da `sso-config.sh` durante delete/add/set-default.

È quindi lo strumento da usare quando vuoi:
- fare un intervento una tantum;
- validare il processo manualmente;
- recuperare un ambiente prima di automatizzarlo.

### 2) Bundle Kubernetes: checker + reconciler

Il bundle YAML definisce il perimetro Kubernetes in namespace `ldaps-sync`.

#### Namespace
- `ns.yaml` crea il namespace `ldaps-sync`.

#### Configurazione condivisa
- `cm01.yaml` crea la `ConfigMap` `ldaps-sync-config` con:
  - URL vCenter;
  - nome del provider LDAPS da aggiornare;
  - dominio SSO;
  - parametri AD/LDAP;
  - nome della Secret corrente;
  - prefisso delle Secret storiche;
  - modalità di confronto (`CHECK_MODE`);
  - timeout di `openssl`.

#### Secret
- `secret01.yaml` contiene `ldaps-current`, cioè la Secret "corrente" con:
  - `cert-chain.pem`;
  - `metadata.json`.
- `secret02.yaml` contiene `vcenter-api-credentials` con utente/password per autenticarsi a vCenter.
- `secret03.yaml` contiene `ldaps-bind-credentials` con bind DN e password LDAP.

#### Checker
- `sa01.yaml` crea la ServiceAccount `ldaps-checker`.
- `role01.yaml` assegna al checker permessi su `secrets`, `configmaps` ed `events`.
- `rolebinding01.yaml` collega ruolo e ServiceAccount.
- `cron.yaml` crea il `CronJob` `ldaps-checker`, pianificato ogni 6 ore.

Dai commenti del `CronJob`, il comportamento atteso del container è:
- leggere la Secret corrente (`CURRENT_CERT_SECRET_NAME`);
- interrogare gli endpoint LDAPS primario e secondario;
- confrontare il certificato o la chain con quanto salvato;
- in caso di mismatch, creare una Secret storica con prefisso `HISTORY_CERT_SECRET_PREFIX`;
- aggiornare la Secret corrente.

#### Reconciler vCenter
- `sa02.yaml` crea la ServiceAccount `vcenter-ldaps-reconciler`.
- `role02.yaml` assegna permessi di lettura su `secrets` e `configmaps`, più creazione/patch di `events`.
- `rolebinding02.yaml` collega ruolo e ServiceAccount.
- `deploy01.yaml` crea il `Deployment` `vcenter-ldaps-reconciler`.

Dai commenti del `Deployment`, il comportamento atteso del container è:
- osservare la Secret indicata da `CURRENT_CERT_SECRET_NAME`;
- leggere `cert-chain.pem` quando la Secret cambia;
- autenticarsi su vCenter via REST;
- aggiornare il provider indicato da `VCENTER_PROVIDER_NAME`;
- impostarlo come default (`make_default=true`).

---

## Punto importante: cosa c'è davvero e cosa manca

Questi file **non contengono il codice applicativo** del checker e del reconciler.

I manifest descrivono chiaramente l'integrazione attesa, ma le immagini container sono ancora placeholder:

- `ghcr.io/example/ldaps-checker:latest`
- `ghcr.io/example/vcenter-ldaps-reconciler:latest`

Quindi questo repository, così com'è, fornisce:
- il **design operativo**;
- la **struttura Kubernetes**;
- il **contratto di configurazione** tra manifest e applicazioni;
- uno **script manuale funzionante** per la procedura su vCenter.

Ma **non è eseguibile end-to-end in modo automatico** finché non esistono o non vengono sostituite le due immagini reali.

---

## Come leggere il progetto nel modo corretto

Questo non è un semplice "job che legge un certificato".

Lo strumento, nel suo insieme, serve a risolvere questo problema operativo:

> quando i certificati LDAPS dei Domain Controller cambiano, vCenter può restare configurato con certificati non più coerenti; occorre intercettare il cambio, storicizzarlo e riallineare automaticamente l'Identity Source AD over LDAPS.

Le due parti del progetto coprono due esigenze diverse:

### Modalità manuale
Usi `vcenter_ldaps_refresh.sh` quando vuoi un refresh controllato, con conferme esplicite, salvataggio dello stato prima/dopo e verifica umana delle chain.

### Modalità automatica
Usi il bundle Kubernetes quando vuoi un processo continuo:
- il checker scopre i cambi lato Domain Controller;
- il reconciler propaga il cambiamento verso vCenter.

---

## Ordine consigliato di utilizzo

### Fase 1 - Bootstrap iniziale
1. Personalizza `cm01.yaml` con i valori reali del tuo ambiente.
2. Inserisci le credenziali corrette in:
   - `secret02.yaml`
   - `secret03.yaml`
3. Popola `secret01.yaml` con una chain iniziale valida in `cert-chain.pem` e metadati coerenti.

Per il bootstrap iniziale puoi:
- ottenere la chain manualmente con `openssl s_client`, oppure
- usare lo script `vcenter_ldaps_refresh.sh` sul vCenter per raccogliere i certificati live e validare il contenuto da usare.

### Fase 2 - Deploy dei manifest
Applica i file YAML nel namespace `ldaps-sync`.

Poiché nel repository non esiste un file unico chiamato `k8s-ldaps-vcenter-manifests.yaml`, l'apply va fatto:

```bash
kubectl apply -f .
```

oppure indicando esplicitamente i singoli file o una directory dedicata.

### Fase 3 - Attivazione dell'automazione
Sostituisci le immagini placeholder del checker e del reconciler con quelle reali della tua implementazione.

Senza questo passaggio:
- il `CronJob` verrà creato ma non svolgerà la logica attesa;
- il `Deployment` verrà creato ma non aggiornerà vCenter.

---

## Parametri da personalizzare

### ConfigMap `ldaps-sync-config`

Valori obbligatori o altamente probabili da adattare:
- `VCENTER_URL`
- `VCENTER_PROVIDER_NAME`
- `VCENTER_SSO_DOMAIN`
- `DOMAIN_NAME`
- `DOMAIN_ALIAS`
- `USERS_BASE_DN`
- `GROUPS_BASE_DN`
- `PRIMARY_LDAPS_URL`
- `SECONDARY_LDAPS_URL`
- `CURRENT_CERT_SECRET_NAME`
- `HISTORY_CERT_SECRET_PREFIX`

Parametri operativi:
- `CHECK_MODE`: strategia di confronto del checker (`leaf-or-chain`, `leaf-only`, `chain-only`)
- `OPENSSL_TIMEOUT_SECONDS`: timeout per i controlli verso gli endpoint LDAPS

### Secret

#### `vcenter-api-credentials`
Credenziali usate dal reconciler per chiamare vCenter:
- `VCENTER_USERNAME`
- `VCENTER_PASSWORD`

#### `ldaps-bind-credentials`
Credenziali di bind LDAP usate nel payload di aggiornamento verso vCenter:
- `BIND_USERNAME`
- `BIND_PASSWORD`

#### `ldaps-current`
Contiene il materiale certificativo considerato corrente:
- `cert-chain.pem`
- `metadata.json`

`metadata.json` è utile per tracciare provenienza, dominio, URL primario/secondario, fingerprint e date di validità.

---

## Permessi Kubernetes previsti

### Checker
Il checker ha permessi per:
- leggere, elencare, osservare, creare, aggiornare e patchare `Secret`;
- leggere `ConfigMap`;
- creare e patchare `Event`.

Questo è coerente con il suo ruolo: confrontare lo stato, storicizzare e aggiornare la Secret corrente.

### Reconciler
Il reconciler ha permessi per:
- leggere/elencare/osservare `Secret`;
- leggere `ConfigMap`;
- creare e patchare `Event`.

Questo è coerente con un componente che reagisce ai cambiamenti ma non deve modificare direttamente tutte le Secret del namespace.

---

## Sicurezza e note operative

### 1) Snapshot del vCenter prima della modifica
La documentazione operativa allegata e lo script manuale convergono su un punto: prima di rimuovere/ricreare l'Identity Source LDAPS è prudente avere uno snapshot del VCSA.

### 2) Password del bind user
Lo script Bash non salva la password del bind user nei file o nei log, ma la passa comunque a `sso-config.sh` come argomento in fase di esecuzione. Questo riduce la persistenza, ma non elimina del tutto l'esposizione temporanea a runtime.

### 3) Secret Kubernetes in chiaro logico
Le `Secret` Kubernetes non vanno lasciate con placeholder. In produzione conviene gestirle con un meccanismo come Sealed Secrets, External Secrets o integrazione con un vault aziendale.

### 4) `readOnlyRootFilesystem` e `runAsNonRoot`
Sia checker sia reconciler sono già definiti con un profilo di sicurezza ragionevole:
- `seccompProfile: RuntimeDefault`
- `allowPrivilegeEscalation: false`
- `readOnlyRootFilesystem: true`
- `runAsNonRoot: true`
- drop di tutte le capability Linux

### 5) Storico certificati
La presenza del prefisso `ldaps-history` indica che il progetto vuole mantenere una traccia dei cambi. È utile per audit, rollback logico e troubleshooting post-rotazione.

---

## Procedura manuale rapida sul vCenter

Il file `joinldapssso.txt` descrive una procedura manuale minimale per:
- collegarsi in SSH al vCenter;
- usare `openssl s_client -showcerts` verso i DC;
- estrarre le chain PEM;
- invocare `sso-config.sh -add_identity_source -type adldap ... -useSSL true -sslCert dc1.crt,dc2.crt`.

Lo script `vcenter_ldaps_refresh.sh` formalizza e migliora quella procedura, aggiungendo:
- raccolta strutturata dei file;
- salvataggio della configurazione prima/dopo;
- riepilogo dei certificati;
- conferme esplicite;
- gestione più sicura della password del bind user.

Per questo motivo, lo script può essere considerato la versione operativa e robusta della nota manuale.

---

## Limiti attuali

Il progetto ha alcuni limiti espliciti:

1. **Mancano le immagini reali** del checker e del reconciler.
2. **Manca il codice** che definisce il formato esatto del confronto tra chain live e `ldaps-current`.
3. **Manca un manifest unico** già assemblato, quindi il comando `kubectl apply -f k8s-ldaps-vcenter-manifests.yaml` presente nel vecchio README non è coerente con i file disponibili.
4. **Manca documentazione API vCenter** specifica dell'implementazione del reconciler.

Questi limiti non invalidano il design, ma vanno dichiarati apertamente nel README.

---

## Struttura dei file

- `README.md` — documentazione del bundle.
- `vcenter_ldaps_refresh.sh` — helper manuale per refresh dell'Identity Source LDAPS sul vCenter.
- `joinldapssso.txt` — note operative sintetiche per aggiunta manuale di un identity source LDAPS.
- `ns.yaml` — namespace `ldaps-sync`.
- `cm01.yaml` — configurazione condivisa.
- `secret01.yaml` — Secret corrente con chain PEM e metadati.
- `secret02.yaml` — credenziali API vCenter.
- `secret03.yaml` — credenziali bind LDAP.
- `sa01.yaml` / `role01.yaml` / `rolebinding01.yaml` — identità e permessi del checker.
- `cron.yaml` — esecuzione periodica del checker.
- `sa02.yaml` / `role02.yaml` / `rolebinding02.yaml` — identità e permessi del reconciler.
- `deploy01.yaml` — deployment del reconciler.

---

## In sintesi

Questo repository implementa il modello operativo per **tenere allineata la trust/configurazione LDAPS di vCenter ai certificati realmente serviti dai Domain Controller AD**.

La soluzione è composta da:
- una **procedura manuale robusta** (`vcenter_ldaps_refresh.sh`), utile per bootstrap, recovery e troubleshooting;
- una **pipeline automatizzabile su Kubernetes** basata su Secret corrente, storico certificati, checker periodico e reconciler verso vCenter.

È quindi un progetto di **certificate drift detection + reconciliation** applicato al provider LDAPS di vCenter.
