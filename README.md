# Manifest bundle: LDAPS checker + vCenter reconciler

## Oggetti inclusi
- Namespace `ldaps-sync`
- ConfigMap `ldaps-sync-config`
- Secret `ldaps-current`
- Secret `vcenter-api-credentials`
- Secret `ldaps-bind-credentials`
- ServiceAccount / Role / RoleBinding per checker
- CronJob `ldaps-checker`
- ServiceAccount / Role / RoleBinding per reconciler
- Deployment `vcenter-ldaps-reconciler`

## Cosa personalizzare subito
Nel ConfigMap:
- `VCENTER_URL`
- `VCENTER_PROVIDER_NAME`
- `VCENTER_SSO_DOMAIN`
- `DOMAIN_NAME`
- `DOMAIN_ALIAS`
- `USERS_BASE_DN`
- `GROUPS_BASE_DN`
- `PRIMARY_LDAPS_URL`
- `SECONDARY_LDAPS_URL`

Nelle Secret:
- `vcenter-api-credentials`: utente/password API di vCenter
- `ldaps-bind-credentials`: bind user/password LDAP
- `ldaps-current`: chain PEM iniziale e metadata

## Flusso previsto
1. Bootstrappi manualmente `ldaps-current` con il certificato attuale.
2. Il CronJob interroga i DC via LDAPS e confronta la chain con la Secret corrente.
3. Se trova mismatch:
   - crea una Secret storica `ldaps-history-<timestamp>`
   - aggiorna `ldaps-current`
4. Il reconciler osserva `ldaps-current` e aggiorna il provider LDAPS su vCenter.

## Nota pratica
I manifest non includono il codice applicativo del checker o del reconciler.
I due container sono lasciati come placeholder:
- `ghcr.io/example/ldaps-checker:latest`
- `ghcr.io/example/vcenter-ldaps-reconciler:latest`

## Apply
```bash
kubectl apply -f k8s-ldaps-vcenter-manifests.yaml
```
