import hashlib
import json
import logging
import os
import socket
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import requests
from flask import Flask, jsonify
from kubernetes import client, config, watch
from kubernetes.client import CoreV1Api, V1ObjectReference, V1Secret
from kubernetes.client.rest import ApiException

LOGGER = logging.getLogger("vcenter-ldaps-reconciler")
APP = Flask(__name__)
_HEALTH = {"live": True, "ready": False, "last_sync": None, "last_error": None}


@dataclass(frozen=True)
class Settings:
    namespace: str
    current_secret_name: str
    provider_name: str
    vcenter_url: str
    vcenter_sso_domain: str
    domain_name: str
    domain_alias: str
    users_base_dn: str
    groups_base_dn: str
    primary_ldaps_url: str
    secondary_ldaps_url: str
    vcenter_username: str
    vcenter_password: str
    bind_username: str
    bind_password: str
    apply_mode: str
    reconcile_webhook_url: str
    reconcile_webhook_bearer_token: str
    insecure_skip_tls_verify: bool


def configure_logging() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_z(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def strtobool(value: str) -> bool:
    return value.strip().lower() in {"1", "true", "yes", "y", "on"}


def require_env(name: str, default: Optional[str] = None) -> str:
    value = os.getenv(name, default)
    if value is None or not str(value).strip():
        raise ValueError(f"Variabile ambiente obbligatoria non valorizzata: {name}")
    return value.strip()


def load_settings() -> Settings:
    return Settings(
        namespace=require_env("POD_NAMESPACE", "default"),
        current_secret_name=require_env("CURRENT_CERT_SECRET_NAME"),
        provider_name=require_env("VCENTER_PROVIDER_NAME"),
        vcenter_url=require_env("VCENTER_URL"),
        vcenter_sso_domain=require_env("VCENTER_SSO_DOMAIN"),
        domain_name=require_env("DOMAIN_NAME"),
        domain_alias=require_env("DOMAIN_ALIAS"),
        users_base_dn=require_env("USERS_BASE_DN"),
        groups_base_dn=require_env("GROUPS_BASE_DN"),
        primary_ldaps_url=require_env("PRIMARY_LDAPS_URL"),
        secondary_ldaps_url=os.getenv("SECONDARY_LDAPS_URL", "").strip(),
        vcenter_username=require_env("VCENTER_USERNAME"),
        vcenter_password=require_env("VCENTER_PASSWORD"),
        bind_username=require_env("BIND_USERNAME"),
        bind_password=require_env("BIND_PASSWORD"),
        apply_mode=os.getenv("VCENTER_APPLY_MODE", "noop").strip().lower(),
        reconcile_webhook_url=os.getenv("VCENTER_RECONCILE_WEBHOOK_URL", "").strip(),
        reconcile_webhook_bearer_token=os.getenv("VCENTER_RECONCILE_WEBHOOK_BEARER_TOKEN", "").strip(),
        insecure_skip_tls_verify=strtobool(os.getenv("VCENTER_INSECURE_SKIP_TLS_VERIFY", "false")),
    )


def load_kube_client() -> CoreV1Api:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api()


def hash_secret_payload(secret: V1Secret) -> str:
    raw = json.dumps(secret.data or {}, sort_keys=True).encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


def get_secret_string(secret: V1Secret, key: str) -> str:
    if not secret.data or key not in secret.data:
        raise KeyError(f"Chiave assente nella secret {secret.metadata.name}: {key}")
    import base64

    return base64.b64decode(secret.data[key]).decode("utf-8")


def parse_metadata(secret: V1Secret) -> Dict[str, Any]:
    raw = get_secret_string(secret, "metadata.json")
    loaded = json.loads(raw)
    if not isinstance(loaded, dict):
        raise ValueError("metadata.json non contiene un oggetto JSON")
    return loaded


def build_reconcile_payload(settings: Settings, secret: V1Secret) -> Dict[str, Any]:
    metadata = parse_metadata(secret)
    cert_chain = get_secret_string(secret, "cert-chain.pem")
    primary_chain = None
    secondary_chain = None

    if secret.data and "primary-chain.pem" in secret.data:
        primary_chain = get_secret_string(secret, "primary-chain.pem")
    if secret.data and "secondary-chain.pem" in secret.data:
        secondary_chain = get_secret_string(secret, "secondary-chain.pem")

    return {
        "generated_at": isoformat_z(utc_now()),
        "source_secret": {
            "namespace": secret.metadata.namespace,
            "name": secret.metadata.name,
            "resource_version": secret.metadata.resource_version,
            "uid": secret.metadata.uid,
            "data_hash": hash_secret_payload(secret),
        },
        "vcenter": {
            "url": settings.vcenter_url,
            "sso_domain": settings.vcenter_sso_domain,
            "provider_name": settings.provider_name,
            "username": settings.vcenter_username,
            "password": settings.vcenter_password,
            "insecure_skip_tls_verify": settings.insecure_skip_tls_verify,
        },
        "ldap": {
            "domain_name": settings.domain_name,
            "domain_alias": settings.domain_alias,
            "users_base_dn": settings.users_base_dn,
            "groups_base_dn": settings.groups_base_dn,
            "bind_username": settings.bind_username,
            "bind_password": settings.bind_password,
            "primary_ldaps_url": settings.primary_ldaps_url,
            "secondary_ldaps_url": settings.secondary_ldaps_url,
            "cert_chain_pem": cert_chain,
            "primary_chain_pem": primary_chain,
            "secondary_chain_pem": secondary_chain,
        },
        "certificate_metadata": metadata,
    }


def redact_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    redacted = json.loads(json.dumps(payload))
    try:
        redacted["vcenter"]["password"] = "***REDACTED***"
        redacted["ldap"]["bind_password"] = "***REDACTED***"
        cert_data = redacted["ldap"].get("cert_chain_pem")
        if cert_data:
            redacted["ldap"]["cert_chain_pem"] = f"<PEM {len(cert_data)} chars>"
        cert_data = redacted["ldap"].get("primary_chain_pem")
        if cert_data:
            redacted["ldap"]["primary_chain_pem"] = f"<PEM {len(cert_data)} chars>"
        cert_data = redacted["ldap"].get("secondary_chain_pem")
        if cert_data:
            redacted["ldap"]["secondary_chain_pem"] = f"<PEM {len(cert_data)} chars>"
    except KeyError:
        pass
    return redacted


def publish_event(
    api: CoreV1Api,
    namespace: str,
    involved_object: V1ObjectReference,
    event_type: str,
    reason: str,
    message: str,
) -> None:
    body = {
        "metadata": {
            "generateName": f"{involved_object.name.lower()}-",
            "namespace": namespace,
        },
        "type": event_type,
        "reason": reason[:128],
        "message": message,
        "reportingComponent": "vcenter-ldaps-reconciler",
        "reportingInstance": socket.gethostname(),
        "action": reason,
        "regarding": {
            "apiVersion": involved_object.api_version,
            "kind": involved_object.kind,
            "name": involved_object.name,
            "namespace": involved_object.namespace,
        },
        "eventTime": isoformat_z(utc_now()),
    }
    try:
        api.create_namespaced_event(namespace=namespace, body=body)
    except ApiException as exc:
        LOGGER.warning("Impossibile creare Event Kubernetes: %s", exc)


def apply_noop(payload: Dict[str, Any]) -> Tuple[bool, str]:
    LOGGER.info("Modalità noop: nessuna modifica a vCenter verrà eseguita")
    LOGGER.info("Payload riconciliazione: %s", json.dumps(redact_payload(payload), indent=2, sort_keys=True))
    return True, "noop completato"


def apply_webhook(payload: Dict[str, Any], settings: Settings) -> Tuple[bool, str]:
    if not settings.reconcile_webhook_url:
        raise ValueError("VCENTER_RECONCILE_WEBHOOK_URL è obbligatoria in modalità webhook")

    headers = {"Content-Type": "application/json"}
    if settings.reconcile_webhook_bearer_token:
        headers["Authorization"] = f"Bearer {settings.reconcile_webhook_bearer_token}"

    response = requests.post(
        settings.reconcile_webhook_url,
        headers=headers,
        json=payload,
        timeout=30,
        verify=not settings.insecure_skip_tls_verify,
    )
    if response.status_code >= 300:
        raise RuntimeError(
            f"Webhook ha risposto con status {response.status_code}: {response.text[:500]}"
        )
    return True, f"webhook completato con HTTP {response.status_code}"


def reconcile_secret(api: CoreV1Api, settings: Settings, secret: V1Secret) -> None:
    payload = build_reconcile_payload(settings, secret)
    involved_object = V1ObjectReference(
        api_version="v1",
        kind="Secret",
        name=secret.metadata.name,
        namespace=secret.metadata.namespace,
    )

    mode = settings.apply_mode
    if mode == "noop":
        success, message = apply_noop(payload)
    elif mode == "webhook":
        success, message = apply_webhook(payload, settings)
    else:
        raise ValueError(
            "VCENTER_APPLY_MODE non supportata. Valori ammessi: noop, webhook"
        )

    if success:
        _HEALTH["last_sync"] = isoformat_z(utc_now())
        _HEALTH["last_error"] = None
        publish_event(
            api=api,
            namespace=settings.namespace,
            involved_object=involved_object,
            event_type="Normal",
            reason="ReconcileSucceeded",
            message=(
                f"Riconciliazione completata per provider {settings.provider_name} "
                f"con modalità {settings.apply_mode}: {message}."
            ),
        )


def read_current_secret(api: CoreV1Api, namespace: str, name: str) -> V1Secret:
    return api.read_namespaced_secret(name=name, namespace=namespace)


def start_http_server() -> None:
    port = int(os.getenv("PORT", "8080"))
    APP.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)


@APP.get("/healthz")
def healthz() -> Any:
    status_code = 200 if _HEALTH["live"] else 503
    return jsonify(_HEALTH), status_code


@APP.get("/readyz")
def readyz() -> Any:
    status_code = 200 if _HEALTH["ready"] else 503
    return jsonify(_HEALTH), status_code


def watch_loop(api: CoreV1Api, settings: Settings) -> None:
    last_processed_hash = ""

    while True:
        stream = watch.Watch()
        try:
            current = read_current_secret(api, settings.namespace, settings.current_secret_name)
            current_hash = hash_secret_payload(current)
            if current_hash != last_processed_hash:
                reconcile_secret(api, settings, current)
                last_processed_hash = current_hash

            _HEALTH["ready"] = True

            for event in stream.stream(
                api.list_namespaced_secret,
                namespace=settings.namespace,
                field_selector=f"metadata.name={settings.current_secret_name}",
                timeout_seconds=300,
            ):
                event_type = event["type"]
                secret: V1Secret = event["object"]
                if event_type not in {"ADDED", "MODIFIED"}:
                    continue

                payload_hash = hash_secret_payload(secret)
                if payload_hash == last_processed_hash:
                    continue

                LOGGER.info(
                    "Rilevata modifica secret %s rv=%s",
                    secret.metadata.name,
                    secret.metadata.resource_version,
                )
                reconcile_secret(api, settings, secret)
                last_processed_hash = payload_hash
        except Exception as exc:
            _HEALTH["ready"] = False
            _HEALTH["last_error"] = str(exc)
            LOGGER.exception("Errore nel watch loop: %s", exc)
            time.sleep(5)
        finally:
            stream.stop()


def command_watch_secret_and_reconcile() -> int:
    settings = load_settings()
    api = load_kube_client()

    http_thread = threading.Thread(target=start_http_server, daemon=True)
    http_thread.start()

    watch_loop(api, settings)
    return 0


def main(argv: List[str]) -> int:
    configure_logging()
    if len(argv) < 2:
        LOGGER.error("Subcommand mancante")
        return 2

    command = argv[1]
    if command == "watch-secret-and-reconcile":
        return command_watch_secret_and_reconcile()

    LOGGER.error("Subcommand non supportato: %s", command)
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except Exception as exc:
        LOGGER.exception("Errore fatale: %s", exc)
        raise
