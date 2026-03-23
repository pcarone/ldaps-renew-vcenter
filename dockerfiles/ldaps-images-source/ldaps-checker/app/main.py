import hashlib
import json
import logging
import os
import re
import socket
import subprocess
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from kubernetes import client, config
from kubernetes.client import CoreV1Api, V1ObjectMeta, V1ObjectReference, V1Secret
from kubernetes.client.rest import ApiException
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization

LOGGER = logging.getLogger("ldaps-checker")
CERT_PATTERN = re.compile(
    rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
    re.DOTALL,
)


@dataclass(frozen=True)
class EndpointResult:
    name: str
    url: str
    host: str
    port: int
    certificates_pem: List[str]
    leaf_fingerprint_sha256: str
    chain_fingerprint_sha256: str
    subject: str
    issuer: str
    not_before: str
    not_after: str
    dns_names: List[str]


@dataclass(frozen=True)
class Settings:
    namespace: str
    current_secret_name: str
    history_secret_prefix: str
    primary_ldaps_url: str
    secondary_ldaps_url: str
    check_mode: str
    openssl_timeout_seconds: int


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def isoformat_z(value: datetime) -> str:
    return value.replace(microsecond=0).isoformat().replace("+00:00", "Z")


def configure_logging() -> None:
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def require_env(name: str, default: Optional[str] = None) -> str:
    value = os.getenv(name, default)
    if value is None or not str(value).strip():
        raise ValueError(f"Variabile ambiente obbligatoria non valorizzata: {name}")
    return value.strip()


def load_settings() -> Settings:
    return Settings(
        namespace=require_env("POD_NAMESPACE", "default"),
        current_secret_name=require_env("CURRENT_CERT_SECRET_NAME"),
        history_secret_prefix=require_env("HISTORY_CERT_SECRET_PREFIX"),
        primary_ldaps_url=require_env("PRIMARY_LDAPS_URL"),
        secondary_ldaps_url=os.getenv("SECONDARY_LDAPS_URL", "").strip(),
        check_mode=os.getenv("CHECK_MODE", "leaf-or-chain").strip(),
        openssl_timeout_seconds=int(os.getenv("OPENSSL_TIMEOUT_SECONDS", "15")),
    )


def load_kube_client() -> CoreV1Api:
    try:
        config.load_incluster_config()
    except config.ConfigException:
        config.load_kube_config()
    return client.CoreV1Api()


def parse_ldaps_url(url: str) -> Tuple[str, int]:
    parsed = urlparse(url)
    if parsed.scheme.lower() != "ldaps":
        raise ValueError(f"URL non LDAPS: {url}")
    if not parsed.hostname:
        raise ValueError(f"Hostname assente in URL: {url}")
    port = parsed.port or 636
    return parsed.hostname, port


def run_openssl(host: str, port: int, timeout_seconds: int) -> bytes:
    cmd = [
        "openssl",
        "s_client",
        "-showcerts",
        "-servername",
        host,
        "-connect",
        f"{host}:{port}",
        "-brief",
    ]
    LOGGER.info("Raccolta chain da %s:%s", host, port)
    result = subprocess.run(
        cmd,
        input=b"",
        capture_output=True,
        timeout=timeout_seconds,
        check=False,
    )
    combined = result.stdout + b"\n" + result.stderr
    if result.returncode != 0 and not CERT_PATTERN.search(combined):
        raise RuntimeError(
            f"openssl s_client ha fallito verso {host}:{port}: {combined.decode(errors='replace')}"
        )
    return combined


def normalize_pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def fingerprint_sha256(raw_bytes: bytes) -> str:
    return hashlib.sha256(raw_bytes).hexdigest()


def get_dns_names(cert: x509.Certificate) -> List[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return sorted(san.value.get_values_for_type(x509.DNSName))
    except x509.ExtensionNotFound:
        return []


def load_certificates_from_output(output: bytes) -> List[x509.Certificate]:
    chunks = CERT_PATTERN.findall(output)
    if not chunks:
        raise RuntimeError("Nessun certificato PEM estratto dall'output openssl")
    certs: List[x509.Certificate] = []
    for chunk in chunks:
        certs.append(x509.load_pem_x509_certificate(chunk))
    return certs


def build_endpoint_result(name: str, url: str, timeout_seconds: int) -> EndpointResult:
    host, port = parse_ldaps_url(url)
    raw_output = run_openssl(host, port, timeout_seconds)
    certs = load_certificates_from_output(raw_output)
    normalized_certs = [normalize_pem(cert) for cert in certs]
    leaf = certs[0]

    return EndpointResult(
        name=name,
        url=url,
        host=host,
        port=port,
        certificates_pem=normalized_certs,
        leaf_fingerprint_sha256=leaf.fingerprint(hashes.SHA256()).hex(),
        chain_fingerprint_sha256=fingerprint_sha256("".join(normalized_certs).encode("ascii")),
        subject=leaf.subject.rfc4514_string(),
        issuer=leaf.issuer.rfc4514_string(),
        not_before=leaf.not_valid_before_utc.isoformat().replace("+00:00", "Z"),
        not_after=leaf.not_valid_after_utc.isoformat().replace("+00:00", "Z"),
        dns_names=get_dns_names(leaf),
    )


def endpoint_to_metadata(result: EndpointResult) -> Dict[str, Any]:
    return {
        "name": result.name,
        "url": result.url,
        "host": result.host,
        "port": result.port,
        "leaf_fingerprint_sha256": result.leaf_fingerprint_sha256,
        "chain_fingerprint_sha256": result.chain_fingerprint_sha256,
        "subject": result.subject,
        "issuer": result.issuer,
        "not_before": result.not_before,
        "not_after": result.not_after,
        "dns_names": result.dns_names,
    }


def safe_json_loads(raw: Optional[str]) -> Dict[str, Any]:
    if not raw:
        return {}
    try:
        loaded = json.loads(raw)
        return loaded if isinstance(loaded, dict) else {}
    except json.JSONDecodeError:
        LOGGER.warning("metadata.json non parseabile; tratto come vuoto")
        return {}


def read_secret(api: CoreV1Api, namespace: str, name: str) -> V1Secret:
    return api.read_namespaced_secret(name=name, namespace=namespace)


def decode_secret_data(secret: V1Secret, key: str) -> Optional[str]:
    if not secret.data or key not in secret.data:
        return None
    return client.ApiClient().sanitize_for_serialization(secret.data[key])


def get_secret_string(secret: V1Secret, key: str) -> Optional[str]:
    if not secret.data or key not in secret.data:
        return None
    encoded = secret.data[key]
    import base64

    return base64.b64decode(encoded).decode("utf-8")


def build_combined_current_chain(primary: EndpointResult, secondary: Optional[EndpointResult]) -> str:
    if secondary is None:
        return "".join(primary.certificates_pem)
    # Mantiene la compatibilità con il manifest corrente: il campo storico principale resta leggibile.
    return (
        "# primary\n"
        + "".join(primary.certificates_pem)
        + "\n# secondary\n"
        + "".join(secondary.certificates_pem)
    )


def decide_change(
    check_mode: str,
    current_metadata: Dict[str, Any],
    primary: EndpointResult,
    secondary: Optional[EndpointResult],
) -> Tuple[bool, str]:
    current_primary = current_metadata.get("primary", {}) if isinstance(current_metadata.get("primary"), dict) else {}
    current_secondary = current_metadata.get("secondary", {}) if isinstance(current_metadata.get("secondary"), dict) else {}

    primary_leaf_changed = current_primary.get("leaf_fingerprint_sha256") != primary.leaf_fingerprint_sha256
    primary_chain_changed = current_primary.get("chain_fingerprint_sha256") != primary.chain_fingerprint_sha256

    secondary_leaf_changed = False
    secondary_chain_changed = False
    if secondary is not None:
        secondary_leaf_changed = current_secondary.get("leaf_fingerprint_sha256") != secondary.leaf_fingerprint_sha256
        secondary_chain_changed = current_secondary.get("chain_fingerprint_sha256") != secondary.chain_fingerprint_sha256
    elif current_secondary:
        secondary_leaf_changed = True
        secondary_chain_changed = True

    mode = check_mode.lower()
    if mode == "leaf-only":
        changed = primary_leaf_changed or secondary_leaf_changed
    elif mode == "chain-only":
        changed = primary_chain_changed or secondary_chain_changed
    elif mode == "leaf-or-chain":
        changed = (
            primary_leaf_changed
            or primary_chain_changed
            or secondary_leaf_changed
            or secondary_chain_changed
        )
    else:
        raise ValueError(f"CHECK_MODE non supportato: {check_mode}")

    reasons = []
    if primary_leaf_changed:
        reasons.append("primary leaf")
    if primary_chain_changed:
        reasons.append("primary chain")
    if secondary_leaf_changed:
        reasons.append("secondary leaf")
    if secondary_chain_changed:
        reasons.append("secondary chain")

    return changed, ", ".join(reasons) if reasons else "nessuna differenza"


def create_history_secret(
    api: CoreV1Api,
    namespace: str,
    secret_name: str,
    current_secret: V1Secret,
) -> None:
    if not current_secret.data:
        LOGGER.info("Secret corrente senza data: salto la secret storica")
        return

    history_name = secret_name
    body = V1Secret(
        metadata=V1ObjectMeta(
            name=history_name,
            namespace=namespace,
            labels={
                "app.kubernetes.io/name": "ldaps-vcenter-sync",
                "app.kubernetes.io/component": "history-certs",
            },
        ),
        type=current_secret.type or "Opaque",
        data=current_secret.data,
    )
    api.create_namespaced_secret(namespace=namespace, body=body)
    LOGGER.info("Creata secret storica %s", history_name)


def update_current_secret(
    api: CoreV1Api,
    settings: Settings,
    current_secret: V1Secret,
    primary: EndpointResult,
    secondary: Optional[EndpointResult],
    mismatch_reason: str,
) -> None:
    now = utc_now()
    metadata = {
        "source": "ldaps-checker",
        "domain": os.getenv("DOMAIN_NAME", ""),
        "primary_ldaps_url": primary.url,
        "secondary_ldaps_url": secondary.url if secondary else "",
        "fingerprint_sha256": primary.leaf_fingerprint_sha256,
        "not_before": primary.not_before,
        "not_after": primary.not_after,
        "updated_at": isoformat_z(now),
        "check_mode": settings.check_mode,
        "mismatch_reason": mismatch_reason,
        "primary": endpoint_to_metadata(primary),
        "secondary": endpoint_to_metadata(secondary) if secondary else None,
    }
    string_data = {
        "cert-chain.pem": build_combined_current_chain(primary, secondary),
        "metadata.json": json.dumps(metadata, indent=2, sort_keys=True),
        "primary-chain.pem": "".join(primary.certificates_pem),
        "primary-leaf.pem": primary.certificates_pem[0],
    }
    if secondary is not None:
        string_data["secondary-chain.pem"] = "".join(secondary.certificates_pem)
        string_data["secondary-leaf.pem"] = secondary.certificates_pem[0]

    body = {
        "metadata": {
            "resourceVersion": current_secret.metadata.resource_version,
            "annotations": {
                **(current_secret.metadata.annotations or {}),
                "ldaps-sync/updated-at": isoformat_z(now),
                "ldaps-sync/check-mode": settings.check_mode,
            },
        },
        "stringData": string_data,
        "type": current_secret.type or "Opaque",
    }
    api.patch_namespaced_secret(
        name=settings.current_secret_name,
        namespace=settings.namespace,
        body=body,
    )
    LOGGER.info("Aggiornata secret corrente %s", settings.current_secret_name)


def publish_event(
    api: CoreV1Api,
    namespace: str,
    involved_object: V1ObjectReference,
    event_type: str,
    reason: str,
    message: str,
) -> None:
    now = utc_now()
    safe_reason = reason[:128]
    body = {
        "metadata": {
            "generateName": f"{involved_object.name.lower()}-",
            "namespace": namespace,
        },
        "type": event_type,
        "reason": safe_reason,
        "message": message,
        "reportingComponent": "ldaps-checker",
        "reportingInstance": socket.gethostname(),
        "action": reason,
        "regarding": {
            "apiVersion": involved_object.api_version,
            "kind": involved_object.kind,
            "name": involved_object.name,
            "namespace": involved_object.namespace,
        },
        "eventTime": isoformat_z(now),
    }
    try:
        api.create_namespaced_event(namespace=namespace, body=body)
    except ApiException as exc:
        LOGGER.warning("Impossibile creare Event Kubernetes: %s", exc)


def command_check_and_update_secret() -> int:
    settings = load_settings()
    api = load_kube_client()
    current_secret = read_secret(api, settings.namespace, settings.current_secret_name)

    current_metadata = safe_json_loads(get_secret_string(current_secret, "metadata.json"))
    primary = build_endpoint_result("primary", settings.primary_ldaps_url, settings.openssl_timeout_seconds)
    secondary = (
        build_endpoint_result("secondary", settings.secondary_ldaps_url, settings.openssl_timeout_seconds)
        if settings.secondary_ldaps_url
        else None
    )

    changed, mismatch_reason = decide_change(settings.check_mode, current_metadata, primary, secondary)
    LOGGER.info("Esito confronto: changed=%s reason=%s", changed, mismatch_reason)

    involved_object = V1ObjectReference(
        api_version="v1",
        kind="Secret",
        name=settings.current_secret_name,
        namespace=settings.namespace,
    )

    if not changed:
        publish_event(
            api=api,
            namespace=settings.namespace,
            involved_object=involved_object,
            event_type="Normal",
            reason="NoChange",
            message="Nessuna variazione dei certificati LDAPS rilevata.",
        )
        return 0

    timestamp = utc_now().strftime("%Y%m%d-%H%M%S")
    history_secret_name = f"{settings.history_secret_prefix}-{timestamp}"
    create_history_secret(api, settings.namespace, history_secret_name, current_secret)
    update_current_secret(api, settings, current_secret, primary, secondary, mismatch_reason)
    publish_event(
        api=api,
        namespace=settings.namespace,
        involved_object=involved_object,
        event_type="Normal",
        reason="CertificateUpdated",
        message=(
            f"Certificati LDAPS aggiornati nella secret {settings.current_secret_name}; "
            f"backup creato in {history_secret_name}; motivo: {mismatch_reason}."
        ),
    )
    return 0


def main(argv: List[str]) -> int:
    configure_logging()
    if len(argv) < 2:
        LOGGER.error("Subcommand mancante")
        return 2

    command = argv[1]
    if command == "check-and-update-secret":
        return command_check_and_update_secret()

    LOGGER.error("Subcommand non supportato: %s", command)
    return 2


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv))
    except Exception as exc:
        LOGGER.exception("Errore fatale: %s", exc)
        raise
