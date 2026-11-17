"""Perfis de ambiente prontos: atalhos para conjuntos de vendor/produto (formato CPE).

Usados em ``environment.profiles`` (o que eu tenho) e em ``exclude.profiles`` (o que eu
não tenho e não quero ver). Padrões aceitam curinga (``azure*``) e casam também por
prefixo de token: ``windows`` casa com ``windows_server_2022``.
"""

from __future__ import annotations

# perfil -> {vendor: [padrões de produto]}  (lista vazia = qualquer produto do vendor)
PROFILES: dict[str, dict[str, list[str]]] = {
    "azure": {
        "microsoft": [
            "azure*",
            "entra*",
            "azure_active_directory*",
            "defender_for_cloud*",
            "sentinel*",
        ],
    },
    "microsoft365": {
        "microsoft": [
            "365*",
            "office*",
            "exchange_server",
            "sharepoint*",
            "teams*",
            "outlook*",
            "onedrive*",
            "word",
            "excel",
            "powerpoint",
        ],
    },
    "windows": {"microsoft": ["windows*", "win32k", "hyper_v", ".net*", "edge_chromium"]},
    "aws": {"amazon": ["aws*", "amazon_*"], "aws": []},
    "gcp": {"google": ["cloud*", "kubernetes_engine", "gke*", "compute_engine"]},
    "google_workspace": {
        "google": ["workspace*", "gmail", "google_drive*", "drive*", "docs", "meet", "chrome_os"],
    },
    "linux": {"linux": ["linux_kernel"]},
    "kubernetes": {"kubernetes": [], "k8s": []},
}
