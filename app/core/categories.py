"""Categorização das vulnerabilidades por tipo de falha (CWE + palavras-chave).

Quando há mais de um candidato, vence o de maior impacto (ordem de ``CATEGORIES``).
"""

from __future__ import annotations

import re

from app.models.vulnerability import Vulnerability

# Ordem = prioridade (maior impacto primeiro).
CATEGORIES: list[tuple[str, set[int], tuple[str, ...]]] = [
    (
        "Execução remota de código",
        {77, 78, 94, 95, 434, 917, 1336},
        (
            "remote code execution",
            "arbitrary code execution",
            "execute arbitrary code",
            "execute code",
            "execute commands",
            "command injection",
            "code injection",
            " rce ",
        ),
    ),
    ("Desserialização insegura", {502}, ("deserialization",)),
    (
        "Bypass de autenticação",
        {287, 288, 290, 294, 306, 798, 1390},
        (
            "authentication bypass",
            "bypass authentication",
            "hard-coded credential",
            "missing authentication",
        ),
    ),
    (
        "Escalação de privilégio",
        {250, 266, 269, 274},
        (
            "privilege escalation",
            "elevation of privilege",
            "escalate privileges",
            "gain elevated privileges",
        ),
    ),
    (
        "Corrupção de memória",
        {119, 120, 121, 122, 125, 190, 415, 416, 787, 843},
        (
            "buffer overflow",
            "use-after-free",
            "use after free",
            "out-of-bounds",
            "heap overflow",
            "memory corruption",
            "type confusion",
        ),
    ),
    ("Injeção SQL", {89}, ("sql injection",)),
    ("XXE", {611, 776}, ("xml external entity", "xxe")),
    ("SSRF", {918}, ("server-side request forgery", "ssrf")),
    ("Path traversal", {22, 23, 35, 59}, ("path traversal", "directory traversal")),
    (
        "Controle de acesso",
        {284, 285, 639, 732, 862, 863},
        ("improper access control", "missing authorization", "security feature bypass"),
    ),
    ("XSS", {79}, ("cross-site scripting", "xss")),
    ("CSRF", {352}, ("cross-site request forgery", "csrf")),
    ("Spoofing", {345, 346, 451}, ("spoofing",)),
    (
        "Divulgação de informação",
        {200, 209, 312, 359, 532},
        ("information disclosure", "sensitive information", "information leak"),
    ),
    (
        "Negação de serviço",
        {400, 476, 674, 770, 835},
        ("denial of service", "denial-of-service"),
    ),
]
DEFAULT_CATEGORY = "Outros"

_CWE_RE = re.compile(r"CWE-(\d+)")


def categorize(vuln: Vulnerability) -> str:
    cwe_ids = {int(m.group(1)) for c in vuln.cwes if (m := _CWE_RE.search(c))}
    text = f" {vuln.title or ''} {vuln.description} ".lower()
    for name, cwes, keywords in CATEGORIES:
        if cwe_ids & cwes or any(k in text for k in keywords):
            return name
    return DEFAULT_CATEGORY
