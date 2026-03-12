"""
Blurred – anonymization API
──────────────────────────
Flow:
  1. Regex strips structured PII (IPs, DNIs, emails…) → replaces with __BLUR_N__ tokens
  2. LLM receives tokenised text → detects proper names → returns JSON {anonymized_text, mappings}
  3. Tokens are swapped back for realistic fake values
  4. Full reverse-mapping stored in session (fake→original) for de-anonymisation by regex

De-anonymisation:
  • Pure regex replacement using stored session map
  • No LLM call needed
"""

import asyncio
import base64
import json
import os
import random
import re
import string
import uuid
from pathlib import Path
from typing import Optional

import httpx
from faker import Faker
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

# ── Configuration ─────────────────────────────────────────────────────────────

LLM_BASE_URL = os.getenv("LLM_BASE_URL", "http://llama-server:8080/v1")
LLM_API_KEY  = os.getenv("LLM_API_KEY",  "llm-local-key-changeme-abc123")
LLM_MODEL    = os.getenv("LLM_MODEL",    "qwen-coder")
LLM_TIMEOUT  = int(os.getenv("LLM_TIMEOUT", "120"))

app = FastAPI(title="Blurred – Text Anonymiser")

fake_es = Faker("es_ES")
fake_en = Faker("en_US")

# Session store  {session_id: {fake_value: original_value}}
sessions: dict[str, dict[str, str]] = {}

# ── Global persistent dictionary ──────────────────────────────────────────────
# {original: fake}  –  built incrementally across all anonymisation requests.
# Applied by regex before the LLM so known values are never re-delegated.

_GLOBAL_MAP_PATH = Path(os.getenv("GLOBAL_MAP_PATH", "/app/data/global_map.json"))
_global_map: dict[str, str] = {}       # original → fake
_global_map_lock = asyncio.Lock()


def _load_global_map() -> None:
    global _global_map
    if _GLOBAL_MAP_PATH.exists():
        try:
            _global_map = json.loads(_GLOBAL_MAP_PATH.read_text(encoding="utf-8"))
            print(f"[blurred] Global map loaded: {len(_global_map)} entries")
        except Exception as exc:
            print(f"[blurred] Could not load global map: {exc}")
            _global_map = {}


def _save_global_map() -> None:
    try:
        _GLOBAL_MAP_PATH.parent.mkdir(parents=True, exist_ok=True)
        _GLOBAL_MAP_PATH.write_text(
            json.dumps(_global_map, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception as exc:
        print(f"[blurred] Could not save global map: {exc}")


def _apply_global_map(text: str) -> tuple[str, dict[str, str]]:
    """
    Replace known originals with their established fakes.
    Sorts longest-first to avoid partial-match bugs.
    Returns (processed_text, {original: fake} of what was actually substituted).
    """
    applied: dict[str, str] = {}
    for orig, fake in sorted(_global_map.items(), key=lambda x: -len(x[0])):
        if orig in text:
            text = text.replace(orig, fake)
            applied[orig] = fake
    return text, applied


_load_global_map()

# ── Fake-value generators ──────────────────────────────────────────────────────

DNI_LETTERS = "TRWAGMYFPDXBNJZSQVHLCKE"

def _gen_dni(_m=None) -> str:
    n = random.randint(10_000_000, 99_999_999)
    return f"{n}{DNI_LETTERS[n % 23]}"

def _gen_nie(_m=None) -> str:
    prefix = random.choice("XYZ")
    num_map = {"X": 0, "Y": 1, "Z": 2}
    base = random.randint(1_000_000, 9_999_999)
    full = num_map[prefix] * 10_000_000 + base
    return f"{prefix}{base:07d}{DNI_LETTERS[full % 23]}"

def _gen_ipv4(_m=None) -> str:
    while True:
        a = random.randint(1, 223)
        if a not in (10, 100, 127, 169, 172, 192, 198, 203):
            return f"{a}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

def _gen_private_ip(_m=None) -> str:
    nets = [
        (10, random.randint(0,255), random.randint(0,255), random.randint(1,254)),
        (172, random.randint(16,31), random.randint(0,255), random.randint(1,254)),
        (192, 168, random.randint(0,255), random.randint(1,254)),
    ]
    return ".".join(str(x) for x in random.choice(nets))

def _gen_email(_m=None) -> str:
    first = fake_es.first_name().lower().replace(" ", "")
    last  = fake_es.last_name().lower().replace(" ", "")
    domain = fake_en.domain_name()
    return f"{first}.{last}@{domain}"

def _gen_domain(_m=None) -> str:
    tlds = ["com", "es", "net", "org", "io", "eu", "co"]
    word = fake_en.word()
    return f"{word}.{random.choice(tlds)}"

def _gen_url(m) -> str:
    scheme = "https" if m and "https" in m.group(0) else "http"
    path   = "".join(random.choices(string.ascii_lowercase, k=6))
    return f"{scheme}://{_gen_domain()}/{path}"

def _gen_phone_es(_m=None) -> str:
    prefix = random.choice(["6", "7"])
    return f"+34 {prefix}{''.join(random.choices(string.digits, k=8))}"

def _gen_iban_es(_m=None) -> str:
    cc   = random.randint(10, 99)
    ent  = random.randint(1000, 9999)
    off  = random.randint(1000, 9999)
    dc   = random.randint(10, 99)
    acc  = random.randint(1_000_000_000, 9_999_999_999)
    return f"ES{cc} {ent} {off} {dc} {acc}"

def _gen_mac(_m=None) -> str:
    return ":".join(f"{random.randint(0,255):02x}" for _ in range(6))

def _gen_cif(_m=None) -> str:
    types = "ABCDEFGHJKLMNPQRSUVW"
    t = random.choice(types)
    body = random.randint(1_000_000, 9_999_999)
    ctrl = random.randint(0, 9)
    return f"{t}-{body}{ctrl}"

def _gen_hash(m) -> str:
    length = len(m.group(0))
    return "".join(random.choices("0123456789abcdef", k=length))

def _gen_ref(_m=None) -> str:
    prefix = "".join(random.choices(string.ascii_uppercase, k=3))
    year   = random.randint(2020, 2027)
    num    = random.randint(1000, 9999)
    return f"{prefix}-{year}-{num:04d}"

def _gen_employee_id(_m=None) -> str:
    return f"EMP-{random.randint(10000, 99999)}"

def _gen_jwt(_m=None) -> str:
    hdr = base64.urlsafe_b64encode(b'{"alg":"RS256","typ":"JWT"}').rstrip(b'=').decode()
    sub = uuid.uuid4().hex
    pay = base64.urlsafe_b64encode(f'{{"sub":"{sub}","iat":1700000000}}'.encode()).rstrip(b'=').decode()
    sig = base64.urlsafe_b64encode(bytes(random.randint(0, 255) for _ in range(32))).rstrip(b'=').decode()
    return f"{hdr}.{pay}.{sig}"

def _gen_opaque_token(_m=None) -> str:
    prefix = "".join(random.choices(string.ascii_uppercase + string.digits, k=7))
    return f"_{prefix}_{uuid.uuid4()}"

def _gen_uuid_val(_m=None) -> str:
    return str(uuid.uuid4())

def _gen_session_token(_m=None) -> str:
    """Random base64-looking session/cookie token (realistic length)."""
    length = random.choice([24, 32, 48])
    data = bytes(random.randint(0, 255) for _ in range(length))
    return base64.b64encode(data).decode()

# ── Context patterns (match by key/label, replace only the value) ─────────────
# Each pattern MUST have exactly 3 capture groups: (prefix)(value)(suffix)
# The replacer keeps group(1) and group(3), substitutes group(2) with a fake.
# These run BEFORE structural patterns so field-name-identified values are caught
# regardless of their format (opaque tokens, custom schemes, etc.).

CONTEXT_PATTERNS: list[tuple[str, re.Pattern, callable]] = [
    # ── JSON: OAuth / token fields ─────────────────────────────────────────────
    ("json_access_token",
     re.compile(r'("(?:accessToken|access_token)"\s*:\s*")([^"]+)(")'),
     _gen_opaque_token),
    ("json_refresh_token",
     re.compile(r'("(?:refreshToken|refresh_token|curityRefresh)"\s*:\s*")([^"]+)(")'),
     _gen_opaque_token),
    ("json_id_token",
     re.compile(r'("(?:idToken|id_token)"\s*:\s*")([^"]+)(")'),
     _gen_jwt),
    ("json_token_generic",
     re.compile(r'("(?:token|sessionToken|session_token|authToken|auth_token|bearerToken|bearer_token|userToken|user_token|deviceToken|device_token)"\s*:\s*")([^"]+)(")'),
     _gen_opaque_token),
    # ── JSON: credentials & secrets ────────────────────────────────────────────
    ("json_credentials",
     re.compile(r'("(?:password|passwd|pass|secret|client_secret|clientSecret|api_key|apiKey|apikey|credential|credentials|auth_token|privateKey|private_key|signing_key|signingKey)"\s*:\s*")([^"]+)(")'),
     _gen_opaque_token),
    # ── JSON: CSRF / anti-forgery ──────────────────────────────────────────────
    ("json_csrf",
     re.compile(r'("(?:csrfToken|csrf_token|_csrf|xsrfToken|xsrf_token|antiForgery|anti_forgery_token)"\s*:\s*")([^"]+)(")'),
     _gen_opaque_token),
    # ── JSON: OAuth flow ───────────────────────────────────────────────────────
    ("json_oauth_code",
     re.compile(r'("(?:code|auth_code|authCode|authorization_code)"\s*:\s*")([^"]{8,})(")'),  # min 8 chars avoids false positives on "code":"200"
     _gen_opaque_token),
    ("json_nonce",
     re.compile(r'("nonce"\s*:\s*")([^"]+)(")'),
     _gen_opaque_token),
    # ── JSON: OTP / PIN ────────────────────────────────────────────────────────
    ("json_otp",
     re.compile(r'("(?:otp|one_time_password|oneTimePassword|pin|mfaCode|mfa_code|totpCode|totp_code)"\s*:\s*")([^"]+)(")'),
     _gen_opaque_token),
    # ── JSON: financial / PCI ──────────────────────────────────────────────────
    ("json_card",
     re.compile(r'("(?:cardNumber|card_number|pan|cvv|cvc|cvv2|expiryDate|expiry_date|cardHolder|card_holder)"\s*:\s*")([^"]+)(")'),
     _gen_opaque_token),
    ("json_account",
     re.compile(r'("(?:accountNumber|account_number|routingNumber|routing_number|sortCode|sort_code|bban|iban)"\s*:\s*")([^"]+)(")'),
     _gen_opaque_token),
    # ── HTTP: Authorization ────────────────────────────────────────────────────
    ("header_bearer",
     re.compile(r'(Authorization:\s*Bearer\s+)(\S+)()', re.I),
     _gen_opaque_token),
    ("header_basic",
     re.compile(r'(Authorization:\s*Basic\s+)([A-Za-z0-9+/]+=*)()', re.I),
     _gen_session_token),
    ("header_digest",
     re.compile(r'(Authorization:\s*Digest\s+)([^\r\n]+)()', re.I),
     _gen_opaque_token),
    ("header_proxy_auth",
     re.compile(r'(Proxy-Authorization:\s*\w+\s+)(\S+)()', re.I),
     _gen_opaque_token),
    # ── HTTP: Set-Cookie (response) – only the value, before first ";" ─────────
    ("set_cookie",
     re.compile(r'(Set-Cookie:\s*[\w.\-]+=)([^;\r\n]+)((?:;|$))', re.I),
     _gen_session_token),
    # ── HTTP: Cookie (request) – values of sensitive cookie names ─────────────
    # Matches: session=abc; token=xyz inside the Cookie header value
    ("req_cookie_sensitive",
     re.compile(r'((?:session(?:id)?|token|auth|jwt|access_token|refresh_token|sid|ssid|userid|user_id)=)([^;\s\r\n]+)((?:;|$|\s))', re.I),
     _gen_session_token),
    # ── HTTP: CSRF tokens ─────────────────────────────────────────────────────
    ("header_csrf",
     re.compile(r'(X-(?:CSRF|XSRF)-Token:\s*)(\S+)()', re.I),
     _gen_opaque_token),
    ("header_csrf_alt",
     re.compile(r'(X-(?:Requested-With|Request-Token|Anti-Forgery):\s*)(\S+)()', re.I),
     _gen_opaque_token),
    # ── HTTP: Token/key headers ────────────────────────────────────────────────
    ("header_x_api_key",
     re.compile(r'(X-Api-Key:\s*)(\S+)()', re.I),
     _gen_opaque_token),
    ("header_x_auth_token",
     re.compile(r'(X-Auth-Token:\s*)(\S+)()', re.I),
     _gen_opaque_token),
    ("header_x_session",
     re.compile(r'(X-Session(?:-Token|-Id)?:\s*)(\S+)()', re.I),
     _gen_session_token),
    ("header_x_access_token",
     re.compile(r'(X-Access-Token:\s*)(\S+)()', re.I),
     _gen_opaque_token),
    ("header_x_refresh_token",
     re.compile(r'(X-Refresh-Token:\s*)(\S+)()', re.I),
     _gen_opaque_token),
    ("header_x_device",
     re.compile(r'(X-Device-(?:Token|Id|Key):\s*)(\S+)()', re.I),
     _gen_opaque_token),
    ("header_x_user",
     re.compile(r'(X-(?:User|Client)-(?:Token|Id|Key):\s*)(\S+)()', re.I),
     _gen_opaque_token),
    # ── HTTP: Real-IP / forwarded (privacy) ───────────────────────────────────
    # (IPs are also caught by the structural ipv4 pattern; this covers the header label)
    ("header_forwarded_for",
     re.compile(r'(X-Forwarded-For:\s*)([^\r\n]+)()', re.I),
     _gen_ipv4),
    ("header_real_ip",
     re.compile(r'((?:X-Real-IP|CF-Connecting-IP|True-Client-IP|X-Client-IP|X-Originating-IP):\s*)([^\r\n]+)()', re.I),
     _gen_ipv4),
    # ── URL / form-encoded params ──────────────────────────────────────────────
    ("param_password",
     re.compile(r'((?:password|passwd|pass)=)([^&\s\r\n#"\']+)(&|$)', re.I),
     _gen_opaque_token),
    ("param_token",
     re.compile(r'((?:token|access_token|refresh_token|id_token|api_key|apikey|secret|client_secret)=)([^&\s\r\n#"\']{8,})(&|$)', re.I),
     _gen_opaque_token),
    ("param_code",
     re.compile(r'((?:code|auth_code|authorization_code)=)([^&\s\r\n#"\']{8,})(&|$)', re.I),
     _gen_opaque_token),
]

# ── Regex patterns (order matters: most-specific first) ───────────────────────

PATTERNS: list[tuple[str, re.Pattern, callable]] = [
    # URLs  (before email/domain to avoid double-matching)
    ("url",      re.compile(r'https?://[^\s<>"\'{}|\\^\[\]`]+'),                                                                 _gen_url),
    # JWT  (before hashes – base64url, not pure hex; three dot-separated segments starting with eyJ)
    ("jwt",      re.compile(r'eyJ[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]{2,}\.[A-Za-z0-9_-]*'),                                       _gen_jwt),
    # Opaque bearer tokens: _PREFIX_uuid  (before plain UUID to avoid partial match)
    ("opaque",   re.compile(r'_[A-Z0-9]{2,}_[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}'),   _gen_opaque_token),
    # UUID / GUID  (correlation IDs, request IDs, app IDs, session IDs…)
    ("uuid",     re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b'),              _gen_uuid_val),
    # Email  (before standalone domain)
    ("email",    re.compile(r'\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b'),                                          _gen_email),
    # MAC address  (before IPv4 to avoid partial matches)
    ("mac",      re.compile(r'\b(?:[0-9A-Fa-f]{2}[:\-]){5}[0-9A-Fa-f]{2}\b'),                                                  _gen_mac),
    # IPv4
    ("ipv4",     re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),                  _gen_ipv4),
    # SHA-256 (64 hex chars) — before shorter hashes
    ("sha256",   re.compile(r'\b[0-9a-fA-F]{64}\b'),                                                                            _gen_hash),
    # SHA-1 (40 hex chars)
    ("sha1",     re.compile(r'\b[0-9a-fA-F]{40}\b'),                                                                            _gen_hash),
    # MD5 (32 hex chars)
    ("md5",      re.compile(r'\b[0-9a-fA-F]{32}\b'),                                                                            _gen_hash),
    # Spanish IBAN
    ("iban",     re.compile(r'\bES\d{2}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}[\s\-]?\d{4}\b', re.I),               _gen_iban_es),
    # CIF Spain (before NIE/DNI – starts with letter)
    ("cif",      re.compile(r'\b[ABCDEFGHJKLMNPQRSUVW][-]?\d{7}[\dA-J]\b'),                                                     _gen_cif),
    # NIE  (before DNI – starts with X/Y/Z)
    ("nie",      re.compile(r'\b[XYZ][-\s]?\d{7}[-\s]?[A-HJ-NP-TV-Z]\b', re.I),                                               _gen_nie),
    # DNI Spain — with or without hyphen/space before letter  (e.g. 51348276-K or 51348276K)
    ("dni",      re.compile(r'\b\d{8}[-\s]?[A-HJ-NP-TV-Z]\b'),                                                                  _gen_dni),
    # Internal reference codes: INC-2026-0442, REF-2025-001, TKT-0042…
    ("ref",      re.compile(r'\b[A-Z]{2,5}-\d{4}-\d{3,6}\b'),                                                                   _gen_ref),
    # Employee / internal IDs: EMP-20198, USR-001…
    ("empid",    re.compile(r'\b(?:EMP|USR|ID|EMPL|TRB)[-_]?\d{3,8}\b', re.I),                                                  _gen_employee_id),
    # Spanish phone
    ("phone",    re.compile(r'\b(?:\+34[\s\-]?|0034[\s\-]?)?[6-9]\d{8}\b'),                                                     _gen_phone_es),
    # Standalone domain  (after URL/email)
    ("domain",   re.compile(r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+(?:com|es|net|org|io|eu|co)\b'),          _gen_domain),
]

# ── Core anonymisation logic ───────────────────────────────────────────────────

def apply_regex_anonymisation(text: str) -> tuple[str, dict[str, str], dict[str, str]]:
    """
    Returns:
        tokenised_text  – PII replaced by __BLUR_N__ markers
        token_to_fake   – {token: fake_value}
        real_to_fake    – {original: fake_value}  (for display mapping)

    Processing order:
        1. CONTEXT_PATTERNS  – field-name-based (most intentional, run first)
        2. PATTERNS          – value-structure-based (catch anything still unmatched)
    """
    real_to_fake:  dict[str, str] = {}
    real_to_token: dict[str, str] = {}
    token_to_fake: dict[str, str] = {}
    counter = [0]

    def make_replacer(gen):
        """Full-match replacer: replaces the entire regex match."""
        def replacer(match: re.Match) -> str:
            original = match.group(0)
            if original in real_to_token:
                return real_to_token[original]
            fake  = gen(match)
            token = f"__BLUR_{counter[0]}__"
            counter[0] += 1
            real_to_fake[original]  = fake
            real_to_token[original] = token
            token_to_fake[token]    = fake
            return token
        return replacer

    def make_context_replacer(gen):
        """Context-aware replacer: keeps group(1) and group(3), replaces only group(2)."""
        def replacer(match: re.Match) -> str:
            original = match.group(2)  # just the value, not the surrounding key/delimiter
            if original in real_to_token:
                return match.group(1) + real_to_token[original] + match.group(3)
            fake  = gen(match)
            token = f"__BLUR_{counter[0]}__"
            counter[0] += 1
            real_to_fake[original]  = fake
            real_to_token[original] = token
            token_to_fake[token]    = fake
            return match.group(1) + token + match.group(3)
        return replacer

    # 1 – Context patterns first (field-name-based: reliable regardless of value format)
    for _name, pattern, gen in CONTEXT_PATTERNS:
        text = pattern.sub(make_context_replacer(gen), text)

    # 2 – Structural patterns (value-format-based: catch anything still unmatched)
    for _name, pattern, gen in PATTERNS:
        text = pattern.sub(make_replacer(gen), text)

    return text, token_to_fake, real_to_fake


_SYSTEM_PROMPT = (
    "Eres un experto en anonimización de datos personales y corporativos. "
    "Tu tarea es identificar y reemplazar TODA la información identificable que NO haya sido ya sustituida por tokens __BLUR_N__.\n\n"
    "DEBES reemplazar obligatoriamente:\n"
    "1. Nombres completos de personas (nombre + apellidos).\n"
    "2. Razones sociales y nombres de empresas: cualquier nombre seguido de forma jurídica "
    "   (S.L., S.A., S.L.U., S.A.U., S.C., S.C.P., S.L.P., Ltd., GmbH, Inc., Corp…) "
    "   ES SIEMPRE una empresa y DEBE anonimizarse sin excepción. "
    "   También nombres de organizaciones, departamentos, marcas o productos comerciales "
    "   que aparezcan sin forma jurídica.\n"
    "3. Nombres de usuario, cuentas de sistema, handles o logins "
    "   (ej: r.castellano, dbadmin_nexo, admin_user, jdoe).\n"
    "4. Direcciones físicas completas (calle, número, piso, ciudad, código postal, país).\n"
    "5. Nombres de ciudades, municipios o ubicaciones geográficas específicas "
    "   cuando sean identificativos del incidente o la persona.\n"
    "6. Nombres de centros de datos, instalaciones o sedes corporativas específicas.\n"
    "7. Nombres de repositorios, proyectos o recursos internos "
    "   (ej: config-prod, infraestructura, proyecto-x).\n"
    "8. [PRIORIDAD MÁXIMA] Si el texto contiene tráfico HTTP (peticiones, respuestas, logs, curl…):\n"
    "   a) Cabeceras de autenticación: valores de Authorization (Bearer, Basic, Digest, NTLM…), "
    "      Cookie, X-Api-Key, X-Auth-Token, Proxy-Authorization y cualquier cabecera personalizada "
    "      que transporte credenciales o tokens.\n"
    "   b) Cuerpo JSON/form-data/XML: valores de campos como "
    "      accessToken, refreshToken, idToken, curityRefresh, "
    "      access_token, refresh_token, id_token, token, api_key, client_secret, "
    "      password, passwd, secret, credential, auth y similares.\n"
    "   c) Parámetros de query string o path que identifiquen a la corporación: nombres de empresa, "
    "      dominios corporativos, identificadores de tenant, subdominios o rutas internas "
    "      (ej: ?org=nexodata, /api/nexodata-solutions/, tenant_id=acme-corp).\n"
    "   d) Cabeceras Set-Cookie: reemplaza el VALOR de cada cookie (la parte antes del primer ';') "
    "      dejando intactos el nombre de la cookie y sus atributos (Path, Domain, Expires, "
    "      HttpOnly, Secure, SameSite).\n"
    "   e) Identificadores de correlación/traza/sesión en cabeceras "
    "      (X-Correlation-Id, X-Request-Id, X-Trace-Id, Request-Id, appId…): "
    "      reemplaza el valor por un identificador falso del mismo formato.\n"
    "   Sustituye siempre los VALORES; conserva los nombres de cabecera/campo/parámetro.\n\n"
    "REGLAS:\n"
    "- Los tokens __BLUR_N__ son marcadores ya procesados: NO los modifiques bajo ningún concepto.\n"
    "- Si el mensaje incluye un bloque 'VALORES_YA_ANONIMIZADOS', esos valores son sustituciones "
    "  ficticias previamente generadas: NO los vuelvas a anonimizar.\n"
    "- Usa sustituciones realistas y coherentes en español "
    "  (nombres de personas españoles, empresas con forma jurídica S.L./S.A., ciudades reales).\n"
    "- Mantén la misma forma jurídica cuando reemplaces empresas (S.L.→S.L., S.A.→S.A.).\n"
    "- Sé consistente: si un nombre aparece varias veces, usa siempre el mismo reemplazo.\n"
    "- Mantén el tono, la estructura y la coherencia del texto.\n\n"
    "Responde ÚNICAMENTE con JSON válido con esta estructura:\n"
    '{"anonymized_text": "texto completo anonimizado", '
    '"mappings": {"ValorFalso": "ValorOriginal"}}\n\n'
    "No incluyas ningún texto fuera del JSON."
)

_CHUNK_MAX_CHARS = int(os.getenv("BLUR_CHUNK_SIZE", "3000"))


def _split_into_chunks(text: str) -> list[str]:
    """Split text at line boundaries into chunks of at most _CHUNK_MAX_CHARS characters."""
    lines = text.split('\n')
    chunks: list[str] = []
    current: list[str] = []
    current_len = 0

    for line in lines:
        line_len = len(line) + 1  # +1 for the joining \n
        if current and current_len + line_len > _CHUNK_MAX_CHARS:
            chunks.append('\n'.join(current))
            current = [line]
            current_len = line_len
        else:
            current.append(line)
            current_len += line_len

    if current:
        chunks.append('\n'.join(current))

    return chunks or [text]


async def _call_llm_chunk(chunk: str, known_fakes: set[str]) -> tuple[str, dict[str, str]]:
    """
    Call LLM for a single text chunk.
    known_fakes: fake values already in use so the LLM won't re-anonymize them.
    Returns: (anonymised_chunk, {fake: original})
    """
    user_content = chunk
    if known_fakes:
        fakes_block = "\n".join(f"  - {f}" for f in sorted(known_fakes)[:60])
        user_content = (
            f"VALORES_YA_ANONIMIZADOS (son sustituciones ficticias ya aplicadas — NO modificar):\n"
            f"{fakes_block}\n\n"
            f"TEXTO:\n{chunk}"
        )

    try:
        async with httpx.AsyncClient(timeout=LLM_TIMEOUT) as client:
            resp = await client.post(
                f"{LLM_BASE_URL}/chat/completions",
                headers={"Authorization": f"Bearer {LLM_API_KEY}", "Content-Type": "application/json"},
                json={
                    "model": LLM_MODEL,
                    "messages": [
                        {"role": "system", "content": _SYSTEM_PROMPT},
                        {"role": "user",   "content": user_content},
                    ],
                    "temperature": 0.4,
                    "max_tokens": 4096,
                    "response_format": {"type": "json_object"},
                },
            )
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]

            try:
                result = json.loads(content)
                mappings = {str(k): str(v) for k, v in result.get("mappings", {}).items()}
                return result.get("anonymized_text") or chunk, mappings
            except json.JSONDecodeError:
                m = re.search(r'\{.*\}', content, re.DOTALL)
                if m:
                    result = json.loads(m.group(0))
                    mappings = {str(k): str(v) for k, v in result.get("mappings", {}).items()}
                    return result.get("anonymized_text") or chunk, mappings

    except Exception as exc:
        print(f"[blurred] LLM error (chunk skipped): {exc}")

    return chunk, {}


async def call_llm_for_names(
    tokenised_text: str,
    initial_known_fakes: set[str] | None = None,
) -> tuple[str, dict[str, str]]:
    """
    Split text into chunks, call LLM per chunk carrying the cumulative substitution
    map forward so each chunk inherits previous anonymisations.

    initial_known_fakes: fake values already present in the text (from global map)
    so the LLM is told not to re-anonymize them.

    Returns: (anonymised_text, {fake_name: original_name})
    """
    chunks = _split_into_chunks(tokenised_text)
    orig_to_fake: dict[str, str] = {}   # cumulative: original → fake
    result_parts: list[str] = []
    seed_fakes = initial_known_fakes or set()

    for chunk in chunks:
        # Pre-apply substitutions discovered in previous chunks
        pre_chunk = chunk
        for orig, fake in orig_to_fake.items():
            pre_chunk = pre_chunk.replace(orig, fake)

        anon_chunk, new_mappings = await _call_llm_chunk(
            pre_chunk, seed_fakes | set(orig_to_fake.values())
        )

        # new_mappings: {fake: original} — merge, first occurrence wins
        for fake, orig in new_mappings.items():
            if orig not in orig_to_fake:
                orig_to_fake[orig] = fake

        result_parts.append(anon_chunk)

    return '\n'.join(result_parts), {v: k for k, v in orig_to_fake.items()}


# ── Request / response models ──────────────────────────────────────────────────

class AnonymiseRequest(BaseModel):
    text:       str
    session_id: Optional[str] = None

class DeblurRequest(BaseModel):
    text:       str
    session_id: str

class ManualEntry(BaseModel):
    original: str
    fake:     Optional[str] = None   # if omitted, auto-generated

class AddEntriesRequest(BaseModel):
    entries:    list[ManualEntry]
    session_id: Optional[str] = None  # if provided, patch that session's reverse map too

class HttpItem(BaseModel):
    request:  str
    response: Optional[str] = None

class IngestRequest(BaseModel):
    items:    list[HttpItem]
    skip_llm: bool = False   # True = regex-only, fast; False = full pipeline (default)

# ── Rules export definition ────────────────────────────────────────────────────
# Serialisable representation of CONTEXT_PATTERNS for the Burp plugin.
# Update this whenever CONTEXT_PATTERNS changes.

_RULES_PATTERNS: dict[str, list[str]] = {
    "json_fields": [
        # OAuth / session tokens
        "accessToken", "access_token",
        "refreshToken", "refresh_token", "curityRefresh",
        "idToken", "id_token",
        "token", "sessionToken", "session_token",
        "authToken", "auth_token", "bearerToken", "bearer_token",
        "userToken", "user_token", "deviceToken", "device_token",
        # Credentials & secrets
        "password", "passwd", "pass",
        "secret", "client_secret", "clientSecret",
        "api_key", "apiKey", "apikey",
        "credential", "credentials",
        "privateKey", "private_key", "signing_key", "signingKey",
        # CSRF / anti-forgery
        "csrfToken", "csrf_token", "_csrf",
        "xsrfToken", "xsrf_token",
        "antiForgery", "anti_forgery_token",
        # OAuth flow
        "code", "auth_code", "authCode", "authorization_code", "nonce",
        # MFA / OTP
        "otp", "one_time_password", "oneTimePassword",
        "pin", "mfaCode", "mfa_code", "totpCode", "totp_code",
        # PCI / financial
        "cardNumber", "card_number", "pan", "cvv", "cvc", "cvv2",
        "expiryDate", "expiry_date", "cardHolder", "card_holder",
        "accountNumber", "account_number",
        "routingNumber", "routing_number",
        "sortCode", "sort_code", "bban", "iban",
    ],
    "sensitive_headers": [
        "Authorization", "Proxy-Authorization",
        "X-Api-Key", "X-Auth-Token",
        "X-Session-Token", "X-Session-Id",
        "X-Access-Token", "X-Refresh-Token",
        "X-Device-Token", "X-Device-Id", "X-Device-Key",
        "X-User-Token", "X-Client-Token",
        "X-CSRF-Token", "X-XSRF-Token",
        "X-Forwarded-For", "X-Real-IP",
        "CF-Connecting-IP", "True-Client-IP",
        "X-Client-IP", "X-Originating-IP",
    ],
    "cookie_names": [
        "session", "sessionid", "token", "auth", "jwt",
        "access_token", "refresh_token",
        "sid", "ssid", "userid", "user_id",
    ],
    "url_params": [
        "password", "passwd", "pass",
        "token", "access_token", "refresh_token", "id_token",
        "api_key", "apikey", "secret", "client_secret",
        "code", "auth_code", "authorization_code",
    ],
}

# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.get("/")
async def index():
    with open("index.html", encoding="utf-8") as f:
        return HTMLResponse(f.read())

@app.get("/health")
async def health():
    return {"status": "ok", "active_sessions": len(sessions)}

@app.post("/anonymise")
async def anonymise(req: AnonymiseRequest):
    session_id = req.session_id or str(uuid.uuid4())

    # Step 1 – regex PII extraction (IPs, DNIs, JWTs, UUIDs…)
    tokenised, token_to_fake, real_to_fake_regex = apply_regex_anonymisation(req.text)

    # Step 2 – apply global persistent map (known originals → established fakes, no LLM needed)
    pre_llm, applied_from_global = _apply_global_map(tokenised)

    # Step 3 – LLM for anything still unrecognised
    llm_text, name_mappings = await call_llm_for_names(
        pre_llm, initial_known_fakes=set(applied_from_global.values())
    )

    # Step 4 – persist new LLM discoveries into the global map
    new_entries = {orig: fake for fake, orig in name_mappings.items() if orig not in _global_map}
    if new_entries:
        async with _global_map_lock:
            _global_map.update(new_entries)
            _save_global_map()
        print(f"[blurred] Global map updated: +{len(new_entries)} entries (total {len(_global_map)})")

    # Step 5 – replace __BLUR_N__ tokens with their fake values
    final_text = llm_text
    for token, fake_val in token_to_fake.items():
        final_text = final_text.replace(token, fake_val)

    # Step 6 – build reverse map (fake→original) for deblur
    reverse: dict[str, str] = {fake: orig for orig, fake in real_to_fake_regex.items()}
    reverse.update(name_mappings)
    reverse.update({fake: orig for orig, fake in applied_from_global.items()})
    sessions[session_id] = reverse

    # Display map (original→fake) for the UI table
    display_mapping: dict[str, str] = {orig: fake for orig, fake in real_to_fake_regex.items()}
    display_mapping.update({v: k for k, v in name_mappings.items()})
    display_mapping.update(applied_from_global)

    return {
        "session_id":      session_id,
        "anonymised_text": final_text,
        "mapping":         display_mapping,
    }


@app.post("/deblur")
async def deblur(req: DeblurRequest):
    if req.session_id not in sessions:
        raise HTTPException(
            status_code=404,
            detail=f"Sesión '{req.session_id}' no encontrada. ¿Has anonimizado antes?",
        )

    reverse = sessions[req.session_id]
    text    = req.text

    # Sort longest-first to avoid partial-match bugs (e.g. "John" inside "John Smith")
    for fake_val, original_val in sorted(reverse.items(), key=lambda x: -len(x[0])):
        text = text.replace(fake_val, original_val)

    return {"original_text": text}


@app.post("/global-map/entries")
async def add_global_map_entries(req: AddEntriesRequest):
    """
    Manually add entries to the persistent substitution map.
    If session_id is provided, also patches that session's reverse map so /deblur works.
    Fake value is auto-generated when omitted.
    """
    added: list[dict] = []

    async with _global_map_lock:
        for entry in req.entries:
            original = entry.original.strip()
            if not original:
                continue
            # Honour existing mapping if already known; otherwise use provided or generate
            if original in _global_map:
                fake = _global_map[original]
            else:
                fake = entry.fake.strip() if entry.fake and entry.fake.strip() else _gen_opaque_token()
                _global_map[original] = fake

            added.append({"original": original, "fake": fake, "manual": True})

            # Patch session reverse map so /deblur can resolve the fake back to original
            if req.session_id and req.session_id in sessions:
                sessions[req.session_id][fake] = original

        if added:
            _save_global_map()

    return {"added": added}


@app.post("/ingest")
async def ingest(req: IngestRequest):
    """
    Ingest HTTP request/response items (e.g. from Burp history) to build anonymisation rules.
    Runs the full pipeline (regex + optional LLM) on each item and accumulates all
    discovered mappings into the persistent global map.

    Returns a summary — the anonymised text itself is intentionally discarded since
    the goal here is rule-building, not producing output for immediate use.
    """
    items_processed = 0
    total_new       = 0

    for item in req.items:
        # Combine request and response into one block for joint analysis
        text = item.request
        if item.response:
            text += "\n\n--- RESPONSE ---\n\n" + item.response

        # Step 1 – regex
        tokenised, _token_to_fake, real_to_fake_regex = apply_regex_anonymisation(text)

        # Step 2 – apply global map (skip already-known values)
        pre_llm, applied_from_global = _apply_global_map(tokenised)

        # Step 3 – LLM (full mode only)
        if req.skip_llm:
            name_mappings: dict[str, str] = {}
        else:
            _llm_text, name_mappings = await call_llm_for_names(
                pre_llm, initial_known_fakes=set(applied_from_global.values())
            )

        # Step 4 – collect new entries: regex findings + LLM findings not yet in global map
        new_entries: dict[str, str] = {}
        for orig, fake in real_to_fake_regex.items():
            if orig not in _global_map:
                new_entries[orig] = fake
        for fake, orig in name_mappings.items():
            if orig not in _global_map and orig not in new_entries:
                new_entries[orig] = fake

        if new_entries:
            async with _global_map_lock:
                _global_map.update(new_entries)
                _save_global_map()
            total_new += len(new_entries)
            print(f"[blurred] ingest item +{len(new_entries)} entries (total {len(_global_map)})")

        items_processed += 1

    return {
        "items_processed": items_processed,
        "new_entries":     total_new,
        "total_entries":   len(_global_map),
    }


@app.get("/rules")
async def get_rules():
    """
    Export the complete ruleset for the Burp plugin (or any offline consumer).

    Contains:
      - value_map:        known original→fake substitutions (from the global map)
      - context_patterns: field/header/cookie/param names that are always sensitive,
                          regardless of their value format
      - meta:             entry count and generation timestamp
    """
    from datetime import datetime, timezone
    return {
        "meta": {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "value_map_entries": len(_global_map),
        },
        "value_map":        _global_map,
        "context_patterns": _RULES_PATTERNS,
    }


@app.get("/global-map")
async def get_global_map():
    """Return the full persistent substitution dictionary (original → fake)."""
    return {"entries": len(_global_map), "map": _global_map}


@app.delete("/global-map")
async def clear_global_map():
    """Wipe the persistent dictionary (use to start a fresh exercise)."""
    async with _global_map_lock:
        _global_map.clear()
        _save_global_map()
    return {"status": "cleared"}


@app.get("/sessions/{session_id}")
async def get_session_info(session_id: str):
    if session_id not in sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    reverse = sessions[session_id]
    return {
        "session_id": session_id,
        "entries":    len(reverse),
        "mapping":    {v: k for k, v in reverse.items()},   # original→fake
    }
