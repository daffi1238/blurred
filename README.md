# Blurred

Anonimizador de tráfico HTTP para uso seguro con LLMs en la nube.

Sustituye información sensible (tokens, credenciales, cookies, IPs, datos personales…) antes de enviar tráfico a Claude, ChatGPT u otros modelos externos. La respuesta se puede desanonimizar localmente para recuperar los valores reales.

```
Texto original  →  [regex + LLM local]  →  Texto anonimizado  →  LLM externo
                                                                        ↓
Texto original  ←  [reverse map local]  ←  Respuesta anonimizada  ←──┘
```

---

## Requisitos

- Docker + Docker Compose
- **[DocxQA](../DocxQA)** levantado previamente (proporciona el llama-server con qwen-coder)

> Si no usas DocxQA, consulta la sección [Red standalone](#red-standalone).

---

## Despliegue rápido

```bash
# 1. Clona el repositorio
git clone git@github.com:daffi1238/blurred.git
cd blurred

# 2. Crea el directorio de datos persistentes
mkdir -p data

# 3. Asegúrate de que DocxQA está corriendo (proporciona la red y el LLM)
cd ../DocxQA && docker compose up -d && cd -

# 4. Levanta blurred
docker compose up -d

# 5. Comprueba que está OK
curl http://localhost:8100/health
# {"status":"ok","active_sessions":0}
```

La interfaz web estará disponible en **http://localhost:8100**.

---

## Variables de entorno

Configurables en `docker-compose.yaml` o mediante un archivo `.env`:

| Variable | Default | Descripción |
|---|---|---|
| `LLM_BASE_URL` | `http://llama-server:8080/v1` | URL del servidor llama.cpp (OpenAI-compatible) |
| `LLM_API_KEY` | `llm-local-key-changeme-abc123` | API key del LLM local |
| `LLM_MODEL` | `qwen-coder` | Nombre del modelo a usar |
| `LLM_TIMEOUT` | `120` | Timeout en segundos por llamada al LLM |
| `BLUR_CHUNK_SIZE` | `3000` | Caracteres máximos por chunk enviado al LLM |
| `GLOBAL_MAP_PATH` | `/app/data/global_map.json` | Ruta del diccionario persistente |

---

## Acceso

| URL | Descripción |
|---|---|
| `http://localhost:8100` | Interfaz web directa |
| `https://localhost:8443` | HTTPS con certificado auto-generado (Caddy) |
| `http://localhost:8180` | HTTP sin TLS vía Caddy (red LAN) |

Para acceso con dominio propio edita `Caddyfile` y sustituye `blur.midominio.com` por tu dominio real.

---

## API REST

### `POST /anonymise`
Anonimiza un texto. Devuelve el texto anonimizado y un `session_id` para poder desanonimizar después.

```bash
curl -X POST http://localhost:8100/anonymise \
  -H "Content-Type: application/json" \
  -d '{"text": "Authorization: Bearer eyJhbGc...\\npassword=supersecret"}'
```
```json
{
  "session_id": "uuid",
  "anonymised_text": "Authorization: Bearer _FAKE_...\npassword=_FAKE_...",
  "mapping": {"eyJhbGc...": "_FAKE_...", "supersecret": "_FAKE_..."}
}
```

---

### `POST /deblur`
Restaura los valores originales en la respuesta recibida del LLM externo.

```bash
curl -X POST http://localhost:8100/deblur \
  -H "Content-Type: application/json" \
  -d '{"text": "El token _FAKE_... ha expirado", "session_id": "uuid"}'
```
```json
{"original_text": "El token eyJhbGc... ha expirado"}
```

---

### `POST /ingest`
Ingesta items de histórico de Burp Suite para construir el mapa de reglas.
Acepta pares request/response y acumula las sustituciones en el diccionario global.

```bash
curl -X POST http://localhost:8100/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "items": [
      {
        "request":  "POST /api/login HTTP/2\nAuthorization: Bearer eyJ...\n\n{\"password\":\"secret\"}",
        "response": "HTTP/2 200\nSet-Cookie: session=ABC123; HttpOnly\n\n{\"accessToken\":\"tok_...\"}"
      }
    ],
    "skip_llm": false
  }'
```
```json
{"items_processed": 1, "new_entries": 5, "total_entries": 42}
```

`skip_llm: true` salta el LLM local (solo regex). Más rápido pero detecta menos.

---

### `GET /rules`
Exporta el ruleset completo para el plugin de Burp Suite ([blurredBurp](https://github.com/daffi1238/blurredBurp)).

```bash
curl http://localhost:8100/rules -o rules.json
```
```json
{
  "meta": {"generated_at": "2026-03-12T10:00:00Z", "value_map_entries": 42},
  "value_map": {"valor_original": "valor_falso"},
  "context_patterns": {
    "json_fields":       ["accessToken", "password", "cvv", "..."],
    "sensitive_headers": ["Authorization", "X-Api-Key", "..."],
    "cookie_names":      ["session", "token", "..."],
    "url_params":        ["password", "token", "..."]
  }
}
```

---

### `POST /global-map/entries`
Añade entradas manuales al diccionario. Útil durante la auditoría para valores que el pipeline automático no detectó.

```bash
curl -X POST http://localhost:8100/global-map/entries \
  -H "Content-Type: application/json" \
  -d '{
    "entries": [
      {"original": "MiEmpresaS.L."},
      {"original": "john.doe@empresa.com", "fake": "test@example.com"}
    ],
    "session_id": "uuid-opcional"
  }'
```

Si `fake` se omite, se genera automáticamente. Si `session_id` se proporciona, la entrada también queda disponible para `/deblur` en esa sesión.

---

### Otros endpoints

| Método | Endpoint | Descripción |
|---|---|---|
| `GET` | `/health` | Estado del servicio |
| `GET` | `/global-map` | Ver el diccionario persistente completo |
| `DELETE` | `/global-map` | Borrar el diccionario (para empezar desde cero) |
| `GET` | `/sessions/{id}` | Inspeccionar el mapa de una sesión activa |

---

## Cómo funciona la anonimización

El pipeline tiene dos fases:

**Fase 1 — Regex (local, instantáneo)**

Se aplican en orden:
1. `CONTEXT_PATTERNS`: detecta por **nombre de campo** — `"accessToken":"<valor>"`, `Authorization: Bearer <valor>`, `Set-Cookie: name=<valor>`. El valor se sustituye independientemente de su formato.
2. `PATTERNS`: detecta por **estructura del valor** — JWTs (`eyJ...`), UUIDs, IPs, emails, DNIs, IBANs, MACs, hashes, teléfonos ES, dominios.

**Fase 2 — LLM local (qwen-coder)**

Recibe el texto ya tokenizado (`__BLUR_N__`) y detecta lo que la regex no puede: nombres propios, empresas, usuarios, ubicaciones. Devuelve sustituciones realistas.

El mapa inverso `{fake → original}` se guarda en sesión para el deblur.

---

## Red standalone

Si no tienes DocxQA, sustituye la sección `networks` del `docker-compose.yaml`:

```yaml
# Comenta esto:
# networks:
#   llm-net:
#     external: true
#     name: docxqa_llm-net

# Y añade esto:
networks:
  llm-net:
    driver: bridge
```

Y configura `LLM_BASE_URL` para que apunte a tu propio servidor llama.cpp u otro endpoint OpenAI-compatible.

---

## Datos persistentes

El diccionario global se guarda en `./data/global_map.json`. Este archivo **no debe commitearse** (está en `.gitignore`) ya que puede contener valores sensibles reales como claves de mapeo.

Para hacer backup:
```bash
cp data/global_map.json data/global_map.backup.json
```

Para resetear:
```bash
curl -X DELETE http://localhost:8100/global-map
```

---

## Proyecto relacionado

**[blurredBurp](https://github.com/daffi1238/blurredBurp)** — Plugin de Burp Suite que consume blurred para anonimizar tráfico antes de enviarlo a burp-ai-agent u otros agentes IA.
