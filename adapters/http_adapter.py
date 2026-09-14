"""
Adaptador HTTP — envia vetores para qualquer agente via URL.
Nunca conecta em ambiente de produção.
"""

import os
import re
import json
import yaml
import urllib.request
import urllib.error

AMBIENTES_BLOQUEADOS = ["prd", "prod", "production", "producao", "produção"]


def carregar_config(config_path: str) -> dict:
    with open(config_path, "r", encoding="utf-8") as f:
        config = yaml.safe_load(f)

    ambiente = config.get("alvo", {}).get("ambiente", "").lower()
    if ambiente in AMBIENTES_BLOQUEADOS:
        raise ValueError(
            f"[BLOQUEADO] Ambiente '{ambiente}' é produtivo. "
            "VIPER só roda em laboratório."
        )
    return config


def _resolver_env_vars(texto: str) -> str:
    def substituir(match):
        var = match.group(1)
        valor = os.getenv(var)
        if not valor:
            raise ValueError(f"Variável de ambiente não definida: {var}")
        return valor
    return re.sub(r'\$\{(\w+)\}', substituir, texto)


def enviar_payload(payload: str, config: dict) -> str:
    request_cfg = config.get("request", {})
    response_cfg = config.get("response", {})
    url = config["alvo"]["url"]

    campo_mensagem = request_cfg.get("campo_mensagem", "message")
    body = json.dumps({campo_mensagem: payload}).encode("utf-8")

    headers = {"Content-Type": request_cfg.get("content_type", "application/json")}
    for chave, valor in request_cfg.get("headers", {}).items():
        headers[chave] = _resolver_env_vars(str(valor))

    req = urllib.request.Request(url, data=body, headers=headers, method="POST")

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resposta_raw = resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return f"[HTTP {e.code}] {e.reason}"
    except urllib.error.URLError as e:
        return f"[ERRO DE CONEXÃO] {e.reason}"

    try:
        resposta_json = json.loads(resposta_raw)
        campo_resposta = response_cfg.get("campo_resposta", "output")
        for parte in campo_resposta.split("."):
            resposta_json = resposta_json[parte]
        return str(resposta_json)
    except (json.JSONDecodeError, KeyError):
        return resposta_raw