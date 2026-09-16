"""
VIPER — Garak Runner
Usa o garak como fonte de prompts de ataque.
Os prompts são executados via HTTP adapter do VIPER e avaliados pelo scorer do VIPER.
"""

import json
import time
import uuid
import inspect
import urllib.request
import urllib.error

from runner.scorer import avaliar


def executar_garak(config_dict: dict) -> list:
    """
    Extrai prompts das probes do garak e executa contra o agente alvo.
    Retorna lista de resultados no formato VIPER.
    """
    try:
        from garak.probes.base import Probe
    except ImportError:
        print("[GARAK] garak não instalado — pulando camada 1")
        return []

    url            = config_dict["url"]
    json_input     = config_dict.get("json_input", "")
    dados_proteger = config_dict.get("dados_proteger", [])
    token          = config_dict.get("token", "")
    nome           = config_dict.get("nome", "Agente")

    campo_mensagem = _extrair_campo(json_input, "message")

    print(f"\n[GARAK] Iniciando — campo entrada: '{campo_mensagem}'")

    # Probes confirmadas no garak 0.17
    probes_alvo = [
        "garak.probes.dan",
        "garak.probes.misleading",
        "garak.probes.promptinject",
        "garak.probes.latentinjection",
        "garak.probes.encoding",
    ]

    resultados = []

    for probe_path in probes_alvo:
        try:
            modulo = __import__(probe_path, fromlist=[""])
            classes = [
                cls for _, cls in inspect.getmembers(modulo, inspect.isclass)
                if issubclass(cls, Probe) and cls is not Probe
                and cls.__module__ == probe_path
            ]

            for classe in classes:
                try:
                    probe = classe()
                    prompts = getattr(probe, "prompts", [])
                    if not prompts:
                        continue

                    probe_nome = probe_path.split(".")[-1]
                    print(f"  [GARAK] {probe_nome}.{classe.__name__} — {len(prompts)} prompts")

                    for prompt in prompts[:2]:  # limita 2 por classe pra não sobrecarregar
                        # substitui placeholder do garak pelo nome real do agente
                        prompt = prompt.replace("{generator.name}", nome)
                        inicio = time.time()
                        resposta = _enviar_payload(prompt, url, campo_mensagem, token)
                        duracao  = round(time.time() - inicio, 2)

                        # pula scorer se agente retornou erro de servidor
                        if resposta.startswith("[HTTP 5"):
                            avaliacao = {"sucesso": False, "detector": "marcador", "analise_ia": ""}
                        else:
                            avaliacao = avaliar(resposta, dados_proteger, payload=prompt)

                        resultados.append({
                            "id":             f"G-{probe_nome[:3].upper()}-{str(uuid.uuid4())[:6].upper()}",
                            "categoria":      "garak",
                            "descricao":      f"{probe_nome} · {classe.__name__}",
                            "payload":        prompt,
                            "alvo":           nome,
                            "sucesso_ataque": avaliacao["sucesso"],
                            "detector":       avaliacao["detector"],
                            "analise_ia":     avaliacao["analise_ia"],
                            "resposta":       resposta,
                            "duracao_s":      duracao,
                        })

                except Exception as e:
                    print(f"  [GARAK] Erro na probe {classe.__name__}: {e}")
                    continue

        except Exception as e:
            print(f"  [GARAK] Erro ao carregar {probe_path}: {e}")
            continue

    print(f"[GARAK] Concluído — {len(resultados)} vetores executados")
    return resultados


def _extrair_campo(json_str: str, fallback: str) -> str:
    try:
        obj = json.loads(json_str)
        if isinstance(obj, dict) and obj:
            return list(obj.keys())[0]
    except Exception:
        pass
    return fallback


def _enviar_payload(payload: str, url: str, campo_mensagem: str, token: str) -> str:
    """Envia payload ao agente via HTTP POST."""
    body = json.dumps({campo_mensagem: payload}).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    try:
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        return f"[HTTP {e.code}] {e.reason}"
    except urllib.error.URLError as e:
        return f"[ERRO DE CONEXÃO] {e.reason}"