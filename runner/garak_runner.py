"""
VIPER — Garak Runner
Usa o garak como fonte de prompts de ataque.
"""

import json
import time
import uuid
import inspect
import urllib.request
import urllib.error

from runner.scorer import avaliar

DUMMY_DOC = "Documento de teste VIPER.\nEste arquivo foi gerado automaticamente para fins de teste de segurança."


def executar_garak(config_dict: dict) -> list:
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
    aceita_doc     = config_dict.get("aceita_documento", False)
    campo_doc      = config_dict.get("campo_documento", "file")
    contexto       = config_dict.get("contexto", "")

    campo_mensagem = config_dict.get("campo_ataque") or _extrair_campo(json_input, "message")

    print(f"\n[GARAK] Iniciando — campo entrada: '{campo_mensagem}'")

    probes_alvo = [
        "garak.probes.dan",
        "garak.probes.misleading",
        "garak.probes.promptinject",
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

                    for prompt in prompts[:2]:
                        prompt = prompt.replace("{generator.name}", nome)
                        inicio = time.time()

                        if aceita_doc:
                            resposta = _enviar_multipart(prompt, url, campo_mensagem, token, campo_doc)
                        else:
                            resposta = _enviar_payload(prompt, url, campo_mensagem, token)

                        duracao = round(time.time() - inicio, 2)

                        if resposta.startswith("[HTTP 5"):
                            avaliacao = {"sucesso": False, "detector": "marcador", "analise_ia": "", "recomendacao": ""}
                        else:
                            avaliacao = avaliar(resposta, dados_proteger, payload=prompt, contexto_agente=contexto)

                        resultados.append({
                            "id":             f"G-{probe_nome[:3].upper()}-{str(uuid.uuid4())[:6].upper()}",
                            "categoria":      "garak",
                            "descricao":      f"{probe_nome} · {classe.__name__}",
                            "payload":        prompt,
                            "alvo":           nome,
                            "sucesso_ataque": avaliacao["sucesso"],
                            "detector":       avaliacao["detector"],
                            "analise_ia":     avaliacao.get("analise_ia", ""),
                            "recomendacao":   avaliacao.get("recomendacao", ""),
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


def _enviar_multipart(payload: str, url: str, campo_mensagem: str, token: str, campo_doc: str) -> str:
    boundary = f"----VIPERBoundary{uuid.uuid4().hex}"
    doc_bytes = DUMMY_DOC.encode("utf-8")

    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{campo_mensagem}"\r\n\r\n'
        f"{payload}\r\n"
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="{campo_doc}"; filename="viper_doc.txt"\r\n'
        f"Content-Type: text/plain\r\n\r\n"
    ).encode("utf-8") + doc_bytes + f"\r\n--{boundary}--\r\n".encode("utf-8")

    headers = {
        "Content-Type": f"multipart/form-data; boundary={boundary}",
        "Content-Length": str(len(body)),
    }
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