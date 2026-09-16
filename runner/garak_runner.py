"""
VIPER — Garak Runner
Executa probes do garak contra o agente alvo via RestGenerator.
Converte resultados para o formato padrão VIPER.
"""

import json
import time
import uuid


def executar_garak(config_dict: dict) -> list:
    """
    Executa bateria de probes do garak contra o agente alvo.
    Retorna lista de resultados no formato VIPER.
    """
    try:
        import garak.cli
        import garak._config as _config
        from garak.generators.rest import RestGenerator
        from garak.harnesses.probewise import ProbewiseHarness
        import garak.probes
    except ImportError:
        print("[GARAK] garak não instalado — pulando camada 1")
        return []

    url = config_dict["url"]
    json_input = config_dict.get("json_input", "")
    nome = config_dict.get("nome", "Agente")

    # Descobre o campo de entrada a partir do JSON de input de exemplo
    campo_mensagem = _extrair_campo_mensagem(json_input)
    campo_resposta = _extrair_campo_resposta(config_dict.get("json_output", ""))

    print(f"\n[GARAK] Iniciando — campo entrada: '{campo_mensagem}' | campo saída: '{campo_resposta}'")

    generator_config = {
        "uri":                    url,
        "method":                 "post",
        "headers":                _montar_headers(config_dict.get("token", "")),
        "req_template_json_object": {campo_mensagem: "$INPUT"},
        "response_json":          True,
        "response_json_field":    campo_resposta,
    }

    resultados = []

    try:
        generator = RestGenerator(**generator_config)

        # Probes relevantes para agentes conversacionais
        probes_alvo = [
            "promptinjection",
            "dan",
            "knownbadsignatures",
            "leakage",
            "malwaregen",
            "misleading",
            "packagehallucination",
            "xss",
        ]

        for probe_nome in probes_alvo:
            try:
                probe_modulo = __import__(
                    f"garak.probes.{probe_nome}",
                    fromlist=[""]
                )
                classes = _obter_classes_probe(probe_modulo)

                for classe in classes:
                    try:
                        probe = classe()
                        inicio = time.time()
                        tentativas = probe.probe(generator)
                        duracao = round(time.time() - inicio, 2)

                        for tentativa in tentativas:
                            resultado = _converter_tentativa(
                                tentativa, probe_nome, classe.__name__,
                                nome, duracao
                            )
                            resultados.append(resultado)

                    except Exception as e:
                        print(f"[GARAK] Erro na probe {classe.__name__}: {e}")
                        continue

            except Exception as e:
                print(f"[GARAK] Erro ao carregar probe {probe_nome}: {e}")
                continue

    except Exception as e:
        print(f"[GARAK] Erro ao inicializar generator: {e}")
        return []

    print(f"[GARAK] Concluído — {len(resultados)} tentativas executadas")
    return resultados


def _extrair_campo_mensagem(json_input: str) -> str:
    """Extrai o primeiro campo do JSON de input como campo de mensagem."""
    try:
        obj = json.loads(json_input)
        if isinstance(obj, dict) and obj:
            return list(obj.keys())[0]
    except (json.JSONDecodeError, TypeError):
        pass
    return "message"


def _extrair_campo_resposta(json_output: str) -> str:
    """Extrai o primeiro campo do JSON de output como campo de resposta."""
    try:
        obj = json.loads(json_output)
        if isinstance(obj, dict) and obj:
            return list(obj.keys())[0]
    except (json.JSONDecodeError, TypeError):
        pass
    return "output"


def _montar_headers(token: str) -> dict:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _obter_classes_probe(modulo) -> list:
    """Retorna as classes de probe de um módulo garak."""
    import inspect
    try:
        from garak.probes.base import Probe
        return [
            cls for _, cls in inspect.getmembers(modulo, inspect.isclass)
            if issubclass(cls, Probe) and cls is not Probe
        ]
    except Exception:
        return []


def _converter_tentativa(tentativa, probe_nome: str, classe_nome: str, alvo: str, duracao: float) -> dict:
    """Converte uma tentativa do garak para o formato VIPER."""
    try:
        payload  = tentativa.prompt if hasattr(tentativa, "prompt") else str(tentativa)
        resposta = tentativa.outputs[0] if hasattr(tentativa, "outputs") and tentativa.outputs else ""
        sucesso  = tentativa.passed is False if hasattr(tentativa, "passed") else False
    except Exception:
        payload  = str(tentativa)
        resposta = ""
        sucesso  = False

    return {
        "id":             f"G-{probe_nome[:3].upper()}-{str(uuid.uuid4())[:4].upper()}",
        "categoria":      "garak",
        "descricao":      f"{probe_nome} · {classe_nome}",
        "payload":        payload,
        "alvo":           alvo,
        "sucesso_ataque": sucesso,
        "detector":       "garak",
        "analise_ia":     None,
        "resposta":       resposta,
        "duracao_s":      duracao,
    }