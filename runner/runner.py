"""
Runner: carrega os vetores e executa cada um contra o alvo via HTTP.
"""

import os
import time
import yaml
from adapters.http_adapter import carregar_config, enviar_payload
from runner.scorer import avaliar

VECTORS_PATH = os.path.join(os.path.dirname(__file__), "..", "attacks", "vectors.yaml")


def carregar_vetores(categorias: list = None) -> list:
    with open(VECTORS_PATH, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    vetores = data["vetores"]
    if categorias:
        vetores = [v for v in vetores if v["categoria"] in categorias]
    return vetores


def executar_bateria(config_path: str, categorias: list = None) -> list:
    """
    Executa todos os vetores contra o alvo configurado.
    Retorna lista de resultados.
    """
    config = carregar_config(config_path)
    marcadores = config.get("marcadores", [])
    nome_alvo = config["alvo"]["nome"]
    vetores = carregar_vetores(categorias)

    print(f"\n🐍 VIPER iniciando")
    print(f"   Alvo: {nome_alvo}")
    print(f"   Vetores: {len(vetores)}")
    print(f"   Marcadores: {len(marcadores)}\n")

    resultados = []

    for vetor in vetores:
        inicio = time.time()
        resposta = enviar_payload(vetor["payload"], config)
        duracao = round(time.time() - inicio, 2)

        sucesso_ataque = avaliar(resposta, marcadores)

        resultado = {
            "id":             vetor["id"],
            "categoria":      vetor["categoria"],
            "descricao":      vetor["descricao"],
            "payload":        vetor["payload"],
            "alvo":           nome_alvo,
            "sucesso_ataque": sucesso_ataque,
            "resposta":       resposta,
            "duracao_s":      duracao,
        }

        resultados.append(resultado)

        status = "🔴 VULNERÁVEL" if sucesso_ataque else "🟢 RESISTIU"
        print(f"  [{vetor['id']}] {status} — {vetor['descricao']}")

    return resultados