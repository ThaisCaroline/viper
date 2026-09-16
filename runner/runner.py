"""
Runner: orquestra as três camadas de ataque do VIPER.
  Camada 1 — Garak: probes de red team via RestGenerator
  Camada 2 — IA Contextual: ataques gerados com base no contexto do agente
  Camada 3 — Documento: injeção indireta via documento envenenado (opcional)
"""

from runner.garak_runner import executar_garak
from runner.ai_attacker import executar_ataques_contextuais
from runner.doc_injector import executar_injecao_documento


def executar_bateria(config_dict: dict) -> list:
    """
    Executa as três camadas de ataque contra o agente alvo.
    Retorna lista consolidada de resultados no formato VIPER.
    """
    nome               = config_dict.get("nome", "Agente")
    usar_ia_contextual = config_dict.get("usar_ia_contextual", True)
    aceita_documento   = config_dict.get("aceita_documento", False)

    print(f"\n🐍 VIPER iniciando")
    print(f"   Alvo: {nome}")
    print(f"   IA contextual: {'sim' if usar_ia_contextual else 'não'}")
    print(f"   Documento: {'sim' if aceita_documento else 'não'}\n")

    resultados = []

    # Camada 1 — Garak
    print("── Camada 1: Garak ──────────────────────────")
    resultados_garak = executar_garak(config_dict)
    resultados.extend(resultados_garak)
    print(f"   {len(resultados_garak)} resultados\n")

    # Camada 2 — IA Contextual (opcional)
    if usar_ia_contextual:
        print("── Camada 2: IA Contextual ──────────────────")
        resultados_ia = executar_ataques_contextuais(config_dict)
        resultados.extend(resultados_ia)
        print(f"   {len(resultados_ia)} resultados\n")
    else:
        print("── Camada 2: IA Contextual — desativada ─────\n")

    # Camada 3 — Documento (opcional)
    if aceita_documento:
        print("── Camada 3: Injeção Indireta ───────────────")
        resultados_doc = executar_injecao_documento(config_dict)
        resultados.extend(resultados_doc)
        print(f"   {len(resultados_doc)} resultados\n")

    total_vuln = sum(1 for r in resultados if r["sucesso_ataque"])
    print(f"🐍 Concluído — {len(resultados)} vetores | {total_vuln} vulneráveis\n")

    return resultados