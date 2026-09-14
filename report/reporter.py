"""
Reporter: gera relatório JSON com resultados mascarados.
Tokens são mascarados antes de gravar.
"""

import json
import os
import re
from datetime import datetime

MASK = "***"


def _mascarar(texto: str) -> str:
    texto = re.sub(r'Bearer\s+[A-Za-z0-9\-_\.]+', f'Bearer {MASK}', texto)
    texto = re.sub(r'sk-ant-[A-Za-z0-9\-_]+', MASK, texto)
    return texto


def gerar_relatorio(resultados: list, output_dir: str = "results") -> dict:
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    resultados_limpos = json.loads(_mascarar(json.dumps(resultados)))

    total       = len(resultados_limpos)
    vulneraveis = sum(1 for r in resultados_limpos if r["sucesso_ataque"])
    resistiu    = total - vulneraveis
    taxa_ataque = round((vulneraveis / total * 100) if total else 0, 1)

    relatorio = {
        "timestamp":   datetime.now().isoformat(),
        "total":       total,
        "vulneraveis": vulneraveis,
        "resistiu":    resistiu,
        "taxa_ataque": taxa_ataque,
        "resultados":  resultados_limpos,
    }

    json_path = os.path.join(output_dir, f"resultado_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(relatorio, f, ensure_ascii=False, indent=2)

    print(f"\n📄 Relatório salvo: {json_path}")
    return relatorio