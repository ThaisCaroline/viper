"""
VIPER — Logger
Salva e consulta histórico de testes no SQLite.
"""

import json
import sqlite3
import os
from datetime import datetime

DB_PATH = os.getenv("VIPER_DB_PATH", "/app/data/viper.db")


def _conectar():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def inicializar_banco():
    """Cria as tabelas se não existirem."""
    conn = _conectar()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS testes (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp   TEXT NOT NULL,
            url_agente  TEXT NOT NULL,
            nome_agente TEXT NOT NULL,
            tecnico     TEXT NOT NULL,
            total       INTEGER NOT NULL,
            vulneraveis INTEGER NOT NULL,
            resistiu    INTEGER NOT NULL,
            score       REAL NOT NULL,
            resultados  TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


def salvar_teste(relatorio: dict, tecnico: str):
    """Salva um teste no banco."""
    conn = _conectar()
    conn.execute("""
        INSERT INTO testes
            (timestamp, url_agente, nome_agente, tecnico, total, vulneraveis, resistiu, score, resultados)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        relatorio.get("timestamp", datetime.now().isoformat()),
        relatorio.get("url_agente", ""),
        relatorio.get("alvo", ""),
        tecnico,
        relatorio.get("total", 0),
        relatorio.get("vulneraveis", 0),
        relatorio.get("resistiu", 0),
        relatorio.get("taxa_ataque", 0.0),
        json.dumps(relatorio.get("resultados", []), ensure_ascii=False)
    ))
    conn.commit()
    conn.close()


def listar_testes() -> list:
    """Retorna todos os testes ordenados por data desc, sem resultados detalhados."""
    conn = _conectar()
    rows = conn.execute("""
        SELECT id, timestamp, url_agente, nome_agente, tecnico, total, vulneraveis, resistiu, score
        FROM testes
        ORDER BY timestamp DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def buscar_teste(teste_id: int) -> dict:
    """Retorna um teste completo com resultados."""
    conn = _conectar()
    row = conn.execute("SELECT * FROM testes WHERE id = ?", (teste_id,)).fetchone()
    conn.close()
    if not row:
        return {}
    d = dict(row)
    d["resultados"] = json.loads(d["resultados"])
    return d


def comparar_testes(id1: int, id2: int) -> dict:
    """
    Compara dois testes do mesmo agente.
    Retorna delta por vetor: melhorou / piorou / igual / novo / removido.
    """
    t1 = buscar_teste(id1)
    t2 = buscar_teste(id2)

    if not t1 or not t2:
        return {"erro": "Teste não encontrado"}

    # Mapeia resultados por descrição
    def mapear(resultados):
        return {r["descricao"]: r for r in resultados}

    r1 = mapear(t1.get("resultados", []))
    r2 = mapear(t2.get("resultados", []))

    todas_descricoes = set(r1.keys()) | set(r2.keys())
    delta = []

    for desc in sorted(todas_descricoes):
        v1 = r1.get(desc)
        v2 = r2.get(desc)

        if v1 and v2:
            if not v1["sucesso_ataque"] and v2["sucesso_ataque"]:
                status = "piorou"
            elif v1["sucesso_ataque"] and not v2["sucesso_ataque"]:
                status = "melhorou"
            else:
                status = "igual"
        elif v1 and not v2:
            status = "removido"
        else:
            status = "novo"

        delta.append({
            "descricao":  desc,
            "status":     status,
            "teste1_vuln": v1["sucesso_ataque"] if v1 else None,
            "teste2_vuln": v2["sucesso_ataque"] if v2 else None,
        })

    return {
        "teste1": {
            "id": t1["id"], "timestamp": t1["timestamp"],
            "tecnico": t1["tecnico"], "score": t1["score"],
            "vulneraveis": t1["vulneraveis"], "total": t1["total"]
        },
        "teste2": {
            "id": t2["id"], "timestamp": t2["timestamp"],
            "tecnico": t2["tecnico"], "score": t2["score"],
            "vulneraveis": t2["vulneraveis"], "total": t2["total"]
        },
        "delta": delta
    }