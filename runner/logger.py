"""
VIPER — Logger
Salva e consulta histórico de testes no SQLite.
"""

import json
import os
import sqlite3
from datetime import datetime, timedelta

DB_PATH = os.getenv("VIPER_DB_PATH", "/app/data/viper.db")


def _conectar():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def inicializar_banco():
    """Cria as tabelas se não existirem e aplica migrações."""
    conn = _conectar()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS testes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp       TEXT NOT NULL,
            url_agente      TEXT NOT NULL,
            nome_agente     TEXT NOT NULL,
            tecnico         TEXT NOT NULL,
            email_tecnico   TEXT NOT NULL DEFAULT '',
            total           INTEGER NOT NULL,
            vulneraveis     INTEGER NOT NULL,
            resistiu        INTEGER NOT NULL,
            score           REAL NOT NULL,
            resultados      TEXT NOT NULL,
            html_path       TEXT DEFAULT ''
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS audit_log (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            deletado_em     TEXT NOT NULL,
            deletado_por    TEXT NOT NULL DEFAULT '',
            teste_id        INTEGER NOT NULL,
            timestamp       TEXT NOT NULL,
            url_agente      TEXT NOT NULL,
            nome_agente     TEXT NOT NULL,
            tecnico         TEXT NOT NULL,
            email_tecnico   TEXT NOT NULL DEFAULT '',
            total           INTEGER NOT NULL,
            vulneraveis     INTEGER NOT NULL,
            resistiu        INTEGER NOT NULL,
            score           REAL NOT NULL,
            resultados      TEXT NOT NULL,
            html_path       TEXT DEFAULT '',
            json_path       TEXT DEFAULT ''
        )
    """)

    # Migrações
    colunas = [r[1] for r in conn.execute("PRAGMA table_info(testes)").fetchall()]
    if "email_tecnico" not in colunas:
        conn.execute("ALTER TABLE testes ADD COLUMN email_tecnico TEXT NOT NULL DEFAULT ''")

    audit_colunas = [r[1] for r in conn.execute("PRAGMA table_info(audit_log)").fetchall()]
    if "json_path" not in audit_colunas:
        conn.execute("ALTER TABLE audit_log ADD COLUMN json_path TEXT DEFAULT ''")
    if "deletado_por" not in audit_colunas:
        conn.execute("ALTER TABLE audit_log ADD COLUMN deletado_por TEXT NOT NULL DEFAULT ''")

    conn.commit()
    conn.close()

    _limpar_audit_log_antigo()


def _limpar_audit_log_antigo():
    """Remove registros do audit_log com mais de 2 anos (e seus JSONs do disco)."""
    limite = (datetime.now() - timedelta(days=730)).isoformat()
    conn = _conectar()
    rows = conn.execute(
        "SELECT json_path FROM audit_log WHERE deletado_em < ?", (limite,)
    ).fetchall()
    for row in rows:
        jp = row["json_path"]
        if jp:
            try:
                if os.path.exists(jp):
                    os.remove(jp)
            except Exception:
                pass
    removidos = conn.execute(
        "DELETE FROM audit_log WHERE deletado_em < ?", (limite,)
    ).rowcount
    conn.commit()
    conn.close()
    if removidos:
        print(f"[AUDIT] {removidos} registro(s) expirado(s) removido(s) do audit_log (>2 anos)")


def listar_audit_log() -> list:
    """Retorna registros deletados do audit_log, ordenados por data de deleção desc."""
    conn = _conectar()
    rows = conn.execute("""
        SELECT id, deletado_em, deletado_por, teste_id, timestamp, nome_agente, url_agente,
               tecnico, email_tecnico, total, vulneraveis, resistiu, score, json_path
        FROM audit_log
        ORDER BY deletado_em DESC
    """).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def salvar_teste(relatorio: dict, tecnico: str, email_tecnico: str = ""):
    """Salva um teste no banco."""
    conn = _conectar()
    conn.execute("""
        INSERT INTO testes
            (timestamp, url_agente, nome_agente, tecnico, email_tecnico, total, vulneraveis, resistiu, score, resultados, html_path)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        relatorio.get("timestamp", datetime.now().isoformat()),
        relatorio.get("url_agente", ""),
        relatorio.get("alvo", ""),
        tecnico,
        email_tecnico,
        relatorio.get("total", 0),
        relatorio.get("vulneraveis", 0),
        relatorio.get("resistiu", 0),
        relatorio.get("taxa_ataque", 0.0),
        json.dumps(relatorio.get("resultados", []), ensure_ascii=False),
        relatorio.get("html_path", "")
    ))
    conn.commit()
    conn.close()


def listar_testes(email_tecnico: str = None) -> list:
    """Retorna testes ordenados por data desc. Se email informado, filtra só os desse técnico."""
    conn = _conectar()
    if email_tecnico:
        rows = conn.execute("""
            SELECT id, timestamp, url_agente, nome_agente, tecnico, email_tecnico, total, vulneraveis, resistiu, score
            FROM testes
            WHERE email_tecnico = ?
            ORDER BY timestamp DESC
        """, (email_tecnico,)).fetchall()
    else:
        rows = conn.execute("""
            SELECT id, timestamp, url_agente, nome_agente, tecnico, email_tecnico, total, vulneraveis, resistiu, score
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


def deletar_teste(teste_id: int, deletado_por: str = ""):
    """
    Copia o teste para audit_log antes de deletar (retenção 2 anos).
    Remove o HTML do disco mas mantém o JSON para auditoria.
    """
    conn = _conectar()
    row = conn.execute("SELECT * FROM testes WHERE id = ?", (teste_id,)).fetchone()

    if row:
        html_path = row["html_path"] or ""
        json_path = html_path.replace(".html", ".json") if html_path else ""

        conn.execute("""
            INSERT INTO audit_log
                (deletado_em, deletado_por, teste_id, timestamp, url_agente, nome_agente, tecnico,
                 email_tecnico, total, vulneraveis, resistiu, score, resultados, html_path, json_path)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().isoformat(),
            deletado_por,
            row["id"],
            row["timestamp"],
            row["url_agente"],
            row["nome_agente"],
            row["tecnico"],
            row["email_tecnico"],
            row["total"],
            row["vulneraveis"],
            row["resistiu"],
            row["score"],
            row["resultados"],
            html_path,
            json_path if os.path.exists(json_path) else "",
        ))

        # Remove apenas o HTML do disco
        if html_path:
            try:
                if os.path.exists(html_path):
                    os.remove(html_path)
            except Exception:
                pass

    conn.execute("DELETE FROM testes WHERE id = ?", (teste_id,))
    conn.commit()
    conn.close()


def buscar_audit_json_path(audit_id: int) -> str:
    """Retorna o json_path de um registro do audit_log."""
    conn = _conectar()
    row = conn.execute("SELECT json_path FROM audit_log WHERE id = ?", (audit_id,)).fetchone()
    conn.close()
    return row["json_path"] if row and row["json_path"] else ""


def comparar_testes(id1: int, id2: int) -> dict:
    """Compara dois testes do mesmo agente. Retorna delta por vetor."""
    t1 = buscar_teste(id1)
    t2 = buscar_teste(id2)

    if not t1 or not t2:
        return {"erro": "Teste não encontrado"}

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
            "descricao":   desc,
            "status":      status,
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