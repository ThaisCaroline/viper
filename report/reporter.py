"""
Reporter: gera relatório JSON e HTML com resultados mascarados.
Tokens são mascarados antes de gravar.
Formato compacto: detalhe expandível só pra vulneráveis, seção de recomendações ao final.
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


def _truncar(texto: str, limite: int = 200) -> str:
    texto = str(texto or "")
    return texto[:limite] + "..." if len(texto) > limite else texto


def _gerar_html(relatorio: dict) -> str:
    ts   = relatorio["timestamp"][:19].replace("T", " ")
    taxa = relatorio["taxa_ataque"]
    vuln = relatorio["vulneraveis"]
    safe = relatorio["resistiu"]
    total = relatorio["total"]
    taxa_cor = "#e24b4a" if taxa > 0 else "#4a9e4a"
    vuln_cor = "#e24b4a" if vuln > 0 else "#4a9e4a"

    linhas = ""
    recomendacoes_html = ""

    for r in relatorio["resultados"]:
        is_vuln    = r["sucesso_ataque"]
        status_cls = "vuln" if is_vuln else "safe"
        badge_txt  = "VULNERÁVEL" if is_vuln else "RESISTIU"
        badge_cls  = "badge-v" if is_vuln else "badge-s"
        detector   = r.get("detector", "marcador")
        analise_ia = r.get("analise_ia", "")
        recomendacao = r.get("recomendacao", "")

        detector_badge = f'<span class="detector-badge det-{detector}">{detector.upper()}</span>'

        if is_vuln:
            payload  = _truncar(r.get("payload",  "—"), 200).replace("<", "&lt;").replace(">", "&gt;")
            resposta = _truncar(r.get("resposta", "—"), 300).replace("<", "&lt;").replace(">", "&gt;")

            analise_html = ""
            if analise_ia:
                analise_html = f'<div class="detail-label" style="margin-top:0.75rem">ANÁLISE</div><div class="detail-txt analise">{analise_ia}</div>'

            linhas += f"""
        <tr class="vuln" onclick="toggle(this)">
          <td class="rid">{r['id']}</td>
          <td><span class="badge badge-v">VULNERÁVEL ▾</span></td>
          <td>{r['descricao']}</td>
          <td>{detector_badge}</td>
          <td class="dur">{r['duracao_s']}s</td>
        </tr>
        <tr class="detail vuln-detail">
          <td colspan="5">
            <div class="detail-box">
              <div class="detail-label">PAYLOAD (resumido)</div>
              <div class="detail-txt">{payload}</div>
              <div class="detail-label" style="margin-top:0.75rem">RESPOSTA DO AGENTE</div>
              <div class="detail-txt">{resposta}</div>
              {analise_html}
            </div>
          </td>
        </tr>"""

            # Seção de recomendações
            if recomendacao:
                recomendacoes_html += f"""
        <div class="rec-item">
          <div class="rec-id">{r['id']} — {r['descricao']}</div>
          <div class="rec-txt">💡 {recomendacao}</div>
        </div>"""

        else:
            linhas += f"""
        <tr class="safe">
          <td class="rid">{r['id']}</td>
          <td><span class="badge badge-s">RESISTIU</span></td>
          <td>{r['descricao']}</td>
          <td>{detector_badge}</td>
          <td class="dur">{r['duracao_s']}s</td>
        </tr>"""

    if not recomendacoes_html:
        recomendacoes_html = '<div style="color:#666;font-size:0.75rem">Nenhuma vulnerabilidade encontrada — agente passou em todos os testes.</div>'

    return f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VIPER — Relatório</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 100 100'%3E%3Ctext y='0.9em' font-size='90'%3E%F0%9F%90%8D%3C/text%3E%3C/svg%3E">
  <style>
    :root {{ --bg:#0a0a0f; --card:#0d0d18; --border:#1e1e2e; --red:#e24b4a; --green:#4a9e4a; --font:'Segoe UI',Arial,sans-serif; }}
    * {{ box-sizing:border-box; margin:0; padding:0; }}
    body {{ background:var(--bg); color:#fff; font-family:var(--font); padding:2rem; }}

    .header {{ display:flex; align-items:center; justify-content:space-between; margin-bottom:2rem; padding-bottom:1rem; border-bottom:1px solid var(--border); }}
    .logo {{ font-size:1.4rem; font-weight:500; letter-spacing:0.2rem; }}
    .logo span {{ color:var(--red); }}
    .meta {{ font-size:0.72rem; color:#888; text-align:right; }}
    .meta strong {{ color:#ccc; }}

    .stats {{ display:grid; grid-template-columns:repeat(4,1fr); gap:1rem; margin-bottom:2rem; }}
    .stat {{ background:var(--card); border:1px solid var(--border); border-radius:10px; padding:1.25rem; text-align:center; }}
    .stat-val {{ font-size:2.2rem; font-weight:600; line-height:1; }}
    .stat-lbl {{ font-size:0.6rem; color:#888; letter-spacing:0.12rem; margin-top:0.4rem; text-transform:uppercase; }}

    .section-title {{ font-size:0.6rem; letter-spacing:0.15rem; color:#888; text-transform:uppercase; margin-bottom:0.75rem; margin-top:2rem; }}
    table {{ width:100%; border-collapse:collapse; }}
    tr.vuln {{ border-left:3px solid var(--red); cursor:pointer; }}
    tr.safe {{ border-left:3px solid var(--green); }}
    tr {{ background:var(--card); border-bottom:1px solid var(--border); }}
    tr.vuln:hover {{ background:#111128; }}
    td {{ padding:0.7rem 1rem; font-size:0.78rem; }}
    .rid {{ color:#aaa; width:3rem; font-weight:500; }}
    .dur {{ color:#666; text-align:right; white-space:nowrap; }}
    .badge {{ font-size:0.6rem; padding:0.2rem 0.5rem; border-radius:3px; white-space:nowrap; }}
    .badge-v {{ background:#1a0505; color:var(--red);   border:1px solid #3a0a0a; }}
    .badge-s {{ background:#051a05; color:var(--green); border:1px solid #0a3a0a; }}
    .detector-badge {{ font-size:0.58rem; padding:0.15rem 0.45rem; border-radius:3px; white-space:nowrap; }}
    .det-marcador {{ background:#0a0a1a; color:#4a6ae2; border:1px solid #1a1a3a; }}
    .det-ia       {{ background:#1a0a1a; color:#c44ae2; border:1px solid #3a1a3a; }}
    .det-garak    {{ background:#0a1a0a; color:#4ae24a; border:1px solid #1a3a1a; }}

    .detail {{ display:none; }}
    .detail.open {{ display:table-row; }}
    .vuln-detail td {{ background:#0f0808; }}
    .detail-box {{ padding:0.75rem 1rem; }}
    .detail-label {{ font-size:0.58rem; letter-spacing:0.12rem; color:#666; text-transform:uppercase; margin-bottom:0.35rem; }}
    .detail-txt {{ font-size:0.75rem; color:#ccc; white-space:pre-wrap; line-height:1.5; }}
    .detail-txt.analise {{ color:#c44ae2; font-style:italic; }}

    .rec-item {{ background:var(--card); border:1px solid var(--border); border-left:3px solid var(--red); border-radius:6px; padding:0.85rem 1rem; margin-bottom:0.5rem; }}
    .rec-id {{ font-size:0.65rem; color:#aaa; margin-bottom:0.35rem; }}
    .rec-txt {{ font-size:0.78rem; color:#fff; line-height:1.5; }}

    .footer {{ margin-top:2rem; font-size:0.65rem; color:#444; text-align:center; padding-top:1rem; border-top:1px solid var(--border); }}

    @media print {{
      body {{ background:#fff; color:#000; padding:1rem; }}
      .stat {{ background:#f5f5f5; border-color:#ddd; }}
      tr {{ background:#fff; }}
      .vuln-detail td {{ background:#fff5f5; }}
      .detail {{ display:table-row !important; }}
      .rec-item {{ background:#fff5f5; border-color:#ddd; }}
    }}
  </style>
</head>
<body>
  <div class="header">
    <div>
      <div class="logo">🐍 <span>VIPER</span></div>
      <div style="font-size:0.65rem;color:#666;margin-top:0.25rem">vulnerability injection & penetration evaluation for ai resilience</div>
    </div>
    <div class="meta">
      <div><strong>Agente:</strong> {relatorio.get('alvo','—')}</div>
      <div><strong>Data:</strong> {ts}</div>
    </div>
  </div>

  <div class="stats">
    <div class="stat"><div class="stat-val" style="color:{taxa_cor}">{taxa}%</div><div class="stat-lbl">Taxa de Ataque</div></div>
    <div class="stat"><div class="stat-val" style="color:{vuln_cor}">{vuln}</div><div class="stat-lbl">Vulnerável</div></div>
    <div class="stat"><div class="stat-val" style="color:#4a9e4a">{safe}</div><div class="stat-lbl">Resistiu</div></div>
    <div class="stat"><div class="stat-val" style="color:#d8d7d7">{total}</div><div class="stat-lbl">Total</div></div>
  </div>

  <div class="section-title">Resultados — clique nos vulneráveis para expandir</div>
  <table>{linhas}</table>

  <div class="section-title">Recomendações de Defesa</div>
  {recomendacoes_html}

  <div class="footer">VIPER · Relatório gerado em {ts} · Ambiente isolado de laboratório</div>

  <script>
    function toggle(row) {{
      const detail = row.nextElementSibling;
      if (detail && detail.classList.contains('detail')) {{
        detail.classList.toggle('open');
      }}
    }}
  </script>
</body>
</html>"""


def gerar_relatorio(resultados: list, output_dir: str = "results", alvo: str = "") -> dict:
    os.makedirs(output_dir, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    resultados_limpos = json.loads(_mascarar(json.dumps(resultados)))

    total       = len(resultados_limpos)
    vulneraveis = sum(1 for r in resultados_limpos if r["sucesso_ataque"])
    resistiu    = total - vulneraveis
    taxa_ataque = round((vulneraveis / total * 100) if total else 0, 1)

    relatorio = {
        "timestamp":   datetime.now().isoformat(),
        "alvo":        alvo,
        "total":       total,
        "vulneraveis": vulneraveis,
        "resistiu":    resistiu,
        "taxa_ataque": taxa_ataque,
        "resultados":  resultados_limpos,
        "html_path":   html_path,
    }

    json_path = os.path.join(output_dir, f"resultado_{ts}.json")
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(relatorio, f, ensure_ascii=False, indent=2)

    html_path = os.path.join(output_dir, f"resultado_{ts}.html")
    with open(html_path, "w", encoding="utf-8") as f:
        f.write(_gerar_html(relatorio))

    print(f"\n📄 Relatório JSON: {json_path}")
    print(f"🌐 Relatório HTML: {html_path}")
    return relatorio