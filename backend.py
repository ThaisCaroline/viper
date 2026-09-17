"""
VIPER — Backend FastAPI
Recebe a config do alvo, executa a bateria e devolve os resultados.
"""

import os
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv

from runner.runner import executar_bateria
from report.reporter import gerar_relatorio
from runner.logger import inicializar_banco, salvar_teste, listar_testes, buscar_teste, comparar_testes

load_dotenv()

# Inicializa o banco na subida do servidor
inicializar_banco()

app = FastAPI(title="VIPER")

app.mount("/static", StaticFiles(directory="frontend"), name="static")


class ConfigAtaque(BaseModel):
    url: str
    nome: str
    ambiente: str
    token: str = ""
    contexto: str
    json_input: str
    json_output: str
    dados_proteger: list[str] = []
    usar_ia_contextual: bool = True
    aceita_documento: bool = False
    formato_documento: str | None = ""
    tecnico: str = "Anônimo"


@app.get("/")
def index():
    return FileResponse("frontend/login.html")


@app.get("/viper")
def viper():
    return FileResponse("frontend/index.html")


@app.get("/historico")
def historico():
    return FileResponse("frontend/historico.html")


@app.get("/favicon.ico")
def favicon():
    return FileResponse("frontend/favicon.ico")


@app.post("/atacar")
def atacar(config: ConfigAtaque):
    if config.ambiente.lower() in ["prd", "prod", "production"]:
        return {"erro": "Ambiente produtivo bloqueado. Use ambiente de laboratório."}

    config_dict = {
        "url":                config.url,
        "nome":               config.nome,
        "token":              config.token,
        "contexto":           config.contexto,
        "json_input":         config.json_input,
        "json_output":        config.json_output,
        "dados_proteger":     config.dados_proteger,
        "usar_ia_contextual": config.usar_ia_contextual,
        "aceita_documento":   config.aceita_documento,
        "formato_documento":  config.formato_documento,
    }

    resultados = executar_bateria(config_dict)
    relatorio  = gerar_relatorio(resultados, alvo=config.nome)

    # Adiciona URL e técnico ao relatório antes de salvar
    relatorio["url_agente"] = config.url
    salvar_teste(relatorio, tecnico=config.tecnico)

    # Lê o HTML gerado e inclui no retorno pra o front usar no botão PDF
    html_path = relatorio.get("html_path", "")
    if html_path and os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            relatorio["relatorio_html"] = f.read()

    return relatorio


@app.get("/api/historico")
def api_historico():
    return listar_testes()


@app.get("/api/historico/{teste_id}/html")
def api_teste_html(teste_id: int):
    from fastapi.responses import HTMLResponse
    teste = buscar_teste(teste_id)
    if not teste:
        return {"erro": "Teste não encontrado"}
    html_path = teste.get("html_path", "")
    if html_path and os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read())
    return HTMLResponse(content="<p>Relatório não disponível</p>", status_code=404)


@app.get("/api/historico/{teste_id}")
def api_teste(teste_id: int):
    teste = buscar_teste(teste_id)
    if not teste:
        return {"erro": "Teste não encontrado"}
    return teste


@app.get("/api/comparativo/{id1}/{id2}")
def api_comparativo(id1: int, id2: int):
    return comparar_testes(id1, id2)