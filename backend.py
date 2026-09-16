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

load_dotenv()

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
    formato_documento: str = ""


@app.get("/")
def index():
    return FileResponse("frontend/index.html")


@app.get("/favicon.ico")
def favicon():
    return FileResponse("frontend/favicon.ico")


@app.post("/atacar")
def atacar(config: ConfigAtaque):
    if config.ambiente.lower() in ["prd", "prod", "production"]:
        return {"erro": "Ambiente produtivo bloqueado. Use ambiente de laboratório."}

    config_dict = {
        "url":               config.url,
        "nome":              config.nome,
        "token":             config.token,
        "contexto":          config.contexto,
        "json_input":        config.json_input,
        "json_output":       config.json_output,
        "dados_proteger":    config.dados_proteger,
        "usar_ia_contextual": config.usar_ia_contextual,
        "aceita_documento":   config.aceita_documento,
        "formato_documento": config.formato_documento,
    }

    resultados = executar_bateria(config_dict)
    relatorio  = gerar_relatorio(resultados, alvo=config.nome)
    return relatorio