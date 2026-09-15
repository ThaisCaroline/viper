"""
VIPER — Backend FastAPI
Recebe a config do alvo, executa a bateria e devolve os resultados.
"""

import os
import json
import tempfile
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
    campo_mensagem: str
    campo_resposta: str
    token: str = ""
    marcadores: list[str]
    categorias: list[str] = []


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
        "alvo": {
            "nome":      config.nome,
            "url":       config.url,
            "ambiente":  config.ambiente,
        },
        "request": {
            "campo_mensagem":  config.campo_mensagem,
            "content_type":    "application/json",
            "headers": {"Authorization": f"Bearer {config.token}"} if config.token else {},
        },
        "response": {
            "campo_resposta": config.campo_resposta,
        },
        "marcadores": config.marcadores,
    }

    with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
        import yaml
        yaml.dump(config_dict, f)
        tmp_path = f.name

    try:
        categorias = config.categorias if config.categorias else None
        resultados = executar_bateria(tmp_path, categorias=categorias)
        relatorio  = gerar_relatorio(resultados, alvo=config.nome)
        return relatorio
    finally:
        os.unlink(tmp_path)