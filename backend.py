"""
VIPER — Backend FastAPI
Recebe a config do alvo, executa a bateria e devolve os resultados.
"""

import os
from fastapi import FastAPI, Query, Header, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel
from dotenv import load_dotenv
from typing import Optional

from runner.runner import executar_bateria
from report.reporter import gerar_relatorio
from runner.logger import inicializar_banco, salvar_teste, listar_testes, buscar_teste, comparar_testes

load_dotenv()

inicializar_banco()

app = FastAPI(title="VIPER")

app.mount("/static", StaticFiles(directory="frontend"), name="static")

ADMINS = [e.strip().lower() for e in os.getenv("VIPER_ADMINS", "").split(",") if e.strip()]
API_KEY = os.getenv("VIPER_API_KEY", "")


def is_admin(email: str) -> bool:
    return email.strip().lower() in ADMINS


def validar_api_key(x_api_key: str = Header(default="")):
    if API_KEY and x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Chave de API inválida")


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
    formato_documento: Optional[str] = ""
    campo_documento: str = "file"
    documento_base64: str = ""
    documento_nome: str = ""
    tecnico: str = "Anônimo"
    email_tecnico: str = ""


@app.get("/")
def index():
    return FileResponse("frontend/login.html")


@app.get("/viper")
def viper():
    return FileResponse("frontend/index.html")


@app.get("/historico")
def historico():
    return FileResponse("frontend/historico.html")


@app.get("/logout")
def logout():
    return FileResponse("frontend/logout.html")


@app.get("/favicon.ico")
def favicon():
    return FileResponse("frontend/favicon.ico")


@app.get("/api/me")
def api_me(email: str = Query("")):
    return {"admin": is_admin(email)}


@app.get("/api/auth-config")
def api_auth_config():
    return {
        "clientId":    os.getenv("AZURE_CLIENT_ID", ""),
        "tenantId":    os.getenv("AZURE_TENANT_ID", ""),
        "redirectUri": os.getenv("AZURE_REDIRECT_URI", "http://localhost:8001/viper"),
    }


@app.get("/api/config")
def api_config():
    """Configurações do frontend — inclui API key para autenticar /atacar."""
    return {
        "apiKey": API_KEY,
    }


@app.post("/atacar")
def atacar(config: ConfigAtaque, x_api_key: str = Header(default="")):
    validar_api_key(x_api_key)

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
        "campo_documento":    config.campo_documento,
        "documento_base64":   config.documento_base64,
        "documento_nome":     config.documento_nome,
    }

    resultados = executar_bateria(config_dict)
    relatorio  = gerar_relatorio(resultados, alvo=config.nome)

    relatorio["url_agente"] = config.url
    salvar_teste(relatorio, tecnico=config.tecnico, email_tecnico=config.email_tecnico)

    html_path = relatorio.get("html_path", "")
    if html_path and os.path.exists(html_path):
        with open(html_path, "r", encoding="utf-8") as f:
            relatorio["relatorio_html"] = f.read()

    return relatorio


@app.get("/api/historico")
def api_historico(email: str = Query(""), admin: bool = Query(False)):
    if admin and is_admin(email):
        return listar_testes()
    return listar_testes(email_tecnico=email)


@app.delete("/api/historico/{teste_id}")
def api_deletar_teste(teste_id: int, email: str = Query("")):
    from runner.logger import deletar_teste
    deletar_teste(teste_id, deletado_por=email)
    return {"ok": True}


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


@app.get("/api/audit-log")
def api_audit_log(email: str = Query("")):
    if not is_admin(email):
        raise HTTPException(status_code=403, detail="Acesso negado")
    from runner.logger import listar_audit_log
    return listar_audit_log()


@app.get("/api/audit-log/{audit_id}/json")
def api_audit_json(audit_id: int, email: str = Query("")):
    if not is_admin(email):
        raise HTTPException(status_code=403, detail="Acesso negado")
    from runner.logger import buscar_audit_json_path
    from fastapi.responses import FileResponse as FR
    json_path = buscar_audit_json_path(audit_id)
    if not json_path or not os.path.exists(json_path):
        raise HTTPException(status_code=404, detail="JSON não encontrado")
    return FR(json_path, media_type="application/json", filename=os.path.basename(json_path))