"""Маршруты управления API-ключами (/api/web/api-keys)."""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response, status
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, StringConstraints

from server.auth import require_user_api
from server.services import api_keys as api_key_svc


def require_session_only(request: Request) -> str:
    """Запретить заголовок Authorization и потребовать сессию администратора."""
    if "authorization" in request.headers:
        raise HTTPException(status_code=401, detail="authorization header not allowed")
    return require_user_api(request)


router = APIRouter(
    prefix="/api/web/api-keys",
    tags=["api_keys"],
    dependencies=[Depends(require_session_only)],
)


class CreateApiKeyReq(BaseModel):
    """Параметры создания нового API-ключа."""

    model_config = ConfigDict(extra="forbid")
    name: Annotated[str, StringConstraints(strip_whitespace=True, min_length=1, max_length=80)]


@router.get("", response_model=None)
def list_api_keys() -> list[api_key_svc.ApiKeyInfo]:
    """Получить список действующих API-ключей администратора."""
    return api_key_svc.list_api_keys()


@router.post("", status_code=201, response_model=None)
def create_api_key(req: CreateApiKeyReq) -> JSONResponse:
    """Выпустить новый API-ключ администратора с однократной выдачей сырого токена."""
    key_data = api_key_svc.create_api_key(req.name)
    return JSONResponse(
        status_code=status.HTTP_201_CREATED,
        content=key_data,
        headers={"Cache-Control": "no-store"},
    )


@router.delete("/{key_id}", status_code=204)
def revoke_api_key(key_id: Annotated[int, Path(ge=1, le=2**63 - 1)]) -> Response:
    """Отозвать действующий API-ключ по идентификатору."""
    deleted = api_key_svc.revoke_api_key(key_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="api key not found")
    return Response(status_code=204)
