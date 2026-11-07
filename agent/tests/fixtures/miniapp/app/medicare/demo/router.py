from fastapi import APIRouter, Depends

from medicare.auth.models import Role, User
from medicare.common.auth import get_current_user, require_roles
from medicare.common.csrf import verify_csrf
from medicare.demo import service

router = APIRouter()


@router.get("/items/{item_id}")
def item_detail(item_id: int, user: User = Depends(get_current_user)):
    return service.load_item(item_id)


@router.post("/items", dependencies=[Depends(verify_csrf)])
def create_item(name: str, user: User = Depends(require_roles(Role.DOCTOR))):
    return {"name": name}


@router.get("/items/{item_id}/export")
def export(item_id: int, user: User = Depends(get_current_user)):
    data = service.load_item(item_id)
    return service.export_item(data)
