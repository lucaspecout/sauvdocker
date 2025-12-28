from fastapi import APIRouter, Depends
from ..auth import require_permission
from ..docker_client import list_containers, list_volumes

router = APIRouter(prefix="/resources", tags=["resources"])


@router.get("/containers")
def containers(user=Depends(require_permission("view"))):
    return {"items": list_containers()}


@router.get("/volumes")
def volumes(user=Depends(require_permission("view"))):
    return {"items": list_volumes()}
