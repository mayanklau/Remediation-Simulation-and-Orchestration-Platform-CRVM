from fastapi import APIRouter, Depends
from motor.motor_asyncio import AsyncIOMotorDatabase

from app.dependencies import database, tenant_context
from app.models import Tenant
from app.services.crvm import build_crvm_model, snapshot_crvm_model

router = APIRouter()


@router.get("/crvm")
async def crvm(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return {"crvm": await build_crvm_model(db, tenant.id)}


@router.post("/crvm/snapshot")
async def snapshot_crvm(tenant: Tenant = Depends(tenant_context), db: AsyncIOMotorDatabase = Depends(database)):
    return await snapshot_crvm_model(db, tenant.id)
