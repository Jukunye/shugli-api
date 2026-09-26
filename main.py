from contextlib import asynccontextmanager

from fastapi import FastAPI

from api.v1.routers import auth
from core.config import settings
from core.db.base import Base, engine
import models

@asynccontextmanager
async def lifespan(app: FastAPI):
    Base.metadata.create_all(bind=engine)
    yield

app = FastAPI(title=settings.app_name, debug=settings.debug, lifespan=lifespan)

app.include_router(auth.router, prefix="/api/v1")
