import threading
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from api.auth_router import router as auth_router
from api.company_router import router as company_router
from api.incidents_router import router as incidents_router
from api.rooms_router import router as rooms_router
from controller import AttenseController

controller = AttenseController()


@asynccontextmanager
async def lifespan(app: FastAPI):
    thread = threading.Thread(target=controller.run, daemon=True)
    thread.start()
    yield


app = FastAPI(lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_router)
app.include_router(company_router)
app.include_router(incidents_router)
app.include_router(rooms_router)


@app.get("/health")
def health():
    blueteam = controller.blueteam_status()
    if not blueteam["healthy"]:
        raise HTTPException(
            status_code=503,
            detail={"status": "degraded", "blue_team": blueteam},
        )
    return {
        "status": "ok",
        "active_incidents": len(controller.incidents),
        "blue_team": blueteam,
    }
