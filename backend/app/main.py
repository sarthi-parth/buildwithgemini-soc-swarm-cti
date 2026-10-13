import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from app.config import settings
from app.database.session import init_db
from app.services.ingestion_service import seed_default_sources, poll_all_sources
from app.services.demo_seeder import seed_demo_data
from app.api.routes import router

scheduler = AsyncIOScheduler()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # 1. Initialize DB tables
    print("[SOC Swarm CTI] Initializing database...")
    await init_db()

    # 2. Seed Default Sources & Demo incidents
    print("[SOC Swarm CTI] Seeding default sources & demo data...")
    await seed_default_sources()
    await seed_demo_data()

    # 3. Setup background scheduler
    print(f"[SOC Swarm CTI] Scheduling RSS poller every {settings.POLLING_INTERVAL_MINUTES} minutes...")
    scheduler.add_job(poll_all_sources, "interval", minutes=settings.POLLING_INTERVAL_MINUTES)
    scheduler.start()

    yield

    # Shutdown
    print("[SOC Swarm CTI] Shutting down scheduler...")
    scheduler.shutdown()

app = FastAPI(
    title="SOC Swarm CTI API",
    description="Autonomous Multi-Agent Cyber Threat Intelligence and Breach Investigation Platform",
    version="1.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # local dev friendly
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(router, prefix="/api")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=True)
