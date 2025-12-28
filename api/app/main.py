import secrets
from fastapi import FastAPI, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from .config import settings
from .db import Base, engine, get_db
from .models import User
from .security import hash_password
from .routers import auth, resources, plans, jobs, settings as settings_router, users, audit

app = FastAPI(title="DockBack API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"]
    if settings.dockback_base_url == "*"
    else [settings.dockback_base_url],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)
    db = next(get_db())
    admin = db.query(User).filter(User.email == "admin").first()
    if not admin:
        password = secrets.token_urlsafe(12)
        admin = User(
            email="admin",
            password_hash=hash_password(password),
            role="Admin",
            force_password_change=True,
            is_active=True,
        )
        db.add(admin)
        db.commit()
        print(f"DockBack admin password (printed once): {password}")
    db.close()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/jobs/{job_id}/logs")
def job_logs(job_id: int):
    def stream():
        yield f"data: job {job_id} log stream not configured\n\n"

    return StreamingResponse(stream(), media_type="text/event-stream")


app.include_router(auth.router)
app.include_router(resources.router)
app.include_router(plans.router)
app.include_router(jobs.router)
app.include_router(settings_router.router)
app.include_router(users.router)
app.include_router(audit.router)


@app.middleware("http")
async def add_security_headers(request, call_next):
    response: Response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "same-origin"
    response.headers["Content-Security-Policy"] = "default-src 'self'; img-src 'self' data:;"
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response
