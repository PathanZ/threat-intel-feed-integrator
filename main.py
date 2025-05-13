from fastapi import FastAPI
from app.routes import feeds

app = FastAPI(title="Threat Intel Feed Integrator")

app.include_router(feeds.router, prefix="/api/feeds")

@app.get("/")
def read_root():
    return {"message": "Welcome to the Threat Intelligence Feed Integrator"}
