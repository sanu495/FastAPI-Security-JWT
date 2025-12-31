from fastapi import FastAPI
from controller import router
from fastapi.security import OAuth2PasswordBearer
import uvicorn

app = FastAPI(title="Backend Security Demo", description="OAuth2 Password Flow Demo", version="1.0.0")

app.include_router(router)

if __name__== "__main__":
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)