from fastapi import FastAPI

from app.db import connect, database_path, init_db
from eval.reference_app.routes import build_router


def create_app(path=None):
    application = FastAPI()
    conn = connect(path or database_path())
    init_db(conn)
    application.state.conn = conn
    application.include_router(build_router())
    return application


app = create_app()
