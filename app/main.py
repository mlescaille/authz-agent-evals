from fastapi import FastAPI

from app.db import connect, database_path, init_db
from app.routes import build_router


def create_app(path=None):
    app = FastAPI()
    conn = connect(path or database_path())
    init_db(conn)
    app.state.conn = conn
    app.include_router(build_router())
    return app


app = create_app()
