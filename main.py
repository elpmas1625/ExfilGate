import uvicorn

from app.config.settings import load_settings


def main() -> None:
    settings = load_settings()
    uvicorn.run("app.main:app", host=settings.server.host, port=settings.server.port)


if __name__ == "__main__":
    main()
