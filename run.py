import os

# Optional: load environment variables from .env (safe if python-dotenv isn't installed)
try:
    from dotenv import load_dotenv  # type: ignore
    load_dotenv()
except Exception:
    pass


from app import create_app

app = create_app()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5101)
