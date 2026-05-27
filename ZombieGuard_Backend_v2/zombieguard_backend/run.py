"""
ZombieGuard — Run Server
Usage: python run.py
Opens: http://localhost:8000
API Docs: http://localhost:8000/docs
"""
import uvicorn

if __name__ == "__main__":
    print("=" * 60)
    print("  🧟 ZombieGuard — Zombie API Discovery & Defence System")
    print("  iDEA 2.0 Hackathon | PS9 | Team Insiders")
    print("  Union Bank of India")
    print("=" * 60)
    print("  Dashboard  → http://localhost:8000")
    print("  API Docs   → http://localhost:8000/docs")
    print("  ReDoc      → http://localhost:8000/redoc")
    print("=" * 60)
    print("  Stack: FastAPI + scikit-learn + NumPy + BeautifulSoup")
    print("         + SQL Alchemy + Pydantic + Kafka + Uvicorn")
    print("=" * 60)
    uvicorn.run(
        "app.main:app",
        host="0.0.0.0",
        port=8000,
        reload=True,
        log_level="info",
    )
