from fastapi import FastAPI, APIRouter, HTTPException, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from starlette.middleware.cors import CORSMiddleware
from motor.motor_asyncio import AsyncIOMotorClient
import os
import logging
from pathlib import Path
from pydantic import BaseModel, Field, ConfigDict
from typing import List, Optional
import uuid
from datetime import datetime, timezone, timedelta
import hashlib
import jwt
 
ROOT_DIR = Path(__file__).parent
load_dotenv(ROOT_DIR / '.env')
 
# MongoDB connection
mongo_url = os.environ['MONGO_URL']
client = AsyncIOMotorClient(mongo_url)
db = client[os.environ['DB_NAME']]
 
SECRET_KEY = os.environ.get('SECRET_KEY', 'partnerfinder-secret-key-2026')
 
app = FastAPI()
api_router = APIRouter(prefix="/api")
security = HTTPBearer()
 
# ─── UTILITY ────────────────────────────────────────────────
def hash_password(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()
 
def create_token(user_id: str, email: str, role: str) -> str:
    payload = {
        "user_id": user_id,
        "email": email,
        "role": role,
        "exp": datetime.now(timezone.utc) + timedelta(days=7)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")
 
def verify_token(credentials: HTTPAuthorizationCredentials = Depends(security)):
    try:
        payload = jwt.decode(credentials.credentials, SECRET_KEY, algorithms=["HS256"])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token scaduto")
    except jwt.InvalidTokenError:
        raise HTTPException(status_code=401, detail="Token non valido")
 
# ─── MODELLI ────────────────────────────────────────────────
class UserRegister(BaseModel):
    nome: str
    email: str
    password: str
    tipo: str  # "sponsor" o "sponsee"
 
class UserLogin(BaseModel):
    email: str
    password: str
 
class User(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    nome: str
    email: str
    tipo: str  # "sponsor", "sponsee", "admin"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    attivo: bool = True
 
class SponsorProfile(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    user_id: str
    nome: str
    email: str
    categoria: str
    descrizione: str
    budget: Optional[str] = ""
    sito_web: Optional[str] = ""
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
 
class SponsorProfileCreate(BaseModel):
    categoria: str
    descrizione: str
    budget: Optional[str] = ""
    sito_web: Optional[str] = ""
 
class RichiestaSponsor(BaseModel):
    model_config = ConfigDict(extra="ignore")
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    sponsee_id: str
    sponsee_nome: str
    sponsor_id: str
    sponsor_nome: str
    messaggio: str
    stato: str = "in_attesa"  # "in_attesa", "approvata", "rifiutata"
    created_at: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
 
class RichiestaCreate(BaseModel):
    sponsor_id: str
    messaggio: str
 
# ─── ROUTES AUTH ────────────────────────────────────────────
@api_router.get("/")
async def root():
    return {"message": "PartnerFinder API funzionante"}
 
@api_router.post("/auth/register")
async def register(data: UserRegister):
    # Controlla se email esiste già
    existing = await db.users.find_one({"email": data.email})
    if existing:
        raise HTTPException(status_code=400, detail="Email già registrata")
    
    if data.tipo not in ["sponsor", "sponsee"]:
        raise HTTPException(status_code=400, detail="Tipo non valido")
    
    user = User(nome=data.nome, email=data.email, tipo=data.tipo)
    doc = user.model_dump()
    doc["password"] = hash_password(data.password)
    
    await db.users.insert_one(doc)
    token = create_token(user.id, user.email, user.tipo)
    
    return {"token": token, "user": {"id": user.id, "nome": user.nome, "email": user.email, "tipo": user.tipo}}
 
@api_router.post("/auth/login")
async def login(data: UserLogin):
    user = await db.users.find_one({"email": data.email, "password": hash_password(data.password)})
    if not user:
        raise HTTPException(status_code=401, detail="Email o password errati")
    
    token = create_token(user["id"], user["email"], user["tipo"])
    return {"token": token, "user": {"id": user["id"], "nome": user["nome"], "email": user["email"], "tipo": user["tipo"]}}
 
@api_router.get("/auth/me")
async def get_me(payload=Depends(verify_token)):
    user = await db.users.find_one({"id": payload["user_id"]}, {"_id": 0, "password": 0})
    if not user:
        raise HTTPException(status_code=404, detail="Utente non trovato")
    return user
 
# ─── ROUTES SPONSOR ─────────────────────────────────────────
@api_router.get("/sponsors")
async def get_sponsors():
    sponsors = await db.sponsor_profiles.find({}, {"_id": 0}).to_list(1000)
    return sponsors
 
@api_router.post("/sponsors/profile")
async def create_sponsor_profile(data: SponsorProfileCreate, payload=Depends(verify_token)):
    if payload["role"] != "sponsor":
        raise HTTPException(status_code=403, detail="Solo gli sponsor possono creare un profilo sponsor")
    
    user = await db.users.find_one({"id": payload["user_id"]})
    existing = await db.sponsor_profiles.find_one({"user_id": payload["user_id"]})
    if existing:
        raise HTTPException(status_code=400, detail="Profilo sponsor già esistente")
    
    profile = SponsorProfile(
        user_id=payload["user_id"],
        nome=user["nome"],
        email=user["email"],
        categoria=data.categoria,
        descrizione=data.descrizione,
        budget=data.budget,
        sito_web=data.sito_web
    )
    await db.sponsor_profiles.insert_one(profile.model_dump())
    return profile
 
# ─── ROUTES RICHIESTE ───────────────────────────────────────
@api_router.post("/richieste")
async def create_richiesta(data: RichiestaCreate, payload=Depends(verify_token)):
    if payload["role"] != "sponsee":
        raise HTTPException(status_code=403, detail="Solo gli sponsee possono inviare richieste")
    
    sponsor_profile = await db.sponsor_profiles.find_one({"id": data.sponsor_id})
    if not sponsor_profile:
        raise HTTPException(status_code=404, detail="Sponsor non trovato")
    
    sponsee = await db.users.find_one({"id": payload["user_id"]})
    
    richiesta = RichiestaSponsor(
        sponsee_id=payload["user_id"],
        sponsee_nome=sponsee["nome"],
        sponsor_id=data.sponsor_id,
        sponsor_nome=sponsor_profile["nome"],
        messaggio=data.messaggio
    )
    await db.richieste.insert_one(richiesta.model_dump())
    return richiesta
 
@api_router.get("/richieste/mie")
async def get_mie_richieste(payload=Depends(verify_token)):
    if payload["role"] == "sponsee":
        richieste = await db.richieste.find({"sponsee_id": payload["user_id"]}, {"_id": 0}).to_list(1000)
    elif payload["role"] == "sponsor":
        profile = await db.sponsor_profiles.find_one({"user_id": payload["user_id"]})
        if not profile:
            return []
        richieste = await db.richieste.find({"sponsor_id": profile["id"]}, {"_id": 0}).to_list(1000)
    else:
        richieste = await db.richieste.find({}, {"_id": 0}).to_list(1000)
    return richieste
 
# ─── ROUTES ADMIN ───────────────────────────────────────────
@api_router.get("/admin/users")
async def get_all_users(payload=Depends(verify_token)):
    if payload["role"] != "admin":
        raise HTTPException(status_code=403, detail="Accesso negato")
    users = await db.users.find({}, {"_id": 0, "password": 0}).to_list(1000)
    return users
 
@api_router.put("/admin/richieste/{richiesta_id}")
async def update_richiesta(richiesta_id: str, stato: str, payload=Depends(verify_token)):
    if payload["role"] != "admin":
        raise HTTPException(status_code=403, detail="Accesso negato")
    if stato not in ["approvata", "rifiutata"]:
        raise HTTPException(status_code=400, detail="Stato non valido")
    await db.richieste.update_one({"id": richiesta_id}, {"$set": {"stato": stato}})
    return {"message": f"Richiesta {stato}"}
 
# ─── INCLUDE ROUTER ─────────────────────────────────────────
app.include_router(api_router)
app.add_middleware(
    CORSMiddleware,
    allow_credentials=True,
    allow_origins=os.environ.get('CORS_ORIGINS', '*').split(','),
    allow_methods=["*"],
    allow_headers=["*"],
)
 
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)
 
@app.on_event("shutdown")
async def shutdown_db_client():
    client.close()
