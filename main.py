import sqlite3
import hashlib
import os
from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

def hash_password(password: str) -> str:
    salt = os.urandom(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    return salt.hex() + ':' + pwd_hash.hex()

def verify_password(plain_password: str, hashed_password: str) -> bool:
    try:
        salt_hex, hash_hex = hashed_password.split(':')
        salt = bytes.fromhex(salt_hex)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', plain_password.encode(), salt, 100000)
        return pwd_hash.hex() == hash_hex
    except ValueError:
        return False

# Updated schemas to match your React forms
class UserRegister(BaseModel):
    name: str
    department: str
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class UserResponse(BaseModel):
    id: int
    name: str
    username: str
    department: str

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"], 
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def init_db():
    with sqlite3.connect("app.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                department TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                hashed_password TEXT NOT NULL
            )
        """)
        conn.commit()

init_db()

def get_db():
    conn = sqlite3.connect("app.db")
    conn.row_factory = sqlite3.Row 
    try:
        yield conn
    finally:
        conn.close()

@app.post("/register", response_model=UserResponse)
def register(user: UserRegister, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    hashed_pwd = hash_password(user.password)
    
    try:
        cursor.execute(
            "INSERT INTO users (name, department, username, hashed_password) VALUES (?, ?, ?, ?)", 
            (user.name, user.department, user.username, hashed_pwd)
        )
        db.commit()
        return {
            "id": cursor.lastrowid, 
            "name": user.name, 
            "department": user.department,
            "username": user.username
        }
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already taken")

@app.post("/login")
def login(user: UserLogin, db: sqlite3.Connection = Depends(get_db)):
    cursor = db.cursor()
    cursor.execute("SELECT id, name, department, username, hashed_password FROM users WHERE username = ?", (user.username,))
    db_user = cursor.fetchone()
    
    if not db_user or not verify_password(user.password, db_user["hashed_password"]):
        raise HTTPException(status_code=401, detail="Invalid username or password")
    
    return {
        "message": "Login successful", 
        "user": {
            "id": db_user["id"], 
            "name": db_user["name"], 
            "department": db_user["department"],
            "username": db_user["username"]
        }
    }