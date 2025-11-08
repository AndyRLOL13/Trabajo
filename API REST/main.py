from datetime import datetime, timedelta
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, status, Query
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from pydantic import BaseModel
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy import Column, DateTime, ForeignKey, Integer, String, Table, create_engine, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, sessionmaker, Session
import json
import os

# ==============================================
# CONFIGURACIÓN GENERAL
# ==============================================
SECRET_KEY = "supersecretkey"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

DATABASE_URL = "sqlite:///./users.db"
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine)
Base = declarative_base()

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="auth/login")

app = FastAPI(title="API REST con Tokens y Roles")

# ==============================================
# MODELOS DE BASE DE DATOS
# ==============================================
user_roles = Table(
    "user_roles",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id")),
    Column("role_id", Integer, ForeignKey("roles.id")),
)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    hashed_password = Column(String)
    roles = relationship("Role", secondary=user_roles, back_populates="users")
    created_at = Column(DateTime, default=datetime.utcnow)


class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True)
    users = relationship("User", secondary=user_roles, back_populates="roles")


Base.metadata.create_all(bind=engine)


# ==============================================
# ESQUEMAS Pydantic
# ==============================================
class UserCreate(BaseModel):
    username: str
    password: str


class UserOut(BaseModel):
    id: int
    username: str
    roles: List[str]

    class Config:
        orm_mode = True


class Token(BaseModel):
    access_token: str
    token_type: str


# ==============================================
# UTILIDADES
# ==============================================
def get_password_hash(password: str):
    return pwd_context.hash(password)


def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

    # Guardar token en archivo local
    token_data = {"usuario": data.get("sub"), "token": encoded_jwt, "expira": str(expire)}
    os.makedirs("data", exist_ok=True)
    with open("data/tokens.json", "a", encoding="utf-8") as f:
        json.dump(token_data, f)
        f.write("\n")

    return encoded_jwt


def get_user_by_username(db: Session, username: str):
    return db.query(User).filter(User.username == username).first()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ==============================================
# CREACIÓN INICIAL DE ADMIN Y ROLES
# ==============================================
def init_db():
    db = SessionLocal()
    admin_role = db.query(Role).filter_by(name="ADMIN").first()
    user_role = db.query(Role).filter_by(name="USER").first()

    if not admin_role:
        admin_role = Role(name="ADMIN")
        db.add(admin_role)
    if not user_role:
        user_role = Role(name="USER")
        db.add(user_role)
    db.commit()

    admin_user = db.query(User).filter_by(username="admin").first()
    if not admin_user:
        admin_user = User(username="admin", hashed_password=get_password_hash("admin123"))
        admin_user.roles = [admin_role, user_role]
        db.add(admin_user)
        db.commit()
    db.close()


init_db()


# ==============================================
# AUTENTICACIÓN Y REGISTRO
# ==============================================
@app.post("/auth/register", response_model=Token, status_code=status.HTTP_201_CREATED)
def register(user_in: UserCreate, db: Session = Depends(get_db)):
    if get_user_by_username(db, user_in.username):
        raise HTTPException(status_code=400, detail="Nombre de usuario ya existe")

    user_role = db.query(Role).filter_by(name="USER").first()
    new_user = User(username=user_in.username, hashed_password=get_password_hash(user_in.password))
    new_user.roles = [user_role]
    db.add(new_user)
    db.commit()
    db.refresh(new_user)

    access_token = create_access_token(data={"sub": new_user.username})
    return {"access_token": access_token, "token_type": "bearer"}


@app.post("/auth/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    user = get_user_by_username(db, form_data.username)
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Credenciales incorrectas")

    access_token = create_access_token(data={"sub": user.username})
    return {"access_token": access_token, "token_type": "bearer"}

@app.post("/users/{username}/change-role")
def change_user_role(username: str, new_role: str = Query(...), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.username == username).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    role = db.query(Role).filter(Role.name == new_role.upper()).first()
    if not role:
        raise HTTPException(status_code=404, detail="Rol no encontrado")

    user.roles = [role]
    db.commit()
    return {"message": f"Rol de {username} cambiado a {new_role.upper()}"}

# ==============================================
# DEPENDENCIAS DE TOKEN
# ==============================================
def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    credentials_exception = HTTPException(status_code=401, detail="Token inválido o expirado")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username = payload.get("sub")
        if username is None:
            raise credentials_exception
    except JWTError:
        raise credentials_exception
    user = get_user_by_username(db, username)
    if user is None:
        raise credentials_exception
    return user


def get_current_admin(current_user: User = Depends(get_current_user)):
    if not any(role.name == "ADMIN" for role in current_user.roles):
        raise HTTPException(status_code=403, detail="No tiene permisos de administrador")
    return current_user


# ==============================================
# ENDPOINTS DE USUARIOS Y ROLES
# ==============================================
@app.get("/users/me", response_model=UserOut)
def read_users_me(current_user: User = Depends(get_current_user)):
    return {"id": current_user.id, "username": current_user.username, "roles": [r.name for r in current_user.roles]}


@app.get("/users", response_model=List[UserOut])
def list_users(db: Session = Depends(get_db), _: User = Depends(get_current_admin)):
    users = db.query(User).all()
    return [{"id": u.id, "username": u.username, "roles": [r.name for r in u.roles]} for u in users]


@app.get("/roles", response_model=List[str])
def list_roles(db: Session = Depends(get_db), _: User = Depends(get_current_admin)):
    roles = db.query(Role).all()
    return [r.name for r in roles]


@app.post("/users/{user_id}/add-admin")
def add_admin_role(user_id: int, db: Session = Depends(get_db), _: User = Depends(get_current_admin)):
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="Usuario no encontrado")

    admin_role = db.query(Role).filter_by(name="ADMIN").first()
    if admin_role not in user.roles:
        user.roles.append(admin_role)
        db.commit()
    return {"msg": f"Usuario {user.username} ahora es ADMIN"}


@app.get("/tokens")
def get_tokens(_: User = Depends(get_current_admin)):
    """Devuelve los tokens guardados localmente (solo admin)."""
    try:
        with open("data/tokens.json", "r", encoding="utf-8") as f:
            return [json.loads(line) for line in f.readlines()]
    except FileNotFoundError:
        return []


# ==============================================
# EJECUCIÓN LOCAL
# ==============================================
if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
