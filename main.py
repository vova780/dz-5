from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import Depends, FastAPI, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, EmailStr, Field

SECRET_KEY = "dev-only-secret-key-change-me"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7

app = FastAPI(title="JWT Auth Demo (мінімальна версія)")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

fake_users_db: dict[str, dict] = {}
token_blacklist: set[str] = set()

def _seed_demo_admin() -> None:
    fake_users_db["admin"] = {
        "username": "admin",
        "email": "admin@example.com",
        "hashed_password": pwd_context.hash("admin123"),
        "role": "admin",
    }

_seed_demo_admin()

class UserRegister(BaseModel):
    username: str = Field(min_length=3, max_length=32)
    email: EmailStr
    password: str = Field(min_length=8)

class UserOut(BaseModel):
    username: str
    email: EmailStr
    role: str

class ChangePassword(BaseModel):
    old_password: str
    new_password: str = Field(min_length=8)

class DeleteAccount(BaseModel):
    password: str

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

class RefreshRequest(BaseModel):
    refresh_token: str

class Message(BaseModel):
    message: str

def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

def _create_token(data: dict, expires_delta: timedelta, token_type: str) -> str:
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire, "type": token_type})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def create_access_token(username: str) -> str:
    return _create_token(
        {"sub": username},
        timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        token_type="access",
    )

def create_refresh_token(username: str) -> str:
    return _create_token(
        {"sub": username},
        timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
        token_type="refresh",
    )

def decode_token(token: str) -> dict:
    if token in token_blacklist:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Токен анульовано (logout)",
        )
    try:
        return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Не вдалося перевірити токен",
        )

def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    payload = decode_token(token)
    if payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Очікувався access-токен",
        )
    username: Optional[str] = payload.get("sub")
    user = fake_users_db.get(username) if username else None
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Користувача не знайдено",
        )
    return user

def require_role(role: str):

    def role_checker(current_user: dict = Depends(get_current_user)) -> dict:
        if current_user.get("role") != role:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Недостатньо прав доступу",
            )
        return current_user

    return role_checker

@app.post("/register", response_model=UserOut, status_code=status.HTTP_201_CREATED)
def register(user: UserRegister):
    if user.username in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Користувач з таким username вже існує",
        )
    fake_users_db[user.username] = {
        "username": user.username,
        "email": user.email,
        "hashed_password": get_password_hash(user.password),
        "role": "user",
    }
    return fake_users_db[user.username]

@app.post("/login", response_model=Token)
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    user = fake_users_db.get(form_data.username)
    if not user or not verify_password(form_data.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Невірний username або пароль",
        )
    return Token(
        access_token=create_access_token(user["username"]),
        refresh_token=create_refresh_token(user["username"]),
    )

@app.post("/refresh", response_model=Token)
def refresh(data: RefreshRequest):
    payload = decode_token(data.refresh_token)
    if payload.get("type") != "refresh":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Очікувався refresh-токен",
        )
    username: Optional[str] = payload.get("sub")
    if username not in fake_users_db:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Користувача не знайдено",
        )
    return Token(
        access_token=create_access_token(username),
        refresh_token=create_refresh_token(username),
    )

@app.post("/logout", response_model=Message)
def logout(token: str = Depends(oauth2_scheme)):
    decode_token(token)
    token_blacklist.add(token)
    return Message(message="Вихід виконано успішно")

@app.get("/profile", response_model=UserOut)
def profile(current_user: dict = Depends(get_current_user)):
    return current_user

@app.post("/change-password", response_model=Message)
def change_password(
    data: ChangePassword,
    current_user: dict = Depends(get_current_user),
):
    if not verify_password(data.old_password, current_user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Поточний пароль вказано невірно",
        )
    current_user["hashed_password"] = get_password_hash(data.new_password)
    return Message(message="Пароль успішно змінено")

@app.delete("/profile", response_model=Message)
def delete_account(
    data: DeleteAccount,
    current_user: dict = Depends(get_current_user),
):
    if not verify_password(data.password, current_user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Пароль вказано невірно — акаунт не видалено",
        )
    del fake_users_db[current_user["username"]]
    return Message(message="Акаунт видалено")

@app.get("/admin/users", response_model=list[UserOut])
def list_users(current_user: dict = Depends(require_role("admin"))):
    return list(fake_users_db.values())