import os
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from passlib.context import CryptContext
from jose import JWTError, jwt
from pydantic import BaseModel, EmailStr, Field
from typing import Optional, Dict
from dotenv import load_dotenv
from datetime import datetime, timedelta

# Load .env variables
load_dotenv()

# App Metadata & OpenAPI tags
app = FastAPI(
    title="Authentication Backend API",
    description="Handles user authentication, registration, token validation, and account management.",
    version="0.1.0",
    openapi_tags=[
        {"name": "Auth", "description": "Authentication-related operations."},
        {"name": "Account", "description": "Account management routes."},
    ],
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Configuration from environment variables
SECRET_KEY = os.getenv("AUTH_SECRET_KEY", "super-secret-placeholder")
ALGORITHM = os.getenv("AUTH_JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.getenv("AUTH_TOKEN_EXPIRE_MINUTES", 30))

# Password hashing context
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="login")

# In-memory "database" (Replace with real DB in production)
users_db: Dict[str, Dict] = {}

#############
# Models
#############

class UserBase(BaseModel):
    """Base user model."""
    email: EmailStr = Field(..., description="User's email address")

class UserCreate(UserBase):
    """User creation model."""
    password: str = Field(..., min_length=8, description="Strong password")

class User(UserBase):
    """User model exposed to clients."""
    full_name: Optional[str] = Field(None, description="User's full name")
    is_active: bool = Field(default=True, description="Active status of user")

class UserInDB(User):
    """Internal user model with password hash."""
    hashed_password: str

class Token(BaseModel):
    """Response for issued JWT tokens."""
    access_token: str
    token_type: str

class TokenData(BaseModel):
    email: Optional[str] = None

#############
# Utilities
#############

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(email: str) -> Optional[UserInDB]:
    user = users_db.get(email)
    if user:
        return UserInDB(**user)
    return None

def authenticate_user(email: str, password: str):
    user = get_user(email)
    if not user:
        return False
    if not verify_password(password, user.hashed_password):
        return False
    return user

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    """Generate JWT Access token."""
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta if expires_delta else timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

async def get_current_user(token: str = Depends(oauth2_scheme)) -> User:
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials.",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception
        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user(token_data.email)
    if user is None or not user.is_active:
        raise credentials_exception
    return user

#############
# API Endpoints
#############

@app.get("/", tags=["Misc"])
def health_check():
    """Health check endpoint."""
    return {"message": "Healthy"}

# PUBLIC_INTERFACE
@app.post("/signup", response_model=User, status_code=status.HTTP_201_CREATED, tags=["Auth"], summary="Register a new user")
def signup(user: UserCreate):
    """
    Register a new user account with email and password.

    - **email**: Email address
    - **password**: User password (min 8 chars)
    """
    if get_user(user.email):
        raise HTTPException(status_code=400, detail="Email already registered.")
    hashed_pw = get_password_hash(user.password)
    user_obj = {
        "email": user.email,
        "hashed_password": hashed_pw,
        "full_name": "",
        "is_active": True,
    }
    users_db[user.email] = user_obj
    return User(**user_obj)

# PUBLIC_INTERFACE
@app.post("/login", response_model=Token, tags=["Auth"], summary="User login and token issue")
def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Authenticate and get JWT token.

    - **username**: Email address (OAuth2 uses `username` field)
    - **password**: User password
    """
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect email or password")
    access_token = create_access_token(data={"sub": user.email})
    return {"access_token": access_token, "token_type": "bearer"}

# PUBLIC_INTERFACE
@app.post("/token/validate", tags=["Auth"], summary="Validate JWT token")
def validate_token(token: str = Depends(oauth2_scheme)):
    """
    Validate a JWT access token.
    
    - **token**: Bearer token in Authorization header
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email = payload.get("sub")
        if get_user(email):
            return {"valid": True, "email": email}
        return {"valid": False}
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

# PUBLIC_INTERFACE
@app.get("/account/me", response_model=User, tags=["Account"], summary="Get my account details")
def get_my_account(current_user: User = Depends(get_current_user)):
    """
    Returns current user's account information.

    Requires valid Bearer JWT token.
    """
    return current_user

# PUBLIC_INTERFACE
@app.delete("/account/me", status_code=204, tags=["Account"], summary="Delete my account")
def delete_my_account(current_user: User = Depends(get_current_user)):
    """
    Delete the current user's account.

    Requires valid Bearer JWT token.
    """
    email = current_user.email
    if email in users_db:
        del users_db[email]
    return

# PUBLIC_INTERFACE
@app.put("/account/me", response_model=User, tags=["Account"], summary="Update my account information")
def update_my_account(updated: User, current_user: User = Depends(get_current_user)):
    """
    Update current user's account fields (except email).

    Requires valid Bearer JWT token.
    """
    user_db = users_db.get(current_user.email)
    if not user_db:
        raise HTTPException(status_code=404, detail="User not found")
    user_db["full_name"] = updated.full_name
    user_db["is_active"] = updated.is_active
    users_db[current_user.email] = user_db
    return User(**user_db)

