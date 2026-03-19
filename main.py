from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from models import User
from database import SessionLocal, engine, Base
import schemas, auth
from utils import (
    create_access_token,
    verify_token,
    build_reset_link,
    send_password_reset_email,
)
from fastapi.security import HTTPBearer
from fastapi import Security
from fastapi.responses import HTMLResponse

app = FastAPI()
security = HTTPBearer()
Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(credentials=Security(security)):
    token = credentials.credentials
    email = verify_token(token)

    if email is None:
        raise HTTPException(status_code=401, detail="Invalid token")

    return email

@app.post("/auth/register")
def register(user: schemas.UserCreate, db: Session = Depends(get_db)):
    existing = db.query(User).filter(User.email == user.email).first()

    if existing:
        raise HTTPException(status_code=400, detail="Email already exists")

    auth.create_user(
        db,
        user.name,
        user.email,
        user.password,
        user.age,
        user.height,
        user.weight,
        user.goal,
    )

    return {"message": "User created successfully"}

@app.post("/auth/login")
def login(user: schemas.UserLogin, db: Session = Depends(get_db)):
    db_user = auth.authenticate_user(db, user.email, user.password)

    if not db_user:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token({"sub": db_user.email})

    return {
        "access_token": token,
        "token_type": "bearer"
    }

@app.post("/auth/forgot-password")
def forgot_password(payload: schemas.ForgotPasswordRequest, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == payload.email).first()

    # Always return the same message to avoid account enumeration.
    if user:
        raw_token = auth.generate_password_reset_token(db, user)
        reset_link = build_reset_link(raw_token)
        # send_password_reset_email(user.email, reset_link)
        print("\n🔗 RESET LINK:", reset_link, "\n")

    return {
        "message": "If an account exists for this email, a reset link has been sent."
    }

@app.post("/auth/reset-password")
def reset_password(payload: schemas.ResetPasswordRequest, db: Session = Depends(get_db)):
    if payload.new_password != payload.confirm_password:
        raise HTTPException(status_code=400, detail="Passwords do not match")

    user = auth.get_user_by_reset_token(db, payload.token)
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired reset token")

    auth.update_password_from_reset(db, user, payload.new_password)

    return {"message": "Password reset successful"}

@app.get("/auth/profile")
def profile(user_email: str = Depends(get_current_user), db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == user_email).first()

    return {
        "name": user.name,
        "email": user.email,
        "age": user.age,
        "height": user.height,
        "weight": user.weight,
        "goal": user.goal,
    }

@app.get("/reset-password", response_class=HTMLResponse)
def reset_password_page(token: str):
    return f"""
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Reset Password – FitTrack</title>
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{ font-family: -apple-system, sans-serif; background: #F5F6FA;
           display: flex; align-items: center; justify-content: center;
           min-height: 100vh; padding: 24px; }}
    .card {{ background: white; border-radius: 16px; padding: 32px;
             width: 100%; max-width: 400px;
             box-shadow: 0 4px 20px rgba(0,0,0,0.08); }}
    .logo {{ display: flex; align-items: center; gap: 10px;
             justify-content: center; margin-bottom: 24px; }}
    .icon {{ background: #2F73EA; border-radius: 12px; width: 48px;
             height: 48px; display: flex; align-items: center;
             justify-content: center; color: white; font-size: 22px; }}
    h1 {{ font-size: 22px; font-weight: 800; color: #0F1A3D;
          text-align: center; margin-bottom: 6px; }}
    p {{ color: #4A5C78; font-size: 14px; text-align: center;
         margin-bottom: 24px; }}
    label {{ font-size: 14px; font-weight: 600; color: #0F1A3D;
             display: block; margin-bottom: 6px; }}
    input {{ width: 100%; height: 48px; padding: 0 14px;
             border: 1px solid #E2E8F0; border-radius: 12px;
             font-size: 15px; margin-bottom: 16px; outline: none; }}
    input:focus {{ border-color: #2F73EA; }}
    button {{ width: 100%; height: 48px; background: #2F73EA; color: white;
              border: none; border-radius: 12px; font-size: 16px;
              font-weight: 700; cursor: pointer; }}
    button:disabled {{ opacity: 0.6; cursor: not-allowed; }}
    #msg {{ margin-top: 16px; text-align: center; font-size: 14px; }}
    .success {{ color: #16a34a; }}
    .error   {{ color: #dc2626; }}
  </style>
</head>
<body>
  <div class="card">
    <div class="logo">
      <div class="icon">&#9977;</div>
      <span style="font-size:20px;font-weight:800;color:#0F1A3D">FitTrack</span>
    </div>
    <h1>Reset Password</h1>
    <p>Enter your new password below.</p>

    <form id="form">
      <label>New Password</label>
      <input type="password" id="pw" placeholder="At least 8 characters" minlength="8" required>
      <label>Confirm Password</label>
      <input type="password" id="cpw" placeholder="Repeat password" minlength="8" required>
      <button type="submit" id="btn">Reset Password</button>
    </form>
    <div id="msg"></div>
  </div>

  <script>
    document.getElementById('form').addEventListener('submit', async (e) => {{
      e.preventDefault();
      const pw  = document.getElementById('pw').value;
      const cpw = document.getElementById('cpw').value;
      const msg = document.getElementById('msg');
      const btn = document.getElementById('btn');

      if (pw !== cpw) {{
        msg.className = 'error';
        msg.textContent = 'Passwords do not match.';
        return;
      }}

      btn.disabled = true;
      btn.textContent = 'Resetting...';

      try {{
        const res = await fetch('/auth/reset-password', {{
          method: 'POST',
          headers: {{ 'Content-Type': 'application/json' }},
          body: JSON.stringify({{
            token: '{token}',
            new_password: pw,
            confirm_password: cpw
          }})
        }});
        const data = await res.json();
        if (res.ok) {{
          msg.className = 'success';
          msg.textContent = '✓ Password updated! Return to the FitTrack app to log in.';
          document.getElementById('form').style.display = 'none';
        }} else {{
          msg.className = 'error';
          msg.textContent = data.detail || 'Something went wrong.';
          btn.disabled = false;
          btn.textContent = 'Reset Password';
        }}
      }} catch (_) {{
        msg.className = 'error';
        msg.textContent = 'Network error. Please try again.';
        btn.disabled = false;
        btn.textContent = 'Reset Password';
      }}
    }});
  </script>
</body>
</html>
"""