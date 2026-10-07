from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from typing import Optional
from datetime import datetime, timezone, timedelta, date
from pathlib import Path
import sqlite3, hashlib, secrets, re, json

ROOT = Path(__file__).resolve().parent.parent
DB = Path(__file__).resolve().parent / "acxiomcrm.db"

app = FastAPI(title="AcxiomCRM API", version="2.0.0")
app.mount("/static", StaticFiles(directory=str(ROOT / "frontend")), name="static")
SESSIONS = {}
SESSION_HOURS = 8
ROLES = ("Admin", "Manager", "Sales Executive")
LEAD_STATUSES = ("New","Contacted","Qualified","Unqualified","Converted","Lost")
OPP_STAGES = ("Qualification","Proposal","Negotiation","Won","Lost")
FOLLOWUP_STATUSES = ("Planned","Completed","Missed","Cancelled")

def utcnow():
    return datetime.now(timezone.utc)

def iso():
    return utcnow().isoformat()

def conn():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1, dklen=64)
    return salt.hex() + "$" + digest.hex()

def verify_password(password, stored):
    try:
        salt, digest = stored.split("$", 1)
        expected = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt),
                                  n=16384, r=8, p=1, dklen=64).hex()
        return secrets.compare_digest(expected, digest)
    except Exception:
        return False

def valid_password(p):
    return bool(re.fullmatch(r"(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[^A-Za-z0-9]).{8,64}", p))

def valid_email(e):
    return bool(re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", e or ""))

def audit(user_id, action, module, record_id="", result="Success", metadata=""):
    c = conn()
    c.execute("""INSERT INTO audit_logs(user_id,timestamp,action,module,record_id,result,metadata)
                 VALUES(?,?,?,?,?,?,?)""",
              (user_id, iso(), action, module, str(record_id), result, metadata))
    c.commit(); c.close()

def init_db():
    c = conn()
    c.executescript("""
    CREATE TABLE IF NOT EXISTS users(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL UNIQUE,
      password_hash TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('Admin','Manager','Sales Executive')),
      active INTEGER NOT NULL DEFAULT 1,
      failed_attempts INTEGER NOT NULL DEFAULT 0,
      locked_until TEXT
    );
    CREATE TABLE IF NOT EXISTS customers(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT NOT NULL,
      company TEXT NOT NULL DEFAULT '',
      owner_id INTEGER NOT NULL REFERENCES users(id),
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS leads(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      email TEXT NOT NULL,
      phone TEXT NOT NULL DEFAULT '',
      source TEXT NOT NULL DEFAULT '',
      status TEXT NOT NULL,
      priority TEXT NOT NULL DEFAULT 'Medium',
      owner_id INTEGER NOT NULL REFERENCES users(id),
      notes TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS opportunities(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      customer_id INTEGER NOT NULL REFERENCES customers(id),
      owner_id INTEGER NOT NULL REFERENCES users(id),
      stage TEXT NOT NULL,
      amount REAL NOT NULL CHECK(amount > 0),
      probability REAL NOT NULL CHECK(probability >= 0 AND probability <= 100),
      expected_close TEXT NOT NULL,
      source TEXT NOT NULL DEFAULT '',
      notes TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS followups(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      subject TEXT NOT NULL,
      type TEXT NOT NULL,
      status TEXT NOT NULL,
      due_date TEXT NOT NULL,
      customer_id INTEGER REFERENCES customers(id),
      lead_id INTEGER REFERENCES leads(id),
      opportunity_id INTEGER REFERENCES opportunities(id),
      assigned_user_id INTEGER NOT NULL REFERENCES users(id),
      notes TEXT NOT NULL DEFAULT '',
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS audit_logs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER REFERENCES users(id),
      timestamp TEXT NOT NULL,
      action TEXT NOT NULL,
      module TEXT NOT NULL,
      record_id TEXT,
      result TEXT NOT NULL,
      metadata TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_customers_owner ON customers(owner_id);
    CREATE INDEX IF NOT EXISTS idx_leads_owner ON leads(owner_id);
    CREATE INDEX IF NOT EXISTS idx_opp_owner ON opportunities(owner_id);
    CREATE INDEX IF NOT EXISTS idx_followup_assignee ON followups(assigned_user_id);
    """)
    if c.execute("SELECT COUNT(*) n FROM users").fetchone()["n"] == 0:
        for name,email,pw,role in [
            ("Administrator","admin@acxiomcrm.local","Admin@123","Admin"),
            ("CRM Manager","manager@acxiomcrm.local","Manager@123","Manager"),
            ("Sales Executive","sales@acxiomcrm.local","Sales@123","Sales Executive")]:
            c.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                      (name,email,hash_password(pw),role))
    c.commit(); c.close()

def user_from_request(request: Request):
    token = request.cookies.get("acxiom_session")
    if not token or token not in SESSIONS:
        raise HTTPException(401, "Authentication required")
    uid, expires = SESSIONS[token]
    if utcnow() >= expires:
        SESSIONS.pop(token, None)
        raise HTTPException(401, "Session expired")
    c=conn(); u=c.execute("SELECT * FROM users WHERE id=? AND active=1",(uid,)).fetchone(); c.close()
    if not u: raise HTTPException(401,"Authentication required")
    return u

def require_role(u, *roles):
    if u["role"] not in roles:
        raise HTTPException(403, "Not authorized for this role")

def can_access_owner(u, owner_id):
    return u["role"] in ("Admin","Manager") or int(owner_id) == int(u["id"])

class Login(BaseModel):
    email: str
    password: str

class Register(BaseModel):
    name: str = Field(min_length=2, max_length=100)
    email: str
    password: str
    role: str = "Sales Executive"

class CustomerIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str
    phone: str = Field(min_length=7, max_length=25)
    company: str = Field(default="", max_length=120)

class LeadIn(BaseModel):
    name: str = Field(min_length=2, max_length=120)
    email: str
    phone: str = ""
    source: str = ""
    status: str = "New"
    priority: str = "Medium"
    owner_id: Optional[int] = None
    notes: str = ""

class OpportunityIn(BaseModel):
    name: str = Field(min_length=2, max_length=150)
    customer_id: int
    stage: str
    amount: float = Field(gt=0)
    probability: float = Field(ge=0, le=100)
    expected_close: str
    source: str = ""
    notes: str = ""

class FollowUpIn(BaseModel):
    subject: str = Field(min_length=2, max_length=150)
    type: str
    status: str = "Planned"
    due_date: str
    customer_id: Optional[int] = None
    lead_id: Optional[int] = None
    opportunity_id: Optional[int] = None
    assigned_user_id: Optional[int] = None
    notes: str = ""

init_db()

@app.get("/")
def home():
    return FileResponse(ROOT / "frontend" / "index.html")

@app.post("/api/auth/login")
def login(data: Login, response: Response):
    c=conn(); u=c.execute("SELECT * FROM users WHERE lower(email)=lower(?)",(data.email.strip(),)).fetchone()
    if not u:
        c.close(); audit(None,"LOGIN_FAILED","Authentication","","Failure","unknown user")
        raise HTTPException(401,"Invalid credentials")
    if u["locked_until"] and u["locked_until"] > iso():
        c.close(); raise HTTPException(423,"Account temporarily locked")
    if not verify_password(data.password,u["password_hash"]):
        attempts=u["failed_attempts"]+1
        locked=(utcnow()+timedelta(minutes=15)).isoformat() if attempts>=5 else None
        c.execute("UPDATE users SET failed_attempts=?,locked_until=? WHERE id=?",(attempts,locked,u["id"]))
        c.commit(); c.close()
        audit(u["id"],"LOGIN_FAILED","Authentication",u["id"],"Failure","invalid password")
        raise HTTPException(401,"Invalid credentials")
    c.execute("UPDATE users SET failed_attempts=0,locked_until=NULL WHERE id=?",(u["id"],))
    c.commit(); c.close()
    token=secrets.token_urlsafe(32)
    SESSIONS[token]=(u["id"],utcnow()+timedelta(hours=SESSION_HOURS))
    response.set_cookie("acxiom_session",token,httponly=True,samesite="lax",max_age=SESSION_HOURS*3600,path="/")
    audit(u["id"],"LOGIN_SUCCESS","Authentication",u["id"])
    return {"user":{"id":u["id"],"name":u["name"],"email":u["email"],"role":u["role"]}}

@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    u=user_from_request(request)
    token=request.cookies.get("acxiom_session"); SESSIONS.pop(token,None)
    response.delete_cookie("acxiom_session",path="/")
    audit(u["id"],"LOGOUT","Authentication",u["id"])
    return {"message":"Logged out"}

@app.get("/api/me")
def me(request: Request):
    u=user_from_request(request)
    return {"id":u["id"],"name":u["name"],"email":u["email"],"role":u["role"]}

@app.post("/api/users")
def create_user(data:Register, request:Request):
    u=user_from_request(request); require_role(u,"Admin")
    if data.role not in ROLES: raise HTTPException(400,"Invalid role")
    if not valid_email(data.email): raise HTTPException(400,"Invalid email")
    if not valid_password(data.password): raise HTTPException(400,"Password must contain upper, lower, number, special character and be 8-64 characters")
    c=conn()
    try:
        cur=c.execute("INSERT INTO users(name,email,password_hash,role) VALUES(?,?,?,?)",
                      (data.name,data.email.lower(),hash_password(data.password),data.role))
        c.commit(); uid=cur.lastrowid
    except sqlite3.IntegrityError:
        c.close(); raise HTTPException(409,"Email already exists")
    c.close(); audit(u["id"],"CREATE","User",uid); return {"id":uid}

@app.get("/api/users")
def list_users(request:Request):
    u=user_from_request(request); require_role(u,"Admin")
    c=conn(); rows=[dict(x) for x in c.execute("SELECT id,name,email,role,active FROM users ORDER BY id").fetchall()]; c.close()
    return rows

@app.put("/api/users/{uid}")
def update_user(uid:int, data:Register, request:Request):
    u=user_from_request(request); require_role(u,"Admin")
    if data.role not in ROLES or not valid_email(data.email): raise HTTPException(400,"Invalid user data")
    c=conn(); row=c.execute("SELECT id FROM users WHERE id=?",(uid,)).fetchone()
    if not row: c.close(); raise HTTPException(404,"User not found")
    if data.password and not valid_password(data.password): c.close(); raise HTTPException(400,"Invalid password policy")
    if data.password:
        c.execute("UPDATE users SET name=?,email=?,role=?,password_hash=? WHERE id=?",
                  (data.name,data.email.lower(),data.role,hash_password(data.password),uid))
    else:
        c.execute("UPDATE users SET name=?,email=?,role=? WHERE id=?",
                  (data.name,data.email.lower(),data.role,uid))
    c.commit(); c.close(); audit(u["id"],"UPDATE","User",uid); return {"message":"Updated"}

@app.get("/api/dashboard")
def dashboard(request:Request):
    u=user_from_request(request); c=conn()
    own = "" if u["role"] in ("Admin","Manager") else f" AND owner_id={u['id']}"
    fown = "" if u["role"] in ("Admin","Manager") else f" AND assigned_user_id={u['id']}"
    customers=c.execute("SELECT COUNT(*) n FROM customers WHERE 1=1"+own).fetchone()["n"]
    leads=c.execute("SELECT COUNT(*) n FROM leads WHERE 1=1"+own).fetchone()["n"]
    opportunities=c.execute("SELECT COUNT(*) n FROM opportunities WHERE 1=1"+own).fetchone()["n"]
    pipeline=c.execute("SELECT COALESCE(SUM(amount*probability/100),0) x FROM opportunities WHERE stage NOT IN ('Won','Lost')"+own).fetchone()["x"]
    upcoming=c.execute("SELECT COUNT(*) n FROM followups WHERE status='Planned' AND due_date>=date('now')"+fown).fetchone()["n"]
    won=c.execute("SELECT COUNT(*) n FROM opportunities WHERE stage='Won'"+own).fetchone()["n"]
    lost=c.execute("SELECT COUNT(*) n FROM opportunities WHERE stage='Lost'"+own).fetchone()["n"]
    c.close()
    return {"customers":customers,"leads":leads,"opportunities":opportunities,
            "weighted_pipeline":round(pipeline,2),"upcoming_followups":upcoming,
            "won":won,"lost":lost}

@app.get("/api/customers")
def customers(request:Request, q:str=""):
    u=user_from_request(request); c=conn()
    sql="SELECT id,name,email,phone,company,owner_id,created_at FROM customers WHERE 1=1"; args=[]
    if u["role"]=="Sales Executive": sql+=" AND owner_id=?"; args.append(u["id"])
    if q: sql+=" AND (name LIKE ? OR email LIKE ? OR company LIKE ?)"; args += [f"%{q}%"]*3
    sql+=" ORDER BY id DESC"
    rows=[dict(x) for x in c.execute(sql,args).fetchall()]; c.close(); return rows

@app.post("/api/customers")
def create_customer(data:CustomerIn,request:Request):
    u=user_from_request(request)
    if not valid_email(data.email): raise HTTPException(400,"Invalid email")
    c=conn()
    if c.execute("SELECT id FROM customers WHERE lower(email)=lower(?)",(data.email,)).fetchone():
        c.close(); raise HTTPException(409,"Customer email already exists")
    cur=c.execute("""INSERT INTO customers(name,email,phone,company,owner_id,created_at)
                     VALUES(?,?,?,?,?,?)""",(data.name,data.email,data.phone,data.company,u["id"],iso()))
    c.commit(); cid=cur.lastrowid; c.close(); audit(u["id"],"CREATE","Customer",cid)
    return {"id":cid}

@app.put("/api/customers/{cid}")
def update_customer(cid:int,data:CustomerIn,request:Request):
    u=user_from_request(request); c=conn(); row=c.execute("SELECT * FROM customers WHERE id=?",(cid,)).fetchone()
    if not row: c.close(); raise HTTPException(404,"Customer not found")
    if not can_access_owner(u,row["owner_id"]): c.close(); raise HTTPException(403,"Not authorized")
    if not valid_email(data.email): c.close(); raise HTTPException(400,"Invalid email")
    c.execute("UPDATE customers SET name=?,email=?,phone=?,company=? WHERE id=?",
              (data.name,data.email,data.phone,data.company,cid)); c.commit(); c.close()
    audit(u["id"],"UPDATE","Customer",cid); return {"message":"Updated"}

@app.delete("/api/customers/{cid}")
def delete_customer(cid:int,request:Request):
    u=user_from_request(request); c=conn(); row=c.execute("SELECT * FROM customers WHERE id=?",(cid,)).fetchone()
    if not row: c.close(); raise HTTPException(404,"Customer not found")
    if not can_access_owner(u,row["owner_id"]): c.close(); raise HTTPException(403,"Not authorized")
    try:
        c.execute("DELETE FROM customers WHERE id=?",(cid,)); c.commit()
    except sqlite3.IntegrityError:
        c.close(); raise HTTPException(409,"Customer is referenced by another CRM record")
    c.close(); audit(u["id"],"DELETE","Customer",cid); return {"message":"Deleted"}

@app.get("/api/leads")
def leads(request:Request,q:str=""):
    u=user_from_request(request); c=conn(); sql="SELECT * FROM leads WHERE 1=1"; args=[]
    if u["role"]=="Sales Executive": sql+=" AND owner_id=?"; args.append(u["id"])
    if q: sql+=" AND (name LIKE ? OR email LIKE ? OR source LIKE ?)"; args += [f"%{q}%"]*3
    rows=[dict(x) for x in c.execute(sql+" ORDER BY id DESC",args).fetchall()]; c.close(); return rows

@app.post("/api/leads")
def create_lead(data:LeadIn,request:Request):
    u=user_from_request(request); owner=data.owner_id or u["id"]
    if data.status not in LEAD_STATUSES: raise HTTPException(400,"Invalid lead status")
    if u["role"]=="Sales Executive" and owner!=u["id"]: raise HTTPException(403,"Cannot assign another owner")
    if not valid_email(data.email): raise HTTPException(400,"Invalid email")
    c=conn()
    if not c.execute("SELECT id FROM users WHERE id=? AND active=1",(owner,)).fetchone(): c.close(); raise HTTPException(400,"Owner not found")
    cur=c.execute("""INSERT INTO leads(name,email,phone,source,status,priority,owner_id,notes,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?)""",
                  (data.name,data.email,data.phone,data.source,data.status,data.priority,owner,data.notes,iso()))
    c.commit(); lid=cur.lastrowid; c.close(); audit(u["id"],"CREATE","Lead",lid); return {"id":lid}

@app.put("/api/leads/{lid}")
def update_lead(lid:int,data:LeadIn,request:Request):
    u=user_from_request(request); c=conn(); row=c.execute("SELECT * FROM leads WHERE id=?",(lid,)).fetchone()
    if not row: c.close(); raise HTTPException(404,"Lead not found")
    if not can_access_owner(u,row["owner_id"]): c.close(); raise HTTPException(403,"Not authorized")
    owner=data.owner_id or row["owner_id"]
    if u["role"]=="Sales Executive" and owner!=u["id"]: c.close(); raise HTTPException(403,"Cannot reassign")
    if data.status not in LEAD_STATUSES: c.close(); raise HTTPException(400,"Invalid lead status")
    c.execute("""UPDATE leads SET name=?,email=?,phone=?,source=?,status=?,priority=?,owner_id=?,notes=? WHERE id=?""",
              (data.name,data.email,data.phone,data.source,data.status,data.priority,owner,data.notes,lid))
    c.commit(); c.close(); audit(u["id"],"UPDATE","Lead",lid,metadata=f"status={data.status}"); return {"message":"Updated"}

@app.post("/api/leads/{lid}/convert")
def convert_lead(lid:int,request:Request):
    u=user_from_request(request); c=conn(); lead=c.execute("SELECT * FROM leads WHERE id=?",(lid,)).fetchone()
    if not lead: c.close(); raise HTTPException(404,"Lead not found")
    if not can_access_owner(u,lead["owner_id"]): c.close(); raise HTTPException(403,"Not authorized")
    if lead["status"]=="Converted": c.close(); raise HTTPException(409,"Lead already converted")
    cur=c.execute("""INSERT INTO customers(name,email,phone,company,owner_id,created_at)
                     VALUES(?,?,?,?,?,?)""",(lead["name"],lead["email"],lead["phone"],"",lead["owner_id"],iso()))
    cid=cur.lastrowid
    c.execute("UPDATE leads SET status='Converted' WHERE id=?",(lid,)); c.commit(); c.close()
    audit(u["id"],"CONVERT","Lead",lid,metadata=f"customer_id={cid}")
    return {"customer_id":cid}

@app.get("/api/opportunities")
def opportunities(request:Request,q:str=""):
    u=user_from_request(request); c=conn()
    sql="""SELECT o.*, c.name customer_name FROM opportunities o
           JOIN customers c ON c.id=o.customer_id WHERE 1=1"""; args=[]
    if u["role"]=="Sales Executive": sql+=" AND o.owner_id=?"; args.append(u["id"])
    if q: sql+=" AND (o.name LIKE ? OR c.name LIKE ?)"; args += [f"%{q}%",f"%{q}%"]
    rows=[dict(x) for x in c.execute(sql+" ORDER BY o.id DESC",args).fetchall()]; c.close()
    for r in rows: r["weighted_pipeline"]=round(r["amount"]*r["probability"]/100,2)
    return rows

def validate_opp(data):
    if data.stage not in OPP_STAGES: raise HTTPException(400,"Invalid opportunity stage")
    if data.amount <= 0: raise HTTPException(400,"Amount must be greater than 0")
    if not 0 <= data.probability <= 100: raise HTTPException(400,"Probability must be 0-100")
    if data.stage not in ("Won","Lost") and data.expected_close < date.today().isoformat():
        raise HTTPException(400,"Active opportunity expected close cannot be in the past")

@app.post("/api/opportunities")
def create_opp(data:OpportunityIn,request:Request):
    u=user_from_request(request); validate_opp(data); c=conn()
    if not c.execute("SELECT id FROM customers WHERE id=?",(data.customer_id,)).fetchone():
        c.close(); raise HTTPException(400,"Customer does not exist")
    cur=c.execute("""INSERT INTO opportunities(name,customer_id,owner_id,stage,amount,probability,expected_close,source,notes,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?)""",
                  (data.name,data.customer_id,u["id"],data.stage,data.amount,data.probability,data.expected_close,data.source,data.notes,iso()))
    c.commit(); oid=cur.lastrowid; c.close(); audit(u["id"],"CREATE","Opportunity",oid); return {"id":oid}

@app.put("/api/opportunities/{oid}")
def update_opp(oid:int,data:OpportunityIn,request:Request):
    u=user_from_request(request); validate_opp(data); c=conn(); row=c.execute("SELECT * FROM opportunities WHERE id=?",(oid,)).fetchone()
    if not row: c.close(); raise HTTPException(404,"Opportunity not found")
    if not can_access_owner(u,row["owner_id"]): c.close(); raise HTTPException(403,"Not authorized")
    c.execute("""UPDATE opportunities SET name=?,customer_id=?,stage=?,amount=?,probability=?,expected_close=?,source=?,notes=? WHERE id=?""",
              (data.name,data.customer_id,data.stage,data.amount,data.probability,data.expected_close,data.source,data.notes,oid))
    c.commit(); c.close(); audit(u["id"],"UPDATE","Opportunity",oid,metadata=f"stage={data.stage}"); return {"message":"Updated"}

@app.delete("/api/opportunities/{oid}")
def delete_opp(oid:int,request:Request):
    u=user_from_request(request); c=conn(); row=c.execute("SELECT * FROM opportunities WHERE id=?",(oid,)).fetchone()
    if not row: c.close(); raise HTTPException(404,"Opportunity not found")
    if not can_access_owner(u,row["owner_id"]): c.close(); raise HTTPException(403,"Not authorized")
    c.execute("DELETE FROM opportunities WHERE id=?",(oid,)); c.commit(); c.close(); audit(u["id"],"DELETE","Opportunity",oid); return {"message":"Deleted"}

@app.get("/api/followups")
def followups(request:Request):
    u=user_from_request(request); c=conn()
    sql="""SELECT f.*, c.name customer_name, l.name lead_name, o.name opportunity_name, u.name assigned_name
           FROM followups f
           LEFT JOIN customers c ON c.id=f.customer_id
           LEFT JOIN leads l ON l.id=f.lead_id
           LEFT JOIN opportunities o ON o.id=f.opportunity_id
           JOIN users u ON u.id=f.assigned_user_id WHERE 1=1"""; args=[]
    if u["role"]=="Sales Executive": sql+=" AND f.assigned_user_id=?"; args.append(u["id"])
    rows=[dict(x) for x in c.execute(sql+" ORDER BY f.due_date,f.id DESC",args).fetchall()]; c.close(); return rows

@app.post("/api/followups")
def create_followup(data:FollowUpIn,request:Request):
    u=user_from_request(request); assigned=data.assigned_user_id or u["id"]
    if data.status not in FOLLOWUP_STATUSES: raise HTTPException(400,"Invalid follow-up status")
    if data.status=="Planned" and data.due_date < date.today().isoformat(): raise HTTPException(400,"Planned follow-up cannot be in the past")
    if not any((data.customer_id,data.lead_id,data.opportunity_id)): raise HTTPException(400,"Follow-up must reference a customer, lead or opportunity")
    if u["role"]=="Sales Executive" and assigned!=u["id"]: raise HTTPException(403,"Cannot assign another user")
    c=conn()
    if not c.execute("SELECT id FROM users WHERE id=? AND active=1",(assigned,)).fetchone(): c.close(); raise HTTPException(400,"Assigned user not found")
    cur=c.execute("""INSERT INTO followups(subject,type,status,due_date,customer_id,lead_id,opportunity_id,assigned_user_id,notes,created_at)
                     VALUES(?,?,?,?,?,?,?,?,?,?)""",
                  (data.subject,data.type,data.status,data.due_date,data.customer_id,data.lead_id,data.opportunity_id,assigned,data.notes,iso()))
    c.commit(); fid=cur.lastrowid; c.close(); audit(u["id"],"CREATE","FollowUp",fid); return {"id":fid}

@app.put("/api/followups/{fid}")
def update_followup(fid:int,data:FollowUpIn,request:Request):
    u=user_from_request(request); c=conn(); row=c.execute("SELECT * FROM followups WHERE id=?",(fid,)).fetchone()
    if not row: c.close(); raise HTTPException(404,"Follow-up not found")
    if not can_access_owner(u,row["assigned_user_id"]): c.close(); raise HTTPException(403,"Not authorized")
    if data.status not in FOLLOWUP_STATUSES: c.close(); raise HTTPException(400,"Invalid follow-up status")
    if data.status=="Planned" and data.due_date < date.today().isoformat(): c.close(); raise HTTPException(400,"Planned follow-up cannot be in the past")
    c.execute("""UPDATE followups SET subject=?,type=?,status=?,due_date=?,customer_id=?,lead_id=?,opportunity_id=?,notes=? WHERE id=?""",
              (data.subject,data.type,data.status,data.due_date,data.customer_id,data.lead_id,data.opportunity_id,data.notes,fid))
    c.commit(); c.close(); audit(u["id"],"UPDATE","FollowUp",fid,metadata=f"status={data.status}"); return {"message":"Updated"}

@app.get("/api/reports/pipeline")
def pipeline(request:Request):
    u=user_from_request(request); c=conn()
    sql="SELECT stage,COUNT(*) count,COALESCE(SUM(amount),0) amount,COALESCE(SUM(amount*probability/100),0) weighted FROM opportunities WHERE 1=1"; args=[]
    if u["role"]=="Sales Executive": sql+=" AND owner_id=?"; args.append(u["id"])
    rows=[dict(x) for x in c.execute(sql+" GROUP BY stage ORDER BY stage",args).fetchall()]; c.close()
    return rows

@app.get("/api/reports/conversion")
def conversion(request:Request):
    u=user_from_request(request); c=conn()
    sql="SELECT status,COUNT(*) count FROM leads WHERE 1=1"; args=[]
    if u["role"]=="Sales Executive": sql+=" AND owner_id=?"; args.append(u["id"])
    rows=[dict(x) for x in c.execute(sql+" GROUP BY status ORDER BY status",args).fetchall()]; c.close()
    return rows

@app.get("/api/reports/user-activity")
def user_activity(request:Request):
    u=user_from_request(request); require_role(u,"Admin","Manager")
    c=conn(); rows=[dict(x) for x in c.execute("""SELECT u.name,u.email,u.role,
       COUNT(a.id) activity_count FROM users u LEFT JOIN audit_logs a ON a.user_id=u.id
       GROUP BY u.id ORDER BY activity_count DESC""").fetchall()]; c.close(); return rows

@app.get("/api/audit")
def audit_report(request:Request):
    u=user_from_request(request); require_role(u,"Admin","Manager")
    c=conn(); rows=[dict(x) for x in c.execute("""SELECT a.id,a.timestamp,a.action,a.module,a.record_id,a.result,a.metadata,u.email
       FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 500""").fetchall()]; c.close(); return rows
