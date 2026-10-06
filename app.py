import base64, hashlib, os, re, sqlite3
from datetime import datetime, timezone
from functools import wraps
import pyotp
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask import Flask, flash, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash, generate_password_hash

app=Flask(__name__)
app.secret_key=os.environ.get("FLASK_SECRET_KEY","development-only-change-me")
DB=os.environ.get("PII_DB","pii_secure.db")
MASTER=os.environ.get("PII_MASTER_KEY","development-master-key")
PATTERNS={
"email":re.compile(r"\b[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}\b"),
"phone":re.compile(r"\b(?:\+91[- ]?)?[6-9]\d{9}\b"),
"ipv4":re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
"mac":re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b"),
"pan":re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"),
"aadhaar":re.compile(r"\b\d{4}[ -]?\d{4}[ -]?\d{4}\b"),
"employee_id":re.compile(r"\bEMP[- ]?\d{3,10}\b",re.I),
}
def key_bytes(): return hashlib.sha256(MASTER.encode()).digest()
def encrypt(value):
    nonce=os.urandom(12); ct=AESGCM(key_bytes()).encrypt(nonce,value.encode(),None); return base64.b64encode(nonce+ct).decode()
def decrypt(value):
    raw=base64.b64decode(value); return AESGCM(key_bytes()).decrypt(raw[:12],raw[12:],None).decode()
def detect(text): return sorted(k for k,p in PATTERNS.items() if p.search(text))
def mask(text):
    for p in PATTERNS.values(): text=p.sub(lambda m: m.group(0)[:2]+"*"*max(0,len(m.group(0))-4)+m.group(0)[-2:] if len(m.group(0))>4 else "*"*len(m.group(0)),text)
    return text
def audit(action,user):
    with db() as c: c.execute("INSERT INTO audit(action,username,timestamp) VALUES(?,?,?)",(action,user,datetime.now(timezone.utc).isoformat())); c.commit()
def db():
    c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def required(fn):
    @wraps(fn)
    def w(*a,**kw): return fn(*a,**kw) if "username" in session else redirect(url_for("login"))
    return w
def init_db():
    with db() as c:
        c.execute("CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY,username TEXT UNIQUE,password TEXT,role TEXT,totp_secret TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS records(id INTEGER PRIMARY KEY,owner TEXT,ciphertext TEXT,pii_types TEXT,digest TEXT,created_at TEXT)")
        c.execute("CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY,action TEXT,username TEXT,timestamp TEXT)")
        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0]==0:
            s=pyotp.random_base32(); c.execute("INSERT INTO users(username,password,role,totp_secret) VALUES(?,?,?,?)",("admin",generate_password_hash("ChangeMe123!"),"Admin",s)); c.commit(); print("Demo admin TOTP secret:",s)
@app.route("/")
def home(): return redirect(url_for("dashboard") if "username" in session else url_for("login"))
@app.route("/login",methods=["GET","POST"])
def login():
    if request.method=="POST":
        u=request.form.get("username","").strip(); pw=request.form.get("password",""); otp=request.form.get("otp","")
        with db() as c: user=c.execute("SELECT * FROM users WHERE username=?",(u,)).fetchone()
        if user and check_password_hash(user["password"],pw) and pyotp.TOTP(user["totp_secret"]).verify(otp): session["username"]=u; session["role"]=user["role"]; audit("LOGIN_SUCCESS",u); return redirect(url_for("dashboard"))
        flash("Invalid credentials or MFA code.")
    return render_template("login.html")
@app.route("/logout")
def logout(): audit("LOGOUT",session.get("username","unknown")); session.clear(); return redirect(url_for("login"))
@app.route("/dashboard")
@required
def dashboard():
    with db() as c: rows=c.execute("SELECT * FROM records ORDER BY id DESC").fetchall()
    privileged=session["role"] in {"Admin","HR","SOC Analyst"}; records=[]
    for r in rows:
        value=decrypt(r["ciphertext"]); records.append({"id":r["id"],"owner":r["owner"],"value":value if privileged else mask(value),"pii_types":r["pii_types"],"digest":r["digest"][:16]+"..."})
    return render_template("dashboard.html",records=records,role=session["role"])
@app.route("/add",methods=["POST"])
@required
def add():
    value=request.form.get("value","").strip()
    if not value: flash("Enter data to protect."); return redirect(url_for("dashboard"))
    with db() as c: c.execute("INSERT INTO records(owner,ciphertext,pii_types,digest,created_at) VALUES(?,?,?,?,?)",(session["username"],encrypt(value),",".join(detect(value)),hashlib.sha256(value.encode()).hexdigest(),datetime.now(timezone.utc).isoformat())); c.commit()
    audit("PII_RECORD_CREATED",session["username"]); flash("Record encrypted and stored."); return redirect(url_for("dashboard"))
if __name__=="__main__": init_db(); app.run(host="127.0.0.1",port=5000,debug=False)
