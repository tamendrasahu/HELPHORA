const express = require("express");
const cors = require("cors");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const { v4: uuidv4 } = require("uuid");
const path = require("path");
const PDFDocument = require("pdfkit");

const app = express();
const PORT = 5000;
const JWT_SECRET = "supersecretkey";

// ---------------- Middleware ----------------
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public"))); // Serve frontend

// ---------------- In-memory storage ----------------
let users = []; // {id, fullName, email, phone, passwordHash, isAdmin}
let needs = []; // {id, type, description, submittedBy, status, createdAt}

// ---------------- Helper ----------------
function authMiddleware(req, res, next){
  const token = req.headers.authorization?.split(" ")[1] || req.query.token;
  if(!token) return res.status(401).json({message:"Unauthorized"});
  try{
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch(e){
    res.status(401).json({message:"Invalid token"});
  }
}

// ---------------- REGISTER ----------------
app.post("/api/register", async (req,res)=>{
  const {fullName,email,phone,password} = req.body;
  if(users.find(u=>u.email===email || u.phone===phone)){
    return res.status(400).json({message:"User already exists"});
  }
  const passwordHash = await bcrypt.hash(password,10);
  const user = {id:uuidv4(), fullName,email,phone,passwordHash, isAdmin:false};
  users.push(user);
  res.json({message:"Registered successfully"});
});

// ---------------- LOGIN ----------------
app.post("/api/login", async (req,res)=>{
  const {identifier,password} = req.body;
  const user = users.find(u=>u.email===identifier || u.phone===identifier);
  if(!user) return res.status(400).json({message:"User not found"});
  const valid = await bcrypt.compare(password,user.passwordHash);
  if(!valid) return res.status(400).json({message:"Incorrect password"});
  const token = jwt.sign({id:user.id, fullName:user.fullName, isAdmin:user.isAdmin}, JWT_SECRET, {expiresIn:"1h"});
  res.json({user:{id:user.id, fullName:user.fullName, isAdmin:user.isAdmin}, token});
});

// ---------------- SUBMIT NEED ----------------
app.post("/api/needs", authMiddleware, (req,res)=>{
  if (req.user.isAdmin) {
    return res.status(403).json({message:"Admins cannot submit needs"});
  }
  const {type,description,submittedBy} = req.body;
  if(!type || !description) return res.status(400).json({message:"All fields required"});
  const need = {
    id:uuidv4(),
    type,
    description,
    submittedBy,
    status:'pending',
    createdAt: new Date().toISOString()
  };
  needs.push(need);
  res.json({message:"Need submitted successfully"});
});

// ---------------- GET ALL NEEDS ----------------
app.get("/api/needs", authMiddleware, (req,res)=>{
  res.json(needs);
});

// ---------------- APPROVE NEED ----------------
app.put("/api/needs/:id/approve", authMiddleware, (req,res)=>{
  const {approved} = req.body;
  if(!req.user.isAdmin) return res.status(403).json({message:"Forbidden"});
  const need = needs.find(n=>n.id===req.params.id);
  if(!need) return res.status(404).json({message:"Need not found"});
  if(approved) need.status='approved';
  res.json({message:"Need updated"});
});

// ---------------- EXPORT NEEDS PDF (Admin only) ----------------
app.get("/api/needs/export/pdf", authMiddleware, (req,res)=>{
  if (!req.user.isAdmin) {
    return res.status(403).json({message:"Forbidden"});
  }

  const doc = new PDFDocument();
  res.setHeader("Content-Type", "application/pdf");
  res.setHeader("Content-Disposition", "attachment; filename=needs.pdf");
  doc.pipe(res);

  doc.fontSize(18).text("HELPHORA - All Needs", {align:"center"});
  doc.moveDown();

  if (needs.length === 0) {
    doc.fontSize(12).text("No needs submitted yet.", {align:"left"});
  } else {
    needs.forEach((n, i) => {
      doc.fontSize(12).text(
        `${i+1}. [${n.type}] ${n.description}\nSubmitted by: ${n.submittedBy}\nStatus: ${n.status}\nDate: ${new Date(n.createdAt).toLocaleString()}\n`
      );
      doc.moveDown();
    });
  }

  doc.end();
});

// ---------------- Start Server ----------------
app.listen(PORT,()=>console.log(`Server running at http://localhost:${PORT}`));

// ---------------- Default admin ----------------
(async()=>{
  if(!users.find(u=>u.email==='admin@helphora.com')){
    const passwordHash = await bcrypt.hash('admin123',10);
    users.push({id:uuidv4(), fullName:'Admin', email:'admin@helphora.com', phone:'+1000000000', passwordHash, isAdmin:true});
    console.log("Default admin created: admin@helphora.com / admin123");
  }
})();
