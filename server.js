// ===============================
// CONFIGURAÇÃO INICIAL
// ===============================
require("dotenv").config()
const express = require("express")
const mongoose = require("mongoose")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")
const stripe = require("stripe")(process.env.STRIPE_SECRET)
const cors = require("cors")

const app = express()
app.use(express.json())
app.use(cors())

// ===============================
// BANCO DE DADOS
// ===============================
mongoose.connect(process.env.MONGO_URI)
.then(()=> console.log("Banco conectado"))
.catch(err=> console.log(err))

// ===============================
// MODEL
// ===============================
const UserSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,
  role: { type: String, default: "user" },
  subscriptionActive: { type: Boolean, default: false }
})

const User = mongoose.model("User", UserSchema)

// ===============================
// MIDDLEWARE AUTH
// ===============================
function auth(req,res,next){
  const token = req.headers.authorization
  if(!token) return res.status(401).json("Sem token")

  try{
    const verified = jwt.verify(token, process.env.JWT_SECRET)
    req.user = verified
    next()
  }catch{
    res.status(400).json("Token inválido")
  }
}

// ===============================
// ROTAS AUTH
// ===============================
app.post("/api/register", async (req,res)=>{
  const hash = await bcrypt.hash(req.body.password,10)
  const user = await User.create({...req.body,password:hash})
  res.json(user)
})

app.post("/api/login", async (req,res)=>{
  const user = await User.findOne({email:req.body.email})
  if(!user) return res.status(400).json("Usuário não encontrado")

  const valid = await bcrypt.compare(req.body.password,user.password)
  if(!valid) return res.status(400).json("Senha inválida")

  const token = jwt.sign({id:user._id},process.env.JWT_SECRET)
  res.json({token,user})
})

// ===============================
// STRIPE ASSINATURA
// ===============================
app.post("/api/checkout", async (req,res)=>{
  const session = await stripe.checkout.sessions.create({
    payment_method_types: ["card"],
    mode: "subscription",
    line_items: [{
      price: process.env.STRIPE_PRICE_ID,
      quantity: 1
    }],
    success_url: "http://localhost:5000/dashboard",
    cancel_url: "http://localhost:5000"
  })

  res.json({url:session.url})
})

// ===============================
// DASHBOARD PROTEGIDO
// ===============================
app.get("/dashboard", auth, (req,res)=>{
  res.send(`
    <h1>Bem-vindo ao Dashboard 🔥</h1>
    <p>Usuário autenticado com sucesso.</p>
  `)
})

// ===============================
// FRONTEND INTEGRADO
// ===============================
app.get("/", (req,res)=>{
  res.send(`
  <html>
  <head>
  <title>Ultra Premium App</title>
  <style>
    body{margin:0;font-family:sans-serif;background:#0f0f0f;color:white;text-align:center}
    header{padding:40px}
    button{
      padding:15px 30px;
      border:none;
      background:linear-gradient(45deg,#6a00ff,#00f0ff);
      color:white;
      font-size:18px;
      border-radius:10px;
      cursor:pointer;
      transition:0.3s;
    }
    button:hover{transform:scale(1.1)}
  </style>
  </head>
  <body>

  <header>
    <h1>🚀 Ultra Startup Platform</h1>
    <button onclick="window.location='/login'">Entrar</button>
  </header>

  </body>
  </html>
  `)
})

// ===============================
// LOGIN PAGE
// ===============================
app.get("/login",(req,res)=>{
  res.send(`
  <html>
  <body style="background:#111;color:white;text-align:center">
  <h2>Login</h2>
  <input id="email" placeholder="Email"/><br/><br/>
  <input id="password" type="password" placeholder="Senha"/><br/><br/>
  <button onclick="login()">Entrar</button>

  <script>
  async function login(){
    const res = await fetch('/api/login',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({
        email:document.getElementById('email').value,
        password:document.getElementById('password').value
      })
    })

    const data = await res.json()
    localStorage.setItem("token",data.token)
    window.location="/dashboard"
  }
  </script>

  </body>
  </html>
  `)
})

// ===============================
app.listen(5000,()=>console.log("Servidor rodando em http://localhost:5000"))