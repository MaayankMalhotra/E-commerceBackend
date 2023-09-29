const jwt = require('jsonwebtoken');
const express=require("express");
const app=express();
const mongoose=require('mongoose');
const bcrypt=require('bcrypt');const crypto = require('crypto');

// Generate a random JWT secret key
// const JWT_SECRET = crypto.randomBytes(32).toString('hex');
// console.log(JWT_SECRET);
const JWT_SECRET ="a074c3a96626892e213316b75e2c59de303c47a9fbfbc0b7a3c72001d6c82074"

app.use(express.json());//actual body parser

function verifyToken(req, res, next) {
    const token = req.header('Authorization');
  
    if (!token) {
      return res.status(401).json({ error: 'Access denied. No token provided' });
    }
  
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      console.log(decoded)
      req.user = decoded; 
      next(); 
    } catch (error) {
      res.status(400).json({ error: 'Invalid token' });
    }
  }
  

const DB=mongoose.connect("mongodb://localhost:27017/User");
if(!DB)
{
    console.log('unable to connect');
}else{
    console.log('connection successfull');
}

const UserSchema=mongoose.Schema({
    firstName : String,
    lastName : String,
    email : {type:String,
            unique:true,},
    password : String,

})

const User=mongoose.model("User",UserSchema);

app.post('/register',async(req,res)=>{

   try{
    const {firstName,lastName,email,password} = req.body;
    
    const existingUser = await User.findOne({email});
    if (existingUser) {
        // If a user with the same username exists, return an error
        return res.status(400).json({ error: 'Username already taken' });
      }
    
    const hashPass=await bcrypt.hash(password,10);
    
    let result=new User({firstName:firstName,
        lastName:lastName,
        email:email,
        password:hashPass} );

    await result.save();
    console.log(result._id);
     
     const token = jwt.sign({ userId: result._id }, JWT_SECRET, {
      expiresIn: '1h', 
    });
    res.json({ message: 'Registration successful', token });
   }catch(error){
    console.error(error);
    res.status(500).json({ error: 'Failed toregister users' });


   }

})


app.post("/login",async(req,res)=>{

   const {email,password}=req.body;
   const user = await User.findOne({email});
   if(!user){
    res.json("no user exist with given email");
   }
   //  console.log(user);

   const check= await bcrypt.compare(password,user.password)
//    console.log(check)
   if(!check){
    res.json("invalid credentials");
   }
   const token = jwt.sign({ userId: user._id }, JWT_SECRET, {
    expiresIn: '1h', // Token expiration time
  });

  res.json({ message: 'Login successful', token });

})
app.delete("/:userid",async(req,res)=>{
    const userid = req.params.userId;
    
    const del=await User.findOneAndRemove(userid);
    if (!del) {
        return res.status(404).json({ error: 'User not found' });
      }

      res.json({message:"successfully deleted"})
    
   
})

app.get("/" ,verifyToken, async(req,res)=>{
    

    const users=await User.find();
    const withoutPassword=users.map((user)=>{
    const {firstName,lastName,email}=user;
    return{firstName,lastName,email}
    }) 
    res.json(withoutPassword);
})


app.listen(3000,()=>console.log("server listenig on port 3000"));

