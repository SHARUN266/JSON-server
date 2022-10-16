const express = require("express");
const app = express();
require("./passport");
const authRoute = require("./routes/auth");
const cookieSession = require("cookie-session");
const mongoose = require("mongoose");
const UserModel = require("./User.Schema");
app.use(express.urlencoded({ extended: true }));
const jwt = require("jsonwebtoken");
var cors = require("cors");
const bcrypt=require("bcrypt")
const nodemailer=require('nodemailer')
const passport = require("passport");
const UserVarificationOTP = require("./UserOTP.Schema");
const router = require("./routes/auth");

// Making transpoter
let transporter=nodemailer.createTransport({
  host:"smtp.ethereal.email",
  port:587,
  auth:{
    user:"hailey.jacobson@ethereal.email",
    pass:"eGYcb5Sw6ezQN45Ae3",
  }
})
app.use(
  cors({
    origin: "http://localhost:3000",
    methods: "GET,POST,PUT,DELETE",
    credentials: true,
  })
);
app.use(express.json());
var refreshTokens = [];
app.post("/refresh", (req, res) => {
  //Take the refresh token from the user
  const token = req.body.token;

  if (!token) {
    return res.status(401).json("Your are not authanticated");
  }

  if (!refreshTokens.includes(token)) {
    return res.status(403).json("Refresh token is not valid");
  }

  jwt.verify(token, "SECRETREFRESH123456", (err, user) => {
    err && console.log(err);
    refreshTokens = refreshTokens.filter((t) => t !== token);
    const newAccessToken = GeneratingAccessToken(user);
    const newRefreshToken = GeneratingRefreshToken(user);
    refreshTokens.push(newRefreshToken);

    res.status(200).json({
      accessToken: newAccessToken,
      refreshToken: newRefreshToken,
    });
  });
  //Everything is ok ,create access token
});
// Routes Auth -> Sign up,SignIn
app.post("/sign", async (req, res, next) => {
  const { name, email, password } = req.body;
  console.log(name, email, password);
  const user = new UserModel({ name, email, password, role: "admin" });
  await user.save();

  res.send(user);
  next();
});
// Getting Token

const GeneratingAccessToken = (user) => {
  return jwt.sign(
    { name: user.name, email: user.email, id: user._id },
    "SECRET123456",
    {
      expiresIn: "5s",
    }
  );
};
const GeneratingRefreshToken = (user) => {
  return jwt.sign(
    { name: user.name, email: user.email, id: user._id },
    "SECRETREFRESH123456",
    {
      expiresIn: "6s",
    }
  );
};
app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await UserModel.findOne({ email, password });
  if (!user) {
    return res.send("Invalid user");
  } else {
    const accessToken = GeneratingAccessToken(user);
    const refreshToken = GeneratingRefreshToken(user);

    refreshTokens.push(refreshToken);
    res.send({ mesage: "Login success", accessToken, refreshToken });
  }
});
// Getting user by ID
app.get("/user/:id", async (req, res) => {
  const { id } = req.params;

  const token = req.headers["authorization"];
  if (!token) {
    return res.status(401).send("Unathorized");
  }

  try {
    const varification = jwt.verify(token, "SECRET1234");
    console.log(varification);
    const user = await UserModel.findById(id);
    return res.send(user);
  } catch (e) {
    return res.status(401).send("Token invalid");
  }
});
// Use Session Cokkies
app.use(
  cookieSession({
    name: "session",
    keys: ["Sharun@123456"],
    maxAge: 24 * 60 * 60 * 100,
  })
);
app.use("/auth", authRoute);

app.use(passport.initialize());
app.use(passport.session());

// Login with git hub
// 4e6c05391e2d3efc3054ecd60913014b75be1d48
// id f677b7796bcb311cd15a

app.get("/github/callback", (req, res) => {
  res.redirect("http://localhost:3000/login");
});

// Send OTP Email
app.post("/resetPassword",(req,res)=>{
  let {email}=req.body;
  UserModel.find({email}).then((data)=>{
    console.log(data,"me data")
    
      
        //user exist
        if(data[0].email!==email){
          res.json({
            status:"FAILED",
            message:"Email hasn't been verified yet.Check your inbox"
          })
        }else{
          let OTP= Math.floor(1000 + Math.random() * 9000)
    
          sendResetEmail(data[0],OTP,res)
        }
       
  }).catch((err)=>{
    console.log(err)
    res.json({
      status:"FAILED",
      message:"An error occured while checking for existing user"
    })
  })

  
})

// send password reset email
const sendResetEmail=(({_id,email,name},OTP,res)=>{
  
  const resetString=(_id).toString();
  // First, we clear all existing reset records
  UserVarificationOTP.deleteMany({userId:_id}).then(result=>{
    
    const mailOption={
      from :"hailey.jacobson@ethereal.email",
      to:email,
      subject:"Otp for Reset",
      html:`<div style="font-family: Helvetica,Arial,sans-serif;min-width:1000px;overflow:auto;line-height:2">
      <div style="margin:50px auto;width:70%;padding:20px 0">
        <div style="border-bottom:1px solid #eee">
          <a href="" style="font-size:1.4em;color: #00466a;text-decoration:none;font-weight:600">My Blogs</a>
        </div>
        <p style="font-size:1.1em">Hi,${name}</p>
        <p>Thank you for choosing My Blogs. Use the following OTP to complete your Sign Up procedures. OTP is valid for 5 minutes</p>
        <h2 style="background: #00466a;margin: 0 auto;width: max-content;padding: 0 10px;color: #fff;border-radius: 4px;">${OTP} </h2>
        <b>or <a  href=${"http://localhost:3000/updatepassword/"+_id}>Click</a></b>
        <p style="font-size:0.9em;">Regards,<br />Sharun</p>
        <hr style="border:none;border-top:1px solid #eee" />
        <div style="float:right;padding:8px 0;color:#aaa;font-size:0.8em;line-height:1;font-weight:300">
          <p>Your Brand Inc</p>
          <p>1600 Amphitheatre Parkway</p>
          <p>California</p>
        </div>
      </div>
    </div>`
    }

    // hash saltRounds
    const saltRounds=10;
   bcrypt.hash(resetString,saltRounds).then(hashResetString=>{
   
    const newPasswordReset=new UserVarificationOTP({
      userId:_id,
      otp:OTP,
      createdAt:Date.now(),
      expireAt:Date.now()+36000000000
    })
    newPasswordReset.save().then(()=>{
      transporter.sendMail(mailOption).then(()=>{
        // reset email sent ans reset record saved
       
        res.json({
         status:"PENDING",
         message:"Password reset email sent"
        })

      }).catch((err)=>{
        console.log(err);
        res.json({
          status:"FAILED",
          message:"A error occured"
        })
       })
    }).catch((err)=>{
      res.json({
        status:"FAILED",
        message:"An error occured while checking for existing user"
      })
    })
   })
  }).catch((err)=>{
    console.log(err);
    res.json({
      status:"FAILED",
      message:"clearing data"
    })
  })

})
// Update password here!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!


app.post("/updatepassword",(req,res)=>{
  let {userId,newPassword,confirmPassword,foamOtp}=req.body;
 
  UserVarificationOTP.findOne({userId}).then((result)=>{
    console.log(result,"grfgegeer")
      const {expireAt,otp}=result;
    //  const hanshResetString=res[0].resetString
     if(expireAt<Date.now()){
      UserVarificationOTP.deleteOne({userId}).then( ()=>{

        res.json({
          status:"FAILED",
          message:"Reset Link expired"
        })

      }
        // Reset record deleted successfully

      ).catch((err)=>{
        console.log(err)
        res.json({
          status:"FAILED",
          message:"Clearing password reset record failed"
        })
      })
     }else {
      if(foamOtp===otp){
        if(newPassword==confirmPassword){
          console.log(userId)
          UserModel.updateOne({userId},{password:newPassword},{multi:false}).then((result)=>{
            

              UserVarificationOTP.deleteOne({userId})
              res.json("Successfull")
      }).catch((err)=>{
        console.log(err)
        res.json({
                status:"FAILED",
                message:"Clearing password reset record failed"
         })
      })
        }else{
          res.json("Password doesn't matched")
        }
      
      }else{
        console.log("otp not match")
        res.json("OTP doesn't match")
      }
   
  }).catch((err)=>{
    console.log(err)
    res.json({
      status:"FAILED",
      message:"An error occured while checking sharun for existing user"
    })
  })

})

app.post("/getUser",(req,res)=>{
  const {email}=req.body;

    UserModel.findOne({email}).then((data)=>{
         console.log(data)
         res.send(data)
    }).catch((err)=>{
      res.json("failed")
    })
})



mongoose.connect("mongodb://127.0.0.1:27017/Jwt").then(() => {
  app.listen(8080, () => {
    console.log("Backend srver is running");
  });
});
