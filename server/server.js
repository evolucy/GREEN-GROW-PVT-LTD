require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bodyParser = require('body-parser');

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static('../public')); // serve frontend from public folder

// Connect to MongoDB
mongoose.connect(process.env.MONGO_URI || 'mongodb://localhost:27017/green-grow', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(()=> console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User model
const UserSchema = new mongoose.Schema({
  email: {type:String, required:true, unique:true},
  passwordHash: String,
  fullName: String,
  phone: String,
  country: String,
  city: String,
  zipCode: String,
  referralCode: String,      // code assigned to this user
  referredBy: String,        // code used while registering (sponsor)
  balance: {type:Number, default:0}, // commissions earned
  points: {type:Number, default:0},
  createdAt: {type:Date, default:Date.now}
});
const User = mongoose.model('User', UserSchema);

// utils
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// generate referral code
function genReferral() {
  return 'GG' + Math.random().toString(36).substring(2,8).toUpperCase();
}

// Register
app.post('/api/auth/register', async (req,res) => {
  try {
    const body = req.body;
    const { email, password, fullName, phone, country, city, zipCode, referralCode } = body;
    if(!email || !password) return res.status(400).json({error:'Email and password required'});

    // check exists
    const exists = await User.findOne({email});
    if(exists) return res.status(400).json({error:'Email already registered'});

    // hash
    const hash = await bcrypt.hash(password, 10);
    const userReferral = genReferral();

    const u = new User({
      email,
      passwordHash: hash,
      fullName, phone, country, city, zipCode,
      referralCode: userReferral,
      referredBy: referralCode || null
    });

    // if referredBy exists, credit sponsor commission (placeholder logic)
    if(referralCode){
      const sponsor = await User.findOne({referralCode});
      if(sponsor){
        // credit sponsor instantly as placeholder (in prod, credit only after payment success)
        sponsor.balance = (sponsor.balance || 0) + 1000; // ₹1,000 sponsor commission
        await sponsor.save();
      }
    }

    await u.save();

    // create JWT
    const token = jwt.sign({id:u._id, email:u.email}, process.env.JWT_SECRET || 'devsecret', {expiresIn:'7d'});
    return res.json({message:'Registered successfully', token, referralCode: userReferral});
  } catch(err){
    console.error(err);
    return res.status(500).json({error:'Server error'});
  }
});

// Login
app.post('/api/auth/login', async (req,res) => {
  try {
    const { email, password } = req.body;
    if(!email || !password) return res.status(400).json({error:'Email and password required'});

    const user = await User.findOne({email});
    if(!user) return res.status(400).json({error:'Invalid credentials'});

    const ok = await bcrypt.compare(password, user.passwordHash);
    if(!ok) return res.status(400).json({error:'Invalid credentials'});

    const token = jwt.sign({id:user._id, email:user.email}, process.env.JWT_SECRET || 'devsecret', {expiresIn:'7d'});
    return res.json({message:'Login successful', token});
  } catch(err){
    console.error(err);
    return res.status(500).json({error:'Server error'});
  }
});

// auth middleware
const auth = (req,res,next) => {
  const header = req.headers['authorization'];
  if(!header) return res.status(401).json({error:'No token'});
  const token = header.split(' ')[1];
  try {
    const data = jwt.verify(token, process.env.JWT_SECRET || 'devsecret');
    req.user = data;
    next();
  } catch(e){
    return res.status(401).json({error:'Invalid token'});
  }
};

// get profile
app.get('/api/user/me', auth, async (req,res) => {
  try {
    const user = await User.findById(req.user.id).select('-passwordHash');
    if(!user) return res.status(404).json({error:'User not found'});
    return res.json(user);
  } catch(err){
    console.error(err);
    return res.status(500).json({error:'Server error'});
  }
});

// placeholder payment endpoint (DO NOT use for real cards)
app.post('/api/payment/process', auth, async (req,res) => {
  // in production integrate Stripe/PayPal — never accept raw card data
  // this endpoint just simulates success
  return res.json({message:'Payment processing simulated. Integrate Stripe for live payments.'});
});

// fallback to serve index
app.get('/', (req,res) => {
  res.sendFile(require('path').resolve(__dirname + '/../public/index.html'));
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, ()=> console.log('Server running on port', PORT));
