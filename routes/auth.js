const express = require("express");
const router = express.Router();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const sendEmail = require("../utiles/sendEmail");

//signup
router.post("/signup", async (req, res) => {
  const { email, name, password } = req.body;
  const userExists = await User.findOne({ email });
  if (userExists) return res.status(400).json({ Error: "User already exists" });

  const hashedPassword = await bcrypt.hash(password, 10);
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const otpExpiry = new Date(Date.now() + 10 * 60 * 1000); // 10 minutes from now

  const user = new User({
    email,
    name,
    password: hashedPassword,
    otp,
    otpExpiry,
  });
  await user.save();
  await sendEmail(email, "Verify your email with OTP", `Your OTP is ${otp}`);

  res
    .status(201)
    .json({
      message: "otp sent to your email",
      user: { id: user._id, email: user.email, name: user.name },
    });
});

//login
router.get("/login", async (req, res) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email });
  if (!user.isVerified) {
    return res.status(403).json({ error: "Please verify your email first." });
  }

  if (!user) return res.status(400).json({ error: "User not found" });

  const isMatch = await bcrypt.compare(password, user.password);
  if (!isMatch) return res.status(400).json({ error: "Invalid credentials" });

  const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
    expiresIn: "1h",
  });
  res
    .status(200)
    .json({
      token,
      user: { id: user._id, email: user.email, name: user.name },
    });
});

router.delete("/delete", async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });
  if (!user) return res.status(400).json({ error: "User not found" });
  else {
    await User.deleteOne({ email });
    res.status(200).json({ message: "User deleted successfully" });
  }
});

router.put("/update/:id", async (req, res) => {
  const { email, name, password } = req.body;
  const user = await User.findById(req.params.id);
  if (!user) return res.status(400).json({ error: "User not found" });
  const hashedPassword = await bcrypt.hash(password, 16);
  await User.updateOne(
    { _id: req.params.id },
    { email, name, password: hashedPassword }
  );
  res.status(200).json({ message: "User updated successfully" });
});

router.get("/users", async (req, res) => {
  const users = await User.find();
  res.status(200).json(users);
});

router.post("/verify-otp/:id", async (req, res) => {
//   req.body = (req.body);
  const {  otp } = req.body;
  const user = await User.findById( req.params.id );

  if (!user) return res.status(400).json({ error: "User not found" });
  if (user.otp !== otp) return res.status(400).json({ error: "Invalid OTP" });
  if (user.otpExpiry < Date.now())
    return res.status(400).json({ error: "OTP expired" });
  if (user.isVerified)
    return res.status(400).json({ error: "User already verified" });
  user.isVerified = true;
  user.otp = undefined;
  user.otpExpiry = undefined;
  await user.save();
  res.status(200).json({ message: "User verified successfully" });
});

module.exports = router;
