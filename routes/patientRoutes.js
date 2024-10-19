import express from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import Patient from "../models/patientModel.js";
import nodemailer from "nodemailer";
import otpGenerator from "otp-generator";
import crypto from "crypto";
// import authenticateToken from '../middleware/auth.js';
import dotenv from "dotenv";
dotenv.config();

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;

// Patient signup route
router.post("/signup", async (req, res) => {
  const { firstName, lastName, email, password, ...otherDetails } = req.body;

  try {
    let patient = await Patient.findOne({ email });
    if (patient) {
      return res.status(400).json({ error: "Patient already exists" });
    }

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    patient = new Patient({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      ...otherDetails,
    });

    await patient.save();

    const payload = { patientId: patient.id };
    const token = jwt.sign(payload, JWT_SECRET, { expiresIn: "1h" });

    res.status(201).json({ token, message: "Patient registered successfully" });
  } catch (error) {
    console.error(error.message);
    res.status(500).send("Server error");
  }
});

// Patient login route
router.post("/login", async (req, res) => {
  const { email, password } = req.body;

  try {
    const patient = await Patient.findOne({ email });
    if (!patient) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = await bcrypt.compare(password, patient.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ id: patient._id }, process.env.JWT_SECRET, {
      expiresIn: "1h",
    });

    res.json({
      token,
      patient: {
        id: patient._id,
        email: patient.email,
        firstName: patient.firstName,
      },
    });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// Patient forgot password route
router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;

  try {
    // Find user by email
    const user = await Patient.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "Email not found" });
    }

    // Generate OTP
    const otp = otpGenerator.generate(6, {
      upperCaseAlphabets: false,
      specialChars: false,
    });

    // Hash the OTP with the SECRET key from .env
    const secret = process.env.SECRET; // Ensure this is set in your .env file
    const hash = crypto.createHmac("sha256", secret).update(otp).digest("hex");

    // Save the original OTP and expiry in the database
    user.resetOtp = otp;
    user.otpExpiry = Date.now() + 3600000; // OTP is valid for 1 hour
    await user.save();

    // Set up email transporter
    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: {
        user: process.env.EMAIL,
        pass: process.env.PASSWORD,
      },
    });

    // Set email options
    const mailOptions = {
      from: process.env.EMAIL,
      to: email,
      subject: "Password Reset OTP",
      text: `Your OTP code is ${otp}. It is valid for 1 hour.`,
    };

    // Send the email
    await transporter.sendMail(mailOptions);

    // Send success response with the hashed OTP
    res.status(200).json({ message: "OTP sent successfully", hash });
  } catch (error) {
    console.error("Error in forgot-password route:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

router.post("/verify-otp", async (req, res) => {
  const { hash, otp } = req.body;

  try {
    const hashedOtp = crypto
      .createHmac("sha256", process.env.SECRET)
      .update(otp)
      .digest("hex");

    if (hashedOtp !== hash) {
      return res.status(400).json({ message: "Invalid OTP" });
    }

    const randomDigit = Math.floor(Math.random() * 1000000000000000);

    res.status(200).json({ message: "OTP verified successfully", randomDigit });
  } catch (error) {
    console.error("Error in verify-otp route:", error);
    res.status(500).json({ message: "Internal Server Error" });
  }
});

// Reset the password
router.post("/reset-password", async (req, res) => {
  const { email, newPassword } = req.body;

  try {
    // Find the user by email
    const user = await Patient.findOne({ email });
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Hash the new password
    const hashedPassword = await bcrypt.hash(newPassword, 10);

    // Save the new password to the user's account
    user.password = hashedPassword;
    await user.save();

    res.status(200).json({ message: "Password has been reset successfully." });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Something went wrong", error: error.message });
  }
});

export default router;
