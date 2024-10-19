import express from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import Patient from '../models/patientModel.js';
// import authenticateToken from '../middleware/auth.js';
import dotenv from "dotenv";
dotenv.config();

const router = express.Router();
const JWT_SECRET = process.env.JWT_SECRET;


// Patient signup route
router.post('/signup', async (req, res) => {
    const { firstName, lastName, email, password, ...otherDetails } = req.body;

    try {
        let patient = await Patient.findOne({ email });
        if (patient) {
            return res.status(400).json({ error: 'Patient already exists' });
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
        const token = jwt.sign(payload, JWT_SECRET, { expiresIn: '1h' });

        res.status(201).json({ token, message: 'Patient registered successfully' });
    } catch (error) {
        console.error(error.message);
        res.status(500).send('Server error');
    }
});

// Patient login route
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const patient = await Patient.findOne({ email });
        if (!patient) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, patient.password);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid credentials' });
        }

        const token = jwt.sign({ id: patient._id }, process.env.JWT_SECRET, { expiresIn: '1h' });

        res.json({ token, patient: { id: patient._id, email: patient.email, firstName: patient.firstName } });
    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Server error' });
    }
});


// Patient forgot password route
router.post('/forgot-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await Patient.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'Email not found' });
        }

        const otp = otpGenerator.generate(6, { upperCaseAlphabets: false, specialChars: false });
        user.resetOtp = otp;
        user.otpExpiry = Date.now() + 3600000; // OTP is valid for 1 hour
        await user.save();

        const transporter = nodemailer.createTransport({
            service: 'gmail',
            auth: {
                user: process.env.EMAIL,
                pass: process.env.PASSWORD,
            },
        });

        const mailOptions = {
            from: process.env.EMAIL,
            to: email,
            subject: 'Password Reset OTP',
            text: `Your OTP code is ${otp}. It is valid for 1 hour.`,
        };

        await transporter.sendMail(mailOptions);


    } catch (error) {
        
    }
});

// Reset the password
router.post('/reset-password', async (req, res) => {
    const { email, newPassword } = req.body;

    try {
        // Find the user by email
        const user = await Patient.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        // Hash the new password
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        // Save the new password to the user's account
        user.password = hashedPassword;
        await user.save();

        res.status(200).json({ message: 'Password has been reset successfully.' });
    } catch (error) {
        res.status(500).json({ message: 'Something went wrong', error: error.message });
    }
});

export default router;
