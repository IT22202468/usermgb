import express from "express";
import cors from "cors";
import mongoose from "mongoose";
import dotenv from "dotenv";

import patientRoutes from "./routes/patientRoutes.js";

dotenv.config();

const app = express();
const PORT = process.env.PORT || 5000; // Use environment variable for port

app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Routes
app.use("/api/patients", patientRoutes);

// Validate required environment variables
if (!process.env.MONGODB_URI || !process.env.JWT_SECRET) {
  throw new Error("MONGODB_URI and JWT_SECRET must be defined in .env");
}

// Connect to MongoDB
mongoose
  .connect(process.env.MONGODB_URI) // Remove deprecated options
  .then(() => console.log("MongoDB connected"))
  .catch((err) => {
    console.error("MongoDB connection error:", err);
    // Consider more specific error handling and logging
  });

// Start the server
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

