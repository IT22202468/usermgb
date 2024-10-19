import jwt from 'jsonwebtoken';

const authenticateToken = (req, res, next) => {
  // Get the token from the request header
  const token = req.header('Authorization')?.split(' ')[1]; // Expected: 'Bearer <token>'
  
  if (!token) {
    return res.status(401).json({ message: 'No token, authorization denied' });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET); // Decode the token using JWT_SECRET
    req.patient = decoded; // Attach decoded token to the request (e.g., patient info)
    next(); // Call next middleware
  } catch (err) {
    return res.status(403).json({ message: 'Token is not valid' });
  }
};

export default authenticateToken;
