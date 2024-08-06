import jwt from "jsonwebtoken";

export const verifyToken = (req, res, next) => {
    const token = req.cookies.token;
    
    if (!token) {
        console.log('No token found');
        return res.status(401).json({ message: "Not Authenticated" });
    }
    
    jwt.verify(token, process.env.JWT_SECRET_KEY, (err, payload) => {
        if (err) {
            console.log('Token verification failed:', err);
            return res.status(401).json({ message: "Token is not valid" });
        }

        // Ensure payload contains the id field
        if (!payload || !payload.id) {
            console.log('Token payload is missing user id');
            return res.status(401).json({ message: "Invalid token payload" });
        }

        req.userId = payload.id;
        next();
    });
};
