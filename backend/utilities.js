const jwt = require("jsonwebtoken");

function authenticateToken(req, res, next) {
    const authHeader = req.headers["authorization"];

    if (!authHeader || !authHeader.startsWith("Bearer ")) {
        return res.status(401).json({ error: true, message: "Access token is missing or invalid" });
    }

    const token = authHeader.split(" ")[1]; // Extract token correctly

    jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, user) => {
        if (err) {
            console.error("JWT verification failed:", err); // Log error
            return res.status(403).json({ error: true, message: "Invalid or expired token" });
        }

        req.user = user; // Attach user data
        next();
    });
}

module.exports = { authenticateToken };
