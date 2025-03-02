require("dotenv").config();
const jwt = require("jsonwebtoken");

const JWT_SECRET = process.env.JWT_SECRET;

const authMiddlware = function auth(req, res, next) {
    const token = req.headers.token || req.headers.authorization;

    try{
        const decodedData = jwt.verify(token, JWT_SECRET);

        if(decodedData) {
            req.userId = decodedData.id;
            next();
        }
    } catch (error) {
        res.status(403).json({
            message: "Incorrect credentials"
        });
    };
};

module.exports = {
    authMiddlware,
    JWT_SECRET,
};