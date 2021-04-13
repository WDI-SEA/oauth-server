const jwt = require('jsonwebtoken')
const User = require('../models/User')

const authenticateJWT = async (req, res, next) => {
    try {
        // Find the attached jwt
        const authHeader = req.headers.authorization

        // Try to decode jwt -- if it fails, will throw an error in catch block
        const decodedJwt = jwt.verify(authHeader, process.env.JWT_SECRET)

        // console.log('This is the user', decodedJwt)

        const foundUser = await User.findById(decodedJwt._id)
        // Add the user to res.locals.user
        res.locals.user = foundUser
        next()
    }
    catch (err) {
        console.log(err)
        if(err.name == 'TokenExpiredError') {
            res.status(401).json({ msg: 'JWT is expired' })
        } else {
            res.status(500).json({ msg: 'Server error occured while authenticating' })
        }
    }
}

module.exports = authenticateJWT