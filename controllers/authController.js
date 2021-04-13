const router = require('express').Router()
const jwt = require('jsonwebtoken')
const googlePassport = require('../config/googlePpConfig')
const githubPassport = require('../config/githubPpConfig')

// Google Oauth
// https://developers.google.com/identity/protocols/oauth2/scopes
router.get('/google', googlePassport.authenticate('google', { scope: ['profile'] }))
router.get('/google/callback',
    // We're not using sessions, use session: false!
    googlePassport.authenticate('google', { failureRedirect: '/auth/google', session: false }),
    function (req, res) {
        // Successful authentication
        // console.log("The user data!", req.user) // The user data we get from google!

        const payload = {
            _id: req.user._id,
            provider: req.user.provider,
            provider_id: req.user.id,
            displayName: req.user.displayName,
            name: {
                familyName: req.user.name.familyName,
                givenName: req.user.name.givenName,
                middleName: req.user.name.middleName
            },
            photos: req.user.photos
        }
        // console.log('the payload', payload)
        const oneHour = 3600
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: oneHour })

        // Important - redirect from the Server's URL (localhost:8000 or heroku or other server host)
        // to the client's URL (localhost:3000 or netlify, or other client host)
        res.redirect(`${process.env.CLIENT_URL}/saveToken?token=${token}`)
    }
)

// Github Oauth
// https://docs.github.com/en/developers/apps/scopes-for-oauth-apps
router.get('/github', githubPassport.authenticate('github', { scope: ['read:user'] }))
router.get('/github/callback',
    githubPassport.authenticate('github', { failureRedirect: '/auth/github', session: false }),
    function (req, res) {
        // Successful authentication
        // console.log("The user data!", req.user) // The user data we get from github!

        const payload = {
            _id: req.user._id,
            provider: req.user.provider,
            provider_id: req.user.provider_id,
            displayName: req.user.displayName,
            name: {
                familyName: req.user.name.familyName,
                givenName: req.user.name.givenName,
                middleName: req.user.name.middleName
            },
            photos: req.user.photos
        }
        // console.log('the payload', payload)
        const oneHour = 3600
        const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: oneHour })

        res.redirect(`${process.env.CLIENT_URL}/saveToken?token=${token}`);
    });

module.exports = router