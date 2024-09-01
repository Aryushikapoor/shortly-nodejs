const express = require('express');
const router = express.Router();
const User = require('../model/user');
const Url = require('../model/url');
const bcrypt = require('bcryptjs');
const passport = require('passport');
require('./passportLocal')(passport);
require('./googleAuth')(passport);
const userRoutes = require('./accountRoutes');

// Middleware to check if user is authenticated
function checkAuth(req, res, next) {
    if (req.isAuthenticated()) {
        res.set('Cache-Control', 'no-cache, private, no-store, must-revalidate, post-check=0, pre-check=0');
        return next();
    }
    req.flash('error_messages', "Please Login to continue !");
    res.redirect('/login');
}

// Render login page
router.get('/login', (req, res) => {
    res.render("login", { csrfToken: req.csrfToken() });
});

// Render signup page
router.get('/signup', (req, res) => {
    res.render("signup", { csrfToken: req.csrfToken() });
});

// Handle signup form submission
router.post('/signup', async (req, res) => {
    const { email, password, confirmpassword } = req.body;

    // Check for empty fields
    if (!email || !password || !confirmpassword) {
        return res.render("signup", { err: "All Fields Required !", csrfToken: req.csrfToken() });
    }

    // Check if passwords match
    if (password !== confirmpassword) {
        return res.render("signup", { err: "Passwords Don't Match !", csrfToken: req.csrfToken() });
    }

    try {
        // Check if user exists
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.render("signup", { err: "User Exists, Try Logging In !", csrfToken: req.csrfToken() });
        }

        // Hash password and save new user
        const salt = await bcrypt.genSalt(12);
        const hash = await bcrypt.hash(password, salt);

        const newUser = new User({
            email,
            password: hash,
            googleId: null,
            provider: 'email',
        });
        await newUser.save();

        res.redirect('/login');
    } catch (err) {
        console.error(err);
        res.render("signup", { err: "An error occurred. Please try again.", csrfToken: req.csrfToken() });
    }
});

// Handle login form submission
router.post('/login', passport.authenticate('local', {
    failureRedirect: '/login',
    successRedirect: '/dashboard',
    failureFlash: true,
}));

// Handle logout
router.get('/logout', (req, res) => {
    req.logout();
    req.session.destroy(err => {
        if (err) console.error(err);
        res.redirect('/');
    });
});

// Google OAuth routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
router.get('/google/callback', passport.authenticate('google', { failureRedirect: '/login' }), (req, res) => {
    res.redirect('/dashboard');
});

// Render dashboard page
router.get('/dashboard', checkAuth, async (req, res) => {
    try {
        const urls = await Url.find({ owned: req.user.email });
        res.render('dashboard', { verified: req.user.isVerified, logged: true, csrfToken: req.csrfToken(), urls });
    } catch (err) {
        console.error(err);
        res.render('dashboard', { verified: req.user.isVerified, logged: true, csrfToken: req.csrfToken(), err: "An error occurred while fetching URLs." });
    }
});

// Redirect route for '/dashboard/desi'
router.get('/dashboard/desi', checkAuth, (req, res) => {
    res.redirect('https://learn.desiprogrammer.com/');
});

// Handle URL creation
router.post('/create', checkAuth, async (req, res) => {
    const { original, short } = req.body;

    if (!original || !short) {
        return res.render('dashboard', { verified: req.user.isVerified, logged: true, csrfToken: req.csrfToken(), err: "Empty Fields !" });
    }

    try {
        const existingUrl = await Url.findOne({ slug: short });
        if (existingUrl) {
            return res.render('dashboard', { verified: req.user.isVerified, logged: true, csrfToken: req.csrfToken(), err: "Try a Different Short URL, This Exists !" });
        }

        const newUrl = new Url({
            originalUrl: original,
            slug: short,
            owned: req.user.email,
        });
        await newUrl.save();
        res.redirect('/dashboard');
    } catch (err) {
        console.error(err);
        res.render('dashboard', { verified: req.user.isVerified, logged: true, csrfToken: req.csrfToken(), err: "An error occurred while creating the URL." });
    }
});

// Use user routes
router.use(userRoutes);

// Handle URL redirection with visit counters
router.get('/:slug?', async (req, res) => {
    const { slug } = req.params;
    const { ref } = req.query;

    try {
        if (slug) {
            const data = await Url.findOne({ slug });
            if (data) {
                data.visits += 1;

                if (ref) {
                    switch (ref) {
                        case 'fb':
                            data.visitsFB += 1;
                            break;
                        case 'ig':
                            data.visitsIG += 1;
                            break;
                        case 'yt':
                            data.visitsYT += 1;
                            break;
                    }
                }

                await data.save();
                return res.redirect(data.originalUrl);
            }
            return res.render("index", { logged: req.isAuthenticated(), err: true });
        }
        res.render("index", { logged: req.isAuthenticated() });
    } catch (err) {
        console.error(err);
        res.render("index", { logged: req.isAuthenticated(), err: true });
    }
});

module.exports = router;
