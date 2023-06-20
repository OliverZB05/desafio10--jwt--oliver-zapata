import { Router } from 'express';
import userModel from '../../dao/models/users.js';
import passport from 'passport';
import { createHash } from '../../utils.js';

const router = Router();

//========= Register =========
router.post('/register', (req, res, next) => {
passport.authenticate('register', (err, data, info) => {
if (err) return next(err);
if (!data) return res.send({ status: 'error', message: info.message });

// Send the JWT token in a cookie
res.cookie('jwt', data.token, { httpOnly: true });

res.send({ status: 'success', message: 'User registered', token: data.token });
})(req, res, next);
});

//========= Register =========

//========= Login =========
router.post('/login', (req, res, next) => {
passport.authenticate('login', (err, data, info) => {
if (err) return next(err);
if (!data) return res.send({ status: 'error', message: info.message });

// Send the JWT token in a cookie
res.cookie('jwt', data.token, { httpOnly: true });

res.send({ status: 'success', message: 'Login success', token: data.token });
})(req, res, next);
});

//========= Login =========

//========= Github =========

router.get('/github', passport.authenticate(
'github', { scope: ['user:email'] }
), async (req, res) => {
res.send({ status: "success", message: "User registered" })
});

/* router.get('/github-callback', passport.authenticate(
'github', { failureRedirect: '/login' }
), async (req, res) => {
// Send the JWT token in a cookie
res.cookie('jwt', req.user.token, { httpOnly: true });

res.redirect('/products');
}); */

router.get('/github-callback', passport.authenticate(
'github', { failureRedirect: '/login' }
), async (req, res) => {
// Send the JWT token in a cookie
/* console.log("GitHub user:", req.user);
console.log("GitHub token:", req.user.token); */
res.cookie('jwt', req.user.token, { httpOnly: true });

res.redirect('/products');
});


//========= Github =========

//========= Reset =========
router.post('/reset', async (req, res) => {
try {
const { email, password } = req.body;

if (!email || !password) return res.status(400).send({ status: 'error', error: 'Incomplete values' });

const user = await userModel.findOne({ email });

if (!user) return res.status(400).send({ status: 'error', error: 'Este correo no coincide con ningún usuario registrado' });

user.password = createHash(password);

await userModel.updateOne({ email }, user);

res.send({ status: 'success', message: 'Password reset' })
} catch (error) {
res.status(500).send({ status: 'error', error: error.message });
}
})
//========= Reset =========


router.get('/current', passport.authenticate('current', { session: false }), (req, res) => {
res.send({ status: 'success', user: req.user });
});


//========= Logout =========
router.get('/logout', (req, res) => {
// Clear the JWT cookie
res.clearCookie('jwt');

req.session.destroy(err => {
if (err) return res.status(500).send({ status: 'error', error: 'Logout fail' });
res.redirect('/')
})
});
//========= Logout =========

export default router;


