import jwt from 'jsonwebtoken';
import passport from 'passport';
import local from 'passport-local';
import GitHubStrategy from 'passport-github2';
import userModel from '../dao/models/users.js';
import { createHash, isValidPassword } from '../utils.js';
import passportJWT from 'passport-jwt';
import { PRIVATE_KEY } from './contans.js';

const JWTStrategy = passportJWT.Strategy;
const ExtractJWT = passportJWT.ExtractJwt;
const LocalStrategy = local.Strategy;

const initializePassport = () => {

const cookieExtractor = (req) => {
    let token = null;
    if (req && req.cookies) {
    token = req.cookies['jwt'];
    }
    /* console.log("Extracted token:", token); */
    return token;
};

passport.use('jwt', new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromExtractors([cookieExtractor]),
    secretOrKey: PRIVATE_KEY
}, async (jwt_payload, done) => {
    try {
    /* console.log("JWT payload:", jwt_payload); */
    const user = await userModel.findById(jwt_payload.id);
    /* console.log("JWT user:", user); */
    if (user) {
        return done(null, user);
    } else {
        return done(null, false);
    }
    } catch (error) {
    return done(error);
    }
}));

//=========={ Login }==========
passport.use('login', new LocalStrategy({
    usernameField: 'email',
    passReqToCallback: true
}, async (req, username, password, done) => {
    try {
    const user = await userModel.findOne({ email: username });

    if (!user) {
        return done(null, false, { message: 'Este correo no coincide con ningún usuario registrado, por favor regístrese antes de iniciar sesión' });
    }

    if (!isValidPassword(user, password)) {
        return done(null, false, { message: 'Contraseña incorrecta' });
    } else {
        const token = jwt.sign({ id: user._id }, PRIVATE_KEY);
        return done(null, { user, token });
    }
    } catch (error) {
    return done(`Error al obtener el usuario: ${error}`)
    }
}));
//=========={ Login }==========

//=========={ Register }==========
passport.use('register', new LocalStrategy({
    usernameField: 'email',
    passReqToCallback: true
}, async (req, username, password, done) => {
    const { first_name, last_name, email, age } = req.body;
    try {
    const user = await userModel.findOne({ email: username });

    if (user) {
        return done(null, false, { message: 'El correo pertenece a un usuario ya registrado' })
    }

    let role;
    if (email === "adminCoder@coder.com" && password === "adminCod3r123") {
        role = "admin";
    }
    const userToSave = {
        first_name,
        last_name,
        email,
        age,
        password: createHash(password),
        role
    }
    const result = await userModel.create(userToSave);
    const token = jwt.sign({ id: result._id }, PRIVATE_KEY);
    return done(null, { user: result, token })
    } catch (error) {
    return done(`Error al obtener el usuario: ${error}`)
    }
}));
//=========={ Register }==========

//=========={ Login en github }==========
passport.use('github', new GitHubStrategy({
    clientID: "Iv1.ad3077c6cea461c0",
    clientSecret: "52e9e374d314ec5d4b39159799ea43d6ef83752c",
    callbackURL: "http://localhost:8080/api/sessions/github-callback",
    scope: ['user:email']
}, async (accessToken, refreshToken, profile, done) => {
    try {
    const email = profile.emails[0].value;
    const user = await userModel.findOne({ email })
    const role = 'user';
    if (!user) {
        const newUser = {
        first_name: profile.username,
        name: profile.username,
        last_name: '',
        age: '',
        email,
        password: '',
        role
        }

        const result = await userModel.create(newUser);

        const token = jwt.sign({ id: result._id }, PRIVATE_KEY);
        done(null, { user: result, token });
    } else {
        const token = jwt.sign({ id: user._id }, PRIVATE_KEY);
        done(null, { user, token });
    }
    } catch (error) {
    return done(error);
    }
}));
//=========={ Login en github }==========

passport.use('current', new JWTStrategy({
    jwtFromRequest: ExtractJWT.fromExtractors([(req) => {
    let token = null;
    if (req && req.cookies) {
        token = req.cookies['jwt'];
    }
    /* console.log("Extracted token:", token); */
    return token;
    }]),
    secretOrKey: PRIVATE_KEY
}, async (jwtPayload, done) => {
    try {
    /* console.log("JWT payload:", jwtPayload); */
    const user = await userModel.findById(jwtPayload.id);
    /* console.log("JWT user:", user); */
    if (user) {
        return done(null, user);
    } else {
        return done(null, false);
    }
    } catch (error) {
    return done(error);
    }
}));


/* passport.serializeUser(function(user, done) {
    done(null, user.id);
});

passport.deserializeUser(function(id, done) {
    userModel.findById(id, function(err, user) {
    done(err, user);
    });
}); */

/* passport.serializeUser(function(user, done) {
    console.log('Serializing user:', user);
    done(null, user.id);
}); */

passport.serializeUser(function(data, done) {
    /* console.log('Serializing user:', data.user); */
    done(null, data.user._id);
});


/* passport.deserializeUser(function(id, done) {
    console.log('Deserializing user with ID:', id);
    userModel.findById(id, function(err, user) {
    if (err) {
        console.log('Error deserializing user:', err);
    }
    done(err, user);
    });
}); */

passport.deserializeUser(async function(id, done) {
   /*  console.log('Deserializing user with ID:', id); */
    try {
    const user = await userModel.findById(id);
    done(null, user);
    } catch (err) {
    console.log('Error deserializing user:', err);
    done(err);
    }
});



};
export default initializePassport;
