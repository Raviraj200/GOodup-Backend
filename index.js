const express = require('express');
const server = express();
const mongoose = require('mongoose');
const cors = require('cors')
const session = require('express-session');
const passport = require('passport')
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const JwtStrategy = require('passport-jwt').Strategy;
const ExtractJwt = require('passport-jwt').ExtractJwt;
const LocalStrategy = require('passport-local').Strategy;

const { createProduct } = require('./controller/Product');
const productsRouter = require('./routes/Products');
const categoriesRouter = require('./routes/Categories');
const brandsRouter = require('./routes/Brands');
const usersRouter = require('./routes/Users');
const authRouter = require('./routes/Auth');
const cartRouter = require('./routes/Cart');
const ordersRouter = require('./routes/Order');
const { User } = require('./model/User');
const { isAuth, sanitizeUser } = require('./services/common');
const SECRET_KEY = "SECRET_KEY";

//JWT option
const opts = {}
opts.jwtFromRequest = ExtractJwt.fromAuthHeaderAsBearerToken();
opts.secretOrKey = SECRET_KEY;

//middlewares
server.use(session({
    secret: 'keyboard cat',
    resave: false,
    saveUninitialized: false,


}));
server.use(passport.authenticate('session'))

server.use(cors({
    exposedHeaders: ['X-Total-Count']
}))
server.use(express.json()); // to parse req.body
server.use('/products', isAuth(), productsRouter.router);
server.use('/categories',isAuth(), categoriesRouter.router)
server.use('/brands',isAuth(), brandsRouter.router)
server.use('/users',isAuth(), usersRouter.router)
server.use('/auth', authRouter.router)
server.use('/cart',isAuth(), cartRouter.router)
server.use('/orders', isAuth(),ordersRouter.router)

//passport strategies

passport.use('local',
    new LocalStrategy(async function (username, password, done) {
        try {
            const user = await User.findOne(
                { email: username }
            ).exec();
            if (!user) {
                done(null, false, { message: 'invalid credentials' })

            }
            // TODO: this is just temporary, we will use strong password auth
            const salt = crypto.randomBytes(16);
            crypto.pbkdf2(
                password,
                user.salt,
                310000,
                32,
                'sha256',
                async function (err, hashedPassword) {
                    if (!crypto.timingSafeEqual(user.password, hashedPassword)) {
                        // TODO: We will make addresses independent of login
                        return done(null, false, { message: 'invalid credentials' })

                    }
                    const token = jwt.sign(sanitizeUser(user), SECRET_KEY);
                    done(null, token);
                })

        } catch (err) {
            done(err)
        }

    }
    ))
passport.use('jwt', new JwtStrategy(opts, async function (jwt_payload, done) {
    console.log({ jwt_payload })
    try {
        const user = await User.findOne({ id: jwt_payload.sub })
            if (user) {
                return done(null,sanitizeUser( user));
            } else {
                return done(null, false);
                // or you could create a new account
            }
     
    } catch (err) {
     
        return done(null, false);

    }
  
   
}))
// this creates session variable req.user on being called 

passport.serializeUser(function (user, cb) {
    console.log('serialize', user);
    process.nextTick(function () {
        return cb(null, { id: user.id, role: user.role });
    });
})
// from authorized request

passport.deserializeUser(function (user, cb) {
    console.log('de-serialize', user);
    process.nextTick(function () {
        return cb(null, user);
    });
});
main().catch(err => console.log(err));

async function main() {
    await mongoose.connect('mongodb://localhost:27017');
    console.log('database connected')
}



server.listen(8080, () => {
    console.log('server started')
})
