// // sessionConfig.js
// import session from 'express-session';

// const sessionMiddleware = session({
//   secret: process.env.SESSION_SECRET || 'your-session-secret',
//   resave: false,
//   saveUninitialized: true,
//   cookie: { secure: process.env.NODE_ENV === 'production' }
// });

// export default sessionMiddleware;


// sessionConfig.js
import session from 'express-session';

const isProduction = process.env.NODE_ENV === 'production';

const sessionMiddleware = session({
  secret: process.env.SESSION_SECRET || 'your-session-secret',
  resave: false,
  saveUninitialized: false, // better security (don't create empty sessions)
  cookie: {
    httpOnly: true,           // Prevent JS access (recommended)
    secure: isProduction ? true : false, // HTTPS only in production
    sameSite: isProduction ? 'None' : 'Lax', // 'None' for cross-origin in prod, 'Lax' for localhost
    maxAge: 3 * 24 * 60 * 60 * 1000, // Optional: 3 days session expiry
  }
});

export default sessionMiddleware;

