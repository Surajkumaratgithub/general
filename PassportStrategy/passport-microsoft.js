// passport-microsoft.js
import passport from 'passport';
import {OIDCStrategy}from 'passport-azure-ad';

passport.use('microsoft', new OIDCStrategy({
  identityMetadata: `https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0/.well-known/openid-configuration`,
  clientID: process.env.CLIENT_ID,
  clientSecret: process.env.CLIENT_SECRET,
  responseType: 'code',
  responseMode: 'form_post',
  redirectUrl: `${process.env.BASE_URL}/auth/microsoft/callback`,
  allowHttpForRedirectUrl: true,
  scope: ['openid', 'profile', 'email', 'offline_access', 'User.Read', 'OnlineMeetings.ReadWrite'],
  passReqToCallback: true
}, async (req, iss, sub, profile, accessToken, refreshToken, params, done) => {
  try {
    // Store Microsoft tokens in DB against your user
    const microsoft = {
      id: profile.oid,
      accessToken,
      refreshToken,
      expiresAt: Date.now() + params.expires_in * 1000
    }
    done(null, microsoft);
  } catch (err) {
 done(err, null);
  }
}));
