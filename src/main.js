import {
  generateRegistrationOptions,
  verifyRegistrationResponse,
  generateAuthenticationOptions,
  verifyAuthenticationResponse,
} from '@simplewebauthn/server';
import AppwriteService from './appwrite.js';
import { throwIfMissing, getStaticFile } from './utils.js';

const rpName = 'Passkey Demo';
const rpID =
  process.env.APPWRITE_FUNCTION_API_ENDPOINT?.replace(/^https?:\/\//, '').split(
    '/'
  )[0] || 'localhost';
const origin =
  process.env.APPWRITE_FUNCTION_API_ENDPOINT?.split('/v1')[0] ||
  `https://${rpID}`;

export default async ({ req, res, log, error }) => {
  const appwrite = new AppwriteService();

  try {
    if (req.method === 'GET' && req.path === '/') {
      return res.text(getStaticFile('index.html'), 200, {
        'Content-Type': 'text/html',
      });
    }

    if (req.path === '/ping') {
      return res.text('Pong');
    }

    if (req.method === 'POST' && req.path === '/v1/challenges') {
      return await handleRegistrationStart(req, res, appwrite, log, error);
    }

    if (req.method === 'PUT' && req.path === '/v1/challenges') {
      return await handleRegistrationFinish(req, res, appwrite, log, error);
    }

    if (req.method === 'POST' && req.path === '/v1/tokens') {
      return await handleAuthenticationStart(req, res, appwrite, log, error);
    }

    if (req.method === 'PUT' && req.path === '/v1/tokens') {
      return await handleAuthenticationFinish(req, res, appwrite, log, error);
    }

    return res.json({ error: 'Endpoint not found' }, 404);
  } catch (err) {
    error('Unexpected error: ' + err.message);
    return res.json({ error: 'Internal server error' }, 500);
  }
};

async function handleRegistrationStart(req, res, appwrite, _, error) {
  try {
    const body = JSON.parse(req.body || '{}');
    throwIfMissing(body, ['email']);

    const user = await appwrite.prepareUser(body.email);

    const options = await generateRegistrationOptions({
      rpName,
      rpID,
      userID: user.$id,
      userName: user.email,
      userDisplayName: user.email,
      attestationType: 'none',
      authenticatorSelection: {
        residentKey: 'preferred',
        userVerification: 'preferred',
        authenticatorAttachment: 'platform',
      },
    });

    const challenge = await appwrite.createChallenge(
      user.$id,
      options.challenge
    );

    return res.json({
      options,
      challengeId: challenge.$id,
    });
  } catch (err) {
    error('Registration start error: ' + err.message);
    return res.json({ error: err.message }, 400);
  }
}

async function handleRegistrationFinish(req, res, appwrite, _, error) {
  try {
    const body = JSON.parse(req.body || '{}');
    throwIfMissing(body, ['challengeId', 'registration']);

    const challenge = await appwrite.getChallenge(body.challengeId);

    const verification = await verifyRegistrationResponse({
      response: body.registration,
      expectedChallenge: challenge.token,
      expectedOrigin: origin,
      expectedRPID: rpID,
    });

    if (!verification.verified || !verification.registrationInfo) {
      throw new Error('Registration verification failed');
    }

    await appwrite.createCredentials(challenge.userId, {
      id: Array.from(verification.registrationInfo.credential.id),
      publicKey: Array.from(verification.registrationInfo.credentialPublicKey),
      counter: verification.registrationInfo.counter,
    });

    await appwrite.deleteChallenge(body.challengeId);

    return res.json({ success: true });
  } catch (err) {
    error('Registration finish error: ' + err.message);
    return res.json({ error: err.message }, 400);
  }
}

async function handleAuthenticationStart(req, res, appwrite, _, error) {
  try {
    const body = JSON.parse(req.body || '{}');
    throwIfMissing(body, ['email']);

    const user = await appwrite.prepareUser(body.email);
    const credential = await appwrite.getCredential(user.$id);

    if (!credential) {
      throw new Error('No credentials found for this user');
    }

    const credentialData = JSON.parse(credential.credentials);

    const options = await generateAuthenticationOptions({
      rpID,
      allowCredentials: [
        {
          id: new Uint8Array(credentialData.id),
          type: 'public-key',
          transports: ['internal', 'hybrid'],
        },
      ],
      userVerification: 'preferred',
    });

    const challenge = await appwrite.createChallenge(
      user.$id,
      options.challenge
    );

    return res.json({
      options,
      challengeId: challenge.$id,
    });
  } catch (err) {
    error('Authentication start error: ' + err.message);
    return res.json({ error: err.message }, 400);
  }
}

async function handleAuthenticationFinish(req, res, appwrite, _, error) {
  try {
    const body = JSON.parse(req.body || '{}');
    throwIfMissing(body, ['challengeId', 'authentication']);

    const challenge = await appwrite.getChallenge(body.challengeId);
    const credential = await appwrite.getCredential(challenge.userId);

    if (!credential) {
      throw new Error('No credentials found for this user');
    }

    const credentialData = JSON.parse(credential.credentials);

    const verification = await verifyAuthenticationResponse({
      response: body.authentication,
      expectedChallenge: challenge.token,
      expectedOrigin: origin,
      expectedRPID: rpID,
      authenticator: {
        credentialID: new Uint8Array(credentialData.id),
        credentialPublicKey: new Uint8Array(credentialData.publicKey),
        counter: credentialData.counter,
      },
    });

    if (!verification.verified) {
      throw new Error('Authentication verification failed');
    }

    const sessionToken = await appwrite.createSessionToken(challenge.userId);
    await appwrite.deleteChallenge(body.challengeId);

    return res.json({
      userId: challenge.userId,
      secret: sessionToken.secret,
    });
  } catch (err) {
    error('Authentication finish error: ' + err.message);
    return res.json({ error: err.message }, 400);
  }
}
