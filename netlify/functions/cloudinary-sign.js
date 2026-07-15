// netlify/functions/cloudinary-sign.js
//
// 로그인한 사용자만 사진을 업로드할 수 있도록, 업로드 전에 서명(signature)을 발급해주는 함수.
// 외부 라이브러리 없이 Node 내장 기능만 사용해서, 별도 설치(npm install) 없이 그대로 배포된다.
//
// 이 함수가 하는 일:
// 1. 요청에 담긴 Firebase 로그인 토큰이 진짜인지 확인한다 (구글 공개키로 서명 검증).
// 2. 진짜 로그인한 사용자가 맞으면, Cloudinary 업로드에 필요한 서명을 만들어 돌려준다.
// 3. 로그인 안 했거나 가짜 요청이면 거절한다.

const crypto = require('crypto');

const FIREBASE_PROJECT_ID = 'pt-diary-daf4e';
const GOOGLE_CERTS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString('utf8');
}

async function verifyFirebaseIdToken(idToken) {
  const parts = idToken.split('.');
  if (parts.length !== 3) throw new Error('잘못된 로그인 정보예요.');

  const header = JSON.parse(base64UrlDecode(parts[0]));
  const payload = JSON.parse(base64UrlDecode(parts[1]));

  if (payload.aud !== FIREBASE_PROJECT_ID) throw new Error('앱 정보가 일치하지 않아요.');
  if (payload.iss !== `https://securetoken.google.com/${FIREBASE_PROJECT_ID}`) throw new Error('발급 기관이 일치하지 않아요.');
  if (!payload.exp || payload.exp * 1000 < Date.now()) throw new Error('로그인이 만료됐어요.');
  if (!payload.sub) throw new Error('사용자 정보가 없어요.');

  const certsRes = await fetch(GOOGLE_CERTS_URL);
  if (!certsRes.ok) throw new Error('인증 서버 확인에 실패했어요.');
  const certs = await certsRes.json();
  const cert = certs[header.kid];
  if (!cert) throw new Error('일치하는 인증 키를 찾지 못했어요.');

  const signedData = `${parts[0]}.${parts[1]}`;
  const signatureBuf = Buffer.from(parts[2].replace(/-/g, '+').replace(/_/g, '/'), 'base64');

  const verifier = crypto.createVerify('RSA-SHA256');
  verifier.update(signedData);
  const isValid = verifier.verify(cert, signatureBuf);
  if (!isValid) throw new Error('로그인 정보 검증에 실패했어요.');

  return payload; // payload.sub === Firebase uid
}

exports.handler = async (event) => {
  const headers = {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    'Access-Control-Allow-Methods': 'POST, OPTIONS',
  };

  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers, body: '' };
  }
  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers, body: JSON.stringify({ error: '허용되지 않은 방식이에요.' }) };
  }

  try {
    const authHeader = event.headers.authorization || event.headers.Authorization || '';
    if (!authHeader.startsWith('Bearer ')) {
      return { statusCode: 401, headers, body: JSON.stringify({ error: '로그인이 필요해요.' }) };
    }
    const idToken = authHeader.slice(7);
    await verifyFirebaseIdToken(idToken);

    const apiKey = process.env.CLOUDINARY_API_KEY;
    const apiSecret = process.env.CLOUDINARY_API_SECRET;
    if (!apiKey || !apiSecret) {
      return { statusCode: 500, headers, body: JSON.stringify({ error: '서버에 Cloudinary 설정이 안 되어 있어요.' }) };
    }

    const timestamp = Math.round(Date.now() / 1000);
    const paramsToSign = `timestamp=${timestamp}`;
    const signature = crypto.createHash('sha1').update(paramsToSign + apiSecret).digest('hex');

    return {
      statusCode: 200,
      headers,
      body: JSON.stringify({ signature, timestamp, apiKey }),
    };
  } catch (err) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: err.message || '인증에 실패했어요.' }) };
  }
};
