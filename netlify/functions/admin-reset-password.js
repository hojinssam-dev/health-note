// netlify/functions/admin-reset-password.js
//
// 관리자 또는 트레이너가 회원의 비밀번호를 000000으로 강제 초기화해주는 함수.
// 클라이언트 SDK로는 "본인" 비밀번호만 바꿀 수 있어서, 다른 사람 비밀번호를 강제로 바꾸려면
// 서버에서 관리자 권한(Admin SDK)으로 처리해야 한다.
//
// 트레이너는 "지금 자기한테 연결되어 있는 회원"만 초기화할 수 있다 — 연결 안 된 회원까지
// 마음대로 바꿀 수 있으면 안 되니, Firestore에서 그 회원의 trainerId를 직접 확인한다.

const crypto = require('crypto');
const admin = require('firebase-admin');

const FIREBASE_PROJECT_ID = 'pt-diary-daf4e';
const GOOGLE_CERTS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
const ADMIN_UID = 'xcYFACPlU9YhCWBjxnDM1lRCAYz1'; // 앱 안에서 관리자로 취급하는 고정 UID와 동일
const RESET_PASSWORD = '000000';

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

  return payload;
}

if (!admin.apps.length) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY || '{}');
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
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
    const payload = await verifyFirebaseIdToken(idToken);
    const callerUid = payload.sub;

    const body = JSON.parse(event.body || '{}');
    const targetUid = (body.targetUid || '').trim();
    if (!targetUid) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: '대상 회원 정보가 없어요.' }) };
    }

    if (callerUid !== ADMIN_UID) {
      // 관리자가 아니면, 트레이너 계정이면서 지금 이 회원이 자기한테 연결되어 있어야만 허용한다
      const db = admin.firestore();
      const callerDoc = await db.collection('users').doc(callerUid).get();
      const callerIsTrainer = callerDoc.exists && callerDoc.data().isTrainer === true;
      if (!callerIsTrainer) {
        return { statusCode: 403, headers, body: JSON.stringify({ error: '트레이너나 관리자만 사용할 수 있어요.' }) };
      }
      const targetDoc = await db.collection('users').doc(targetUid).get();
      const targetBelongsToCaller = targetDoc.exists && targetDoc.data().trainerId === callerUid;
      if (!targetBelongsToCaller) {
        return { statusCode: 403, headers, body: JSON.stringify({ error: '지금 나한테 연결된 회원만 초기화할 수 있어요.' }) };
      }
    }

    await admin.auth().updateUser(targetUid, { password: RESET_PASSWORD });

    return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
  } catch (err) {
    console.error('비밀번호 초기화 오류:', err);
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message || '초기화에 실패했어요.' }) };
  }
};
