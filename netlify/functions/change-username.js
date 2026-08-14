// netlify/functions/change-username.js
//
// 로그인한 회원이 '아이디 변경'을 할 때 호출되는 함수.
//
// 예전엔 클라이언트에서 Firestore의 usernames 문서만 새 아이디로 옮기는 방식이었는데, 그러면
// 실제 Firebase Authentication 계정에 등록된 이메일(합성 이메일, 예: new1@ptdiary.app)은
// 그대로 남아있어서, 나중에 그 예전 아이디를 다른 회원에게 다시 줄 수가 없었다(이메일 중복 오류).
// 그래서 관리자 권한(Admin SDK)으로 실제 Auth 이메일도 새 아이디에 맞춰 같이 바꿔줘서, 예전
// 아이디가 정말로 자유로워지게 한다.
//
// 복구 이메일로 가입해서 진짜 이메일을 쓰는 계정은 애초에 아이디와 Auth 이메일이 무관해서 이
// 문제가 생기지 않으므로, 그런 계정은 Auth 이메일을 건드리지 않는다.

const crypto = require('crypto');
const admin = require('firebase-admin');

const FIREBASE_PROJECT_ID = 'pt-diary-daf4e';
const GOOGLE_CERTS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
const SYNTHETIC_EMAIL_DOMAIN = '@ptdiary.app';
const ADMIN_UID = 'xcYFACPlU9YhCWBjxnDM1lRCAYz1'; // 앱 안에서 관리자로 취급하는 고정 UID와 동일

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

// 클라이언트(index.html)의 usernameDocId()와 정확히 같은 규칙으로 정규화해야, 같은 아이디가
// 항상 같은 문서 id로 매핑된다.
function usernameDocId(rawId) {
  return (rawId || '').trim().toLowerCase().replace(/[^a-z0-9._-]/g, '');
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
    const targetUid = (body.targetUid || callerUid).trim();
    const newDocId = usernameDocId(body.newRawId || '');
    if (newDocId.length < 3) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: '아이디는 영문/숫자 3자 이상으로 입력해주세요.' }) };
    }

    const db = admin.firestore();

    // 0) 남의(다른 회원의) 아이디를 바꾸려는 거라면, 관리자 본인이거나 그 회원을 담당하는
    //    트레이너일 때만 허용한다 — Firestore 보안 규칙의 usernames 쓰기 조건과 동일한 기준.
    if (targetUid !== callerUid && callerUid !== ADMIN_UID) {
      const callerDoc = await db.collection('users').doc(callerUid).get();
      const targetDoc = await db.collection('users').doc(targetUid).get();
      const callerIsTrainer = callerDoc.exists && callerDoc.data().isTrainer === true;
      const targetBelongsToCaller = targetDoc.exists && targetDoc.data().trainerId === callerUid;
      if (!callerIsTrainer || !targetBelongsToCaller) {
        return { statusCode: 403, headers, body: JSON.stringify({ error: '이 회원의 아이디를 바꿀 권한이 없어요.' }) };
      }
    }

    // 1) 새 아이디가 이미 다른 사람 것이면 거부한다 (본인이 예전에 쓰던 아이디로 되돌리는 건 허용)
    const newDocRef = db.collection('usernames').doc(newDocId);
    const newDocSnap = await newDocRef.get();
    const alreadyTarget = newDocSnap.exists && newDocSnap.data().uid === targetUid;
    if (newDocSnap.exists && !alreadyTarget) {
      return { statusCode: 409, headers, body: JSON.stringify({ error: '이미 사용 중인 아이디예요.' }) };
    }

    // 2) 지금 Auth 계정에 등록된 이메일이 '합성 이메일'인지 확인한다.
    //    합성 이메일이면 새 아이디에 맞춰 실제 Auth 이메일도 같이 바꿔서, 예전 아이디가 진짜로
    //    자유로워지게 한다. 복구 이메일(진짜 이메일)을 쓰는 계정은 건드리지 않는다.
    const userRecord = await admin.auth().getUser(targetUid);
    const currentEmail = userRecord.email || '';
    const isSynthetic = currentEmail.toLowerCase().endsWith(SYNTHETIC_EMAIL_DOMAIN);
    let finalEmail = currentEmail;

    if (isSynthetic) {
      const newSyntheticEmail = `${newDocId}${SYNTHETIC_EMAIL_DOMAIN}`;
      if (newSyntheticEmail !== currentEmail.toLowerCase()) {
        await admin.auth().updateUser(targetUid, { email: newSyntheticEmail });
      }
      finalEmail = newSyntheticEmail;
    }

    // 3) 새 아이디 문서를 쓰고, 이 계정에 연결된 예전 아이디 문서는 전부 지운다
    //    (where('uid','==',targetUid)로 찾아서 지우기 때문에, 혹시 남아있던 다른 예전 문서까지 같이 정리된다)
    await newDocRef.set({ email: finalEmail, uid: targetUid });

    const staleSnap = await db.collection('usernames').where('uid', '==', targetUid).get();
    const toDelete = staleSnap.docs.filter((doc) => doc.id !== newDocId);
    if (toDelete.length) {
      const batch = db.batch();
      toDelete.forEach((doc) => batch.delete(doc.ref));
      await batch.commit();
    }

    return { statusCode: 200, headers, body: JSON.stringify({ ok: true, email: finalEmail }) };
  } catch (err) {
    console.error('아이디 변경 오류:', err);
    const msg = err.code === 'auth/email-already-exists'
      ? '이미 사용 중인 아이디예요.'
      : (err.message || '아이디 변경에 실패했어요.');
    return { statusCode: 500, headers, body: JSON.stringify({ error: msg }) };
  }
};
