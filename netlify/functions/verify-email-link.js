// netlify/functions/verify-email-link.js
//
// 메일 속 "이메일 인증 완료하기" 링크를 누르면 호출되는 함수.
// send-verify-code.js가 만들어준 서명된 토큰을 확인해서, 위조되지 않았고 아직 유효기간
// 안이면 실제로 그 계정의 이메일을 바꿔준다. 그 자리에서 바로 결과를 보여주는 간단한
// HTML 페이지를 돌려준다 (앱이 아니라 메일 앱/브라우저에서 바로 열리는 링크라서).

const crypto = require('crypto');
const admin = require('firebase-admin');

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString('utf8');
}

function verifyLinkToken(secret, token) {
  const [encoded, signature] = (token || '').split('.');
  if (!encoded || !signature) throw new Error('링크가 올바르지 않아요.');

  const expectedSig = crypto.createHmac('sha256', secret).update(encoded).digest('hex');
  const sigBuf = Buffer.from(signature, 'hex');
  const expectedBuf = Buffer.from(expectedSig, 'hex');
  if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
    throw new Error('링크가 위조되었거나 손상됐어요.');
  }

  const data = JSON.parse(base64UrlDecode(encoded));
  if (!data.uid || !data.email || !data.exp) throw new Error('링크 정보가 올바르지 않아요.');
  if (Date.now() > data.exp) throw new Error('링크 유효 시간이 지났어요. 다시 요청해주세요.');

  return data; // { uid, email, exp }
}

function htmlPage(title, message, isError) {
  return {
    statusCode: isError ? 400 : 200,
    headers: { 'Content-Type': 'text/html; charset=utf-8' },
    body: `
      <!DOCTYPE html>
      <html lang="ko">
      <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1">
        <title>${title}</title>
        <style>
          body{ margin:0; padding:40px 20px; background:#191F1D; color:#EFEAE0; font-family: -apple-system, BlinkMacSystemFont, sans-serif; text-align:center; }
          h1{ font-size:20px; margin-bottom:12px; color: ${isError ? '#E0574A' : '#C9A227'}; }
          p{ color:#93998F; font-size:15px; line-height:1.6; }
        </style>
      </head>
      <body>
        <h1>${title}</h1>
        <p>${message}</p>
      </body>
      </html>
    `,
  };
}

if (!admin.apps.length) {
  const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY || '{}');
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
}

exports.handler = async (event) => {
  if (event.httpMethod !== 'GET') {
    return htmlPage('잘못된 요청', '허용되지 않은 방식이에요.', true);
  }

  try {
    const token = (event.queryStringParameters || {}).token;
    const secret = process.env.EMAIL_CODE_SECRET;
    if (!secret) return htmlPage('오류', '서버 설정이 안 되어 있어요.', true);

    const { uid, email } = verifyLinkToken(secret, token);

    // 실제로 이 계정의 이메일을 바꾼다
    await admin.auth().updateUser(uid, { email, emailVerified: true });

    // usernames 컬렉션에서 이 uid의 로그인 아이디 문서를 찾아서 email 필드도 같이 갱신한다
    const db = admin.firestore();
    const snap = await db.collection('usernames').where('uid', '==', uid).limit(1).get();
    if (!snap.empty) {
      await snap.docs[0].ref.set({ email }, { merge: true });
    }

    return htmlPage('이메일 인증 완료', '이메일이 등록됐어요. 이제 이 창은 닫으셔도 돼요.', false);
  } catch (err) {
    console.error('이메일 링크 인증 오류:', err);
    const msg = err.code === 'auth/email-already-exists'
      ? '이미 다른 계정에서 쓰고 있는 이메일이에요.'
      : (err.message || '인증에 실패했어요.');
    return htmlPage('인증 실패', msg, true);
  }
};
