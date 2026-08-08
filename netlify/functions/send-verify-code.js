// netlify/functions/send-verify-code.js
//
// 로그인한 사용자에게, 입력한 이메일 주소로 "인증 링크"가 담긴 메일을 보내주는 함수.
// 네이버 계정(SMTP)으로 직접 발송해서, 해외(Firebase 기본) 발신 메일보다 스팸 처리가 덜 되도록 한다.
//
// 예전 방식(6자리 번호 입력)과 달리, 이번엔 메일 속 링크를 누르기만 하면 끝나는 방식이다.
// 그래서 서버에는 아무것도 저장하지 않고, "누구의(uid) 어떤 이메일을, 언제까지" 인증하는 링크인지를
// 링크 안에 통째로 담아서(서명까지 붙여서) 보낸다. 나중에 verify-email-link.js가 이 링크를 열었을 때
// 서명이 맞는지만 확인하면 되므로, 데이터베이스 조회 없이도 위조를 막을 수 있다.

const crypto = require('crypto');

const FIREBASE_PROJECT_ID = 'pt-diary-daf4e';
const GOOGLE_CERTS_URL = 'https://www.googleapis.com/robot/v1/metadata/x509/securetoken@system.gserviceaccount.com';
const LINK_VALID_MS = 30 * 60 * 1000; // 링크 유효 시간(30분)

function base64UrlDecode(str) {
  str = str.replace(/-/g, '+').replace(/_/g, '/');
  while (str.length % 4) str += '=';
  return Buffer.from(str, 'base64').toString('utf8');
}
function base64UrlEncode(str) {
  return Buffer.from(str, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
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

// uid + email + 만료시각을 하나로 묶어서, 비밀키로 서명한 토큰을 만든다.
// 토큰 자체에 정보가 다 들어있어서, 서버에 따로 저장할 필요가 없다.
function buildLinkToken(secret, uid, email, expiresAt) {
  const data = JSON.stringify({ uid, email, exp: expiresAt });
  const encoded = base64UrlEncode(data);
  const signature = crypto.createHmac('sha256', secret).update(encoded).digest('hex');
  return `${encoded}.${signature}`;
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

    const body = JSON.parse(event.body || '{}');
    const email = (body.email || '').trim();
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: '이메일 형식을 확인해주세요.' }) };
    }

    const secret = process.env.EMAIL_CODE_SECRET;
    const naverUser = process.env.NAVER_SMTP_USER;
    const naverPass = process.env.NAVER_SMTP_PASS;
    const siteUrl = process.env.SITE_URL || 'https://health-note.pe.kr';
    if (!secret || !naverUser || !naverPass) {
      return { statusCode: 500, headers, body: JSON.stringify({ error: '서버에 이메일 발송 설정이 안 되어 있어요.' }) };
    }

    const expiresAt = Date.now() + LINK_VALID_MS;
    const token = buildLinkToken(secret, payload.sub, email, expiresAt);
    const verifyUrl = `${siteUrl}/.netlify/functions/verify-email-link?token=${encodeURIComponent(token)}`;

    const nodemailer = require('nodemailer');
    const transporter = nodemailer.createTransport({
      host: 'smtp.naver.com',
      port: 587,
      secure: false, // 587 포트는 STARTTLS 방식
      auth: { user: naverUser, pass: naverPass },
    });

    await transporter.sendMail({
      from: `"운동 일지" <${naverUser}@naver.com>`,
      to: email,
      subject: '[운동 일지] 이메일 인증을 완료해주세요',
      text: `아래 링크를 눌러 이메일 인증을 완료해주세요 (30분 이내 유효):\n${verifyUrl}`,
      html: `
        <div style="font-family: sans-serif; padding: 20px;">
          <p>이메일 인증을 완료하려면 아래 버튼을 눌러주세요.</p>
          <p><a href="${verifyUrl}" style="display:inline-block; padding:12px 24px; background:#C9A227; color:#191F1D; text-decoration:none; border-radius:8px; font-weight:bold;">이메일 인증 완료하기</a></p>
          <p style="color: #888; font-size: 13px;">버튼이 안 눌리면 이 주소를 복사해서 브라우저에 붙여넣어 주세요:<br>${verifyUrl}</p>
          <p style="color: #888; font-size: 13px;">30분 안에 눌러주세요. 본인이 요청하지 않았다면 이 메일은 무시하셔도 돼요.</p>
        </div>
      `,
    });

    return { statusCode: 200, headers, body: JSON.stringify({ ok: true }) };
  } catch (err) {
    console.error('이메일 발송 오류:', err);
    return { statusCode: 500, headers, body: JSON.stringify({ error: err.message || '메일 발송에 실패했어요.' }) };
  }
};
