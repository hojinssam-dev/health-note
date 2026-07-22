// netlify/functions/identify-exercise.js
//
// 사진을 보내면, 로그인한 사용자에 한해 Claude(비전 모델)에게 "이 운동 기구가 뭐야?"라고
// 물어보고 이름을 받아온다. cloudinary-sign.js와 같은 방식으로, 외부 라이브러리 없이
// Node 내장 기능만 사용해서 별도 설치(npm install) 없이 그대로 배포된다.

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

  return payload;
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
    await verifyFirebaseIdToken(authHeader.slice(7));

    const apiKey = process.env.ANTHROPIC_API_KEY;
    if (!apiKey) {
      return { statusCode: 500, headers, body: JSON.stringify({ error: '서버에 AI 설정이 안 되어 있어요.' }) };
    }

    const body = JSON.parse(event.body || '{}');
    const { imageBase64, mediaType } = body;
    if (!imageBase64 || !mediaType) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: '사진 데이터가 없어요.' }) };
    }
    // 너무 큰 이미지는 거절 (base64 기준 대략 6MB 초과)
    if (imageBase64.length > 8_000_000) {
      return { statusCode: 400, headers, body: JSON.stringify({ error: '사진 용량이 너무 커요.' }) };
    }

    const aiRes = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
      },
      body: JSON.stringify({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 100,
        messages: [{
          role: 'user',
          content: [
            { type: 'image', source: { type: 'base64', media_type: mediaType, data: imageBase64 } },
            {
              type: 'text',
              text: '이 사진은 헬스장 운동 기구나 운동 동작 사진이야. 사진 속 기구/운동의 한국어 이름을 아주 짧게(2~6글자, 예: "렛풀다운", "레그프레스", "벤치프레스") 알려줘. 다른 설명 없이 이름만 답해줘. 만약 운동 기구나 운동 동작이 아닌 것 같으면 "인식불가"라고만 답해줘.',
            },
          ],
        }],
      }),
    });

    if (!aiRes.ok) {
      const errText = await aiRes.text();
      console.error('Anthropic API 오류:', aiRes.status, errText);
      return { statusCode: 502, headers, body: JSON.stringify({ error: 'AI 인식에 실패했어요.' }) };
    }

    const aiData = await aiRes.json();
    const textBlock = (aiData.content || []).find(b => b.type === 'text');
    const name = textBlock ? textBlock.text.trim() : '';

    if (!name || name.includes('인식불가')) {
      return { statusCode: 200, headers, body: JSON.stringify({ name: null }) };
    }

    return { statusCode: 200, headers, body: JSON.stringify({ name }) };
  } catch (err) {
    return { statusCode: 401, headers, body: JSON.stringify({ error: err.message || '인증에 실패했어요.' }) };
  }
};
