const express = require('express');
const cors = require('cors');
const fetch = require('node-fetch');
const bcrypt = require('bcryptjs');

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// 보안: 허용된 도메인만 프록시 가능
const ALLOWED_DOMAINS = ['api.commerce.naver.com'];

// API 키 인증 (선택사항 - 보안 강화)
const PROXY_API_KEY = process.env.PROXY_API_KEY || 'your-secret-key';

// 헬스 체크
app.get('/', (req, res) => {
    res.json({ status: 'ok', message: 'Naver Commerce API Proxy' });
});

// 토큰 발급 전용 엔드포인트 (bcrypt 서명 생성 포함)
app.post('/token', async (req, res) => {
    try {
        // API 키 확인
        const apiKey = req.headers['x-api-key'];
        if (apiKey !== PROXY_API_KEY) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const { client_id, client_secret } = req.body;
        const timestamp = Date.now().toString();

        // bcrypt 서명 생성
        const password = client_id + "_" + timestamp;
        const hashed = bcrypt.hashSync(password, client_secret);
        const clientSecretSign = Buffer.from(hashed).toString('base64');

        // 네이버 토큰 요청
        const tokenResponse = await fetch(
            'https://api.commerce.naver.com/external/v1/oauth2/token',
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: new URLSearchParams({
                    client_id: client_id,
                    timestamp: timestamp,
                    client_secret_sign: clientSecretSign,
                    grant_type: 'client_credentials',
                    type: 'SELF'
                }).toString()
            }
        );

        const data = await tokenResponse.json();
        res.json({ ...data, issued_at: Date.now() });

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

// 범용 프록시 엔드포인트
app.all('/proxy', async (req, res) => {
    try {
        // API 키 확인
        const apiKey = req.headers['x-api-key'];
        if (apiKey !== PROXY_API_KEY) {
            return res.status(401).json({ error: 'Unauthorized' });
        }

        const targetUrl = req.query.url;
        if (!targetUrl) {
            return res.status(400).json({ error: 'url parameter required' });
        }

        // 도메인 화이트리스트 확인
        const url = new URL(targetUrl);
        if (!ALLOWED_DOMAINS.includes(url.hostname)) {
            return res.status(403).json({ error: 'Domain not allowed' });
        }

        // 원본 요청 헤더에서 프록시 관련 헤더 제거 후 전달
        const headers = { ...req.headers };
        delete headers['host'];
        delete headers['x-api-key'];

        const response = await fetch(targetUrl, {
            method: req.method,
            headers: headers,
            body: ['POST', 'PUT', 'PATCH'].includes(req.method)
                ? JSON.stringify(req.body)
                : undefined
        });

        const data = await response.json();
        res.status(response.status).json(data);

    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
    console.log(`Proxy server running on port ${PORT}`);
});
