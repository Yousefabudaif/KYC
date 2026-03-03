require('dotenv').config();
const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const multer = require('multer');
const fetch = require('node-fetch');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { execSync } = require('child_process');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3000;

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Middleware — raw body needed for webhook signature verification
app.use('/api/webhook/didit', express.raw({ type: 'application/json' }));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({
    secret: process.env.SESSION_SECRET || 'kyc-secret',
    resave: false,
    saveUninitialized: false,
    cookie: { maxAge: 24 * 60 * 60 * 1000 } // 24 hours
}));

// File upload config — memory storage (files stored in DB, not on disk)
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 15 * 1024 * 1024 }, // 15MB
    fileFilter: (req, file, cb) => {
        const allowed = ['application/pdf', 'image/jpeg', 'image/png', 'image/jpg', 'image/webp'];
        if (allowed.includes(file.mimetype)) cb(null, true);
        else cb(new Error('Only PDF, JPG, PNG, or WebP files are allowed'));
    }
});

// Initialize database tables
async function initDB() {
    const client = await pool.connect();
    try {
        await client.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT NOW()
            );
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS kyc_results (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                session_id VARCHAR(255),
                status VARCHAR(50) DEFAULT 'pending',
                full_name_ar VARCHAR(255),
                id_number VARCHAR(50),
                verification_data JSONB,
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );
        `);
        await client.query(`
            CREATE TABLE IF NOT EXISTS signups (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id),
                kyc_result_id INTEGER REFERENCES kyc_results(id),
                signed_pdf_path VARCHAR(500),
                signed_pdf_data BYTEA,
                signed_pdf_mimetype VARCHAR(100),
                signature_confidence FLOAT,
                signature_detected BOOLEAN,
                status VARCHAR(50) DEFAULT 'pending',
                created_at TIMESTAMP DEFAULT NOW(),
                updated_at TIMESTAMP DEFAULT NOW()
            );
        `);
        // Add new columns if they don't exist (for existing databases)
        await client.query('ALTER TABLE signups ADD COLUMN IF NOT EXISTS signed_pdf_data BYTEA');
        await client.query('ALTER TABLE signups ADD COLUMN IF NOT EXISTS signed_pdf_mimetype VARCHAR(100)');
        await client.query('ALTER TABLE signups ADD COLUMN IF NOT EXISTS signature_confidence FLOAT');
        await client.query('ALTER TABLE signups ADD COLUMN IF NOT EXISTS signature_detected BOOLEAN');
        console.log('Database tables initialized successfully');
    } catch (err) {
        console.error('Error initializing database:', err);
    } finally {
        client.release();
    }
}

// Auth middleware
function requireAuth(req, res, next) {
    if (req.session && req.session.userId) return next();
    res.status(401).json({ error: 'Please log in first' });
}

function requireAdmin(req, res, next) {
    if (req.session && req.session.isAdmin) return next();
    res.status(403).json({ error: 'Admin access required' });
}

// =================== AUTH ROUTES ===================

app.post('/api/signup', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });
        if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });

        const existing = await pool.query('SELECT id FROM users WHERE email = $1', [email]);
        if (existing.rows.length > 0) return res.status(409).json({ error: 'Email already registered' });

        const passwordHash = await bcrypt.hash(password, 12);
        const result = await pool.query(
            'INSERT INTO users (email, password_hash) VALUES ($1, $2) RETURNING id',
            [email, passwordHash]
        );

        req.session.userId = result.rows[0].id;
        req.session.email = email;
        res.json({ success: true, userId: result.rows[0].id });
    } catch (err) {
        console.error('Signup error:', err);
        res.status(500).json({ error: 'Server error during signup' });
    }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ error: 'Email and password are required' });

        const result = await pool.query('SELECT id, password_hash FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(401).json({ error: 'Invalid email or password' });

        const valid = await bcrypt.compare(password, result.rows[0].password_hash);
        if (!valid) return res.status(401).json({ error: 'Invalid email or password' });

        req.session.userId = result.rows[0].id;
        req.session.email = email;

        // Check if user already completed KYC
        const kyc = await pool.query(
            'SELECT status FROM kyc_results WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
            [result.rows[0].id]
        );

        // Check if user already has a pending/approved signup
        const signup = await pool.query(
            'SELECT status FROM signups WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
            [result.rows[0].id]
        );

        let redirectTo = '/kyc.html';
        if (signup.rows.length > 0) {
            if (signup.rows[0].status === 'pending') redirectTo = '/success.html';
            else if (signup.rows[0].status === 'approved') redirectTo = '/success.html';
        } else if (kyc.rows.length > 0 && kyc.rows[0].status === 'Approved') {
            redirectTo = '/pdf.html';
        }

        res.json({ success: true, redirectTo });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error during login' });
    }
});

app.post('/api/logout', (req, res) => {
    req.session.destroy();
    res.json({ success: true });
});

app.get('/api/me', requireAuth, async (req, res) => {
    try {
        const user = await pool.query('SELECT id, email FROM users WHERE id = $1', [req.session.userId]);
        const kyc = await pool.query(
            'SELECT * FROM kyc_results WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
            [req.session.userId]
        );
        const signup = await pool.query(
            'SELECT * FROM signups WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
            [req.session.userId]
        );
        res.json({
            user: user.rows[0],
            kyc: kyc.rows[0] || null,
            signup: signup.rows[0] || null
        });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get user info' });
    }
});

// =================== KYC ROUTES ===================

app.post('/api/kyc/create-session', requireAuth, async (req, res) => {
    try {
        const apiKey = process.env.DIDIT_API_KEY;
        const workflowId = process.env.DIDIT_WORKFLOW_ID;

        console.log('[KYC] Creating session for user:', req.session.userId);
        console.log('[KYC] Workflow ID:', workflowId);
        console.log('[KYC] API Key (first 10 chars):', apiKey ? apiKey.substring(0, 10) + '...' : 'MISSING');

        const requestBody = {
            workflow_id: workflowId,
            vendor_data: String(req.session.userId),
            callback: `http://localhost:${PORT}/kyc.html`
        };

        console.log('[KYC] Request body:', JSON.stringify(requestBody));

        // Create a Didit verification session via API
        const response = await fetch('https://verification.didit.me/v3/session/', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'x-api-key': apiKey
            },
            body: JSON.stringify(requestBody)
        });

        const responseText = await response.text();
        console.log('[KYC] Didit API response status:', response.status);
        console.log('[KYC] Didit API response body:', responseText);

        let data;
        try {
            data = JSON.parse(responseText);
        } catch (e) {
            console.error('[KYC] Failed to parse Didit response as JSON:', responseText);
            return res.status(500).json({ error: 'Invalid response from verification service', rawResponse: responseText });
        }

        if (!response.ok) {
            console.error('[KYC] Didit session creation failed:', response.status, data);
            return res.status(response.status).json({ error: 'Failed to create verification session', details: data });
        }

        console.log('[KYC] Session created successfully:', data.session_id);
        // IMPORTANT: Didit API returns "url" not "verification_url"
        const verificationUrl = data.url || data.verification_url;
        console.log('[KYC] Verification URL:', verificationUrl);
        console.log('[KYC] Session Token:', data.session_token);

        // Store session reference in DB
        await pool.query(
            'INSERT INTO kyc_results (user_id, session_id, status) VALUES ($1, $2, $3)',
            [req.session.userId, data.session_id, 'Not Started']
        );

        res.json({
            success: true,
            verificationUrl: verificationUrl,
            sessionId: data.session_id,
            sessionToken: data.session_token
        });
    } catch (err) {
        console.error('[KYC] Session creation error:', err);
        res.status(500).json({ error: 'Failed to create KYC session', message: err.message });
    }
});

// Re-check KYC status by polling Didit API for the latest decision
app.post('/api/kyc/check-status', requireAuth, async (req, res) => {
    try {
        const { sessionId } = req.body;
        if (!sessionId) return res.status(400).json({ error: 'sessionId required' });

        console.log('[KYC] Checking status from Didit for session:', sessionId);

        // Fetch current decision from Didit
        const detailsResponse = await fetch(
            'https://verification.didit.me/v3/session/' + sessionId + '/decision/',
            { headers: { 'x-api-key': process.env.DIDIT_API_KEY } }
        );

        if (!detailsResponse.ok) {
            console.log('[KYC] Didit returned', detailsResponse.status);
            return res.json({ status: 'pending', message: 'Verification still in progress' });
        }

        const details = JSON.parse(await detailsResponse.text());
        const diditStatus = details.status || details.session_status;
        console.log('[KYC] Didit current status:', diditStatus);

        // Map Didit status to our status
        var mappedStatus;
        if (diditStatus === 'Approved') {
            mappedStatus = 'Approved';
        } else if (diditStatus === 'Declined') {
            mappedStatus = 'Declined';
        } else {
            mappedStatus = diditStatus || 'pending';
        }

        // If now Approved, extract user data
        if (mappedStatus === 'Approved') {
            let fullNameAr = '';
            let idNumber = '';

            const idvArray = details.id_verifications;
            if (Array.isArray(idvArray) && idvArray.length > 0) {
                const idv = idvArray[0];
                fullNameAr = idv.full_name || '';
                idNumber = idv.personal_number || idv.document_number || '';
            }

            console.log('[KYC] Now approved! Name:', fullNameAr, 'ID:', idNumber);

            await pool.query(
                'UPDATE kyc_results SET status = $1, full_name_ar = $2, id_number = $3, verification_data = $4, updated_at = NOW() WHERE session_id = $5 AND user_id = $6',
                [mappedStatus, fullNameAr, idNumber, JSON.stringify(details), sessionId, req.session.userId]
            );
        } else {
            await pool.query(
                'UPDATE kyc_results SET status = $1, updated_at = NOW() WHERE session_id = $2 AND user_id = $3',
                [mappedStatus, sessionId, req.session.userId]
            );
        }

        res.json({ status: mappedStatus });
    } catch (err) {
        console.error('[KYC] Check status error:', err);
        res.status(500).json({ error: 'Failed to check status' });
    }
});

// Fetch session decision from Didit API and store user details
app.post('/api/kyc/update-status', requireAuth, async (req, res) => {
    try {
        const { sessionId, status } = req.body;
        console.log('[KYC] Updating status:', sessionId, status);

        await pool.query(
            'UPDATE kyc_results SET status = $1, updated_at = NOW() WHERE session_id = $2 AND user_id = $3',
            [status, sessionId, req.session.userId]
        );

        // If approved, fetch the verification decision from Didit
        if (status === 'Approved') {
            try {
                console.log('[KYC] Fetching decision for session:', sessionId);
                const detailsResponse = await fetch(`https://verification.didit.me/v3/session/${sessionId}/decision/`, {
                    headers: { 'x-api-key': process.env.DIDIT_API_KEY }
                });

                const detailsText = await detailsResponse.text();
                console.log('[KYC] Decision response status:', detailsResponse.status);
                console.log('[KYC] Decision response:', detailsText.substring(0, 500));

                if (detailsResponse.ok) {
                    const details = JSON.parse(detailsText);

                    // Extract name and ID from the decision data model
                    // IMPORTANT: id_verifications is an ARRAY, not an object!
                    let fullNameAr = '';
                    let idNumber = '';

                    const idvArray = details.id_verifications;
                    if (Array.isArray(idvArray) && idvArray.length > 0) {
                        const idv = idvArray[0];
                        // full_name contains the complete Arabic name
                        fullNameAr = idv.full_name || '';
                        // personal_number is the national ID (14 digits), document_number is the card serial
                        idNumber = idv.personal_number || idv.document_number || '';
                    }

                    console.log('[KYC] Extracted name:', fullNameAr, 'ID:', idNumber);

                    await pool.query(
                        'UPDATE kyc_results SET full_name_ar = $1, id_number = $2, verification_data = $3 WHERE session_id = $4',
                        [fullNameAr, idNumber, detailsText, sessionId]
                    );
                }
            } catch (detailErr) {
                console.error('[KYC] Error fetching verification details:', detailErr);
            }
        }

        res.json({ success: true });
    } catch (err) {
        console.error('[KYC] Status update error:', err);
        res.status(500).json({ error: 'Failed to update KYC status' });
    }
});

// Webhook endpoint — receives real-time results from Didit
app.post('/api/webhook/didit', async (req, res) => {
    try {
        const rawBody = req.body;
        const signature = req.headers['x-signature-v2'];

        // Verify webhook signature if secret is set
        const webhookSecret = process.env.DIDIT_WEBHOOK_SECRET;
        if (webhookSecret && signature) {
            const expectedSig = crypto.createHmac('sha256', webhookSecret)
                .update(rawBody)
                .digest('hex');
            if (signature !== expectedSig) {
                console.error('[Webhook] Invalid signature');
                return res.status(401).json({ error: 'Invalid signature' });
            }
        }

        const payload = JSON.parse(rawBody.toString());
        console.log('[Webhook] Received:', JSON.stringify(payload).substring(0, 500));

        const { session_id, status, vendor_data } = payload;

        if (session_id && status) {
            // Update KYC status
            await pool.query(
                'UPDATE kyc_results SET status = $1, updated_at = NOW() WHERE session_id = $2',
                [status, session_id]
            );

            // If approved, extract and store identity details
            if (status === 'Approved') {
                const idvArray = payload.id_verifications || payload.decision?.id_verifications;
                let fullNameAr = '';
                let idNumber = '';

                if (Array.isArray(idvArray) && idvArray.length > 0) {
                    const idv = idvArray[0];
                    fullNameAr = idv.full_name || '';
                    idNumber = idv.personal_number || idv.document_number || '';
                }

                await pool.query(
                    'UPDATE kyc_results SET full_name_ar = $1, id_number = $2, verification_data = $3 WHERE session_id = $4',
                    [fullNameAr, idNumber, JSON.stringify(payload), session_id]
                );
                console.log('[Webhook] Stored identity: name=', fullNameAr, 'id=', idNumber);
            }
        }

        res.status(200).json({ received: true });
    } catch (err) {
        console.error('[Webhook] Error:', err);
        res.status(500).json({ error: 'Webhook processing failed' });
    }
});

app.get('/api/kyc/session-info', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT * FROM kyc_results WHERE user_id = $1 ORDER BY created_at DESC LIMIT 1',
            [req.session.userId]
        );
        res.json({ session: result.rows[0] || null });
    } catch (err) {
        res.status(500).json({ error: 'Failed to get session info' });
    }
});

// =================== PDF ROUTES ===================

// Path to Tectonic binary (bundled with the project for deployment)
const TECTONIC_BIN = path.join(__dirname, 'bin', process.platform === 'win32' ? 'tectonic.exe' : 'tectonic');

function generateLatexSource(fullName, idNumber, dateStr) {
    // Escape LaTeX special characters in user data
    const esc = (s) => (s || '').replace(/\\/g, '\\textbackslash{}').replace(/[&%$#_{}~^]/g, '\\$&');
    const safeName = esc(fullName);
    const safeId = esc(idNumber);
    const safeDate = esc(dateStr);

    return `% !TEX program = xelatex
\\documentclass[12pt,a4paper]{article}

% ---- Page setup ----
\\usepackage[a4paper,margin=1.7cm]{geometry}
\\usepackage{setspace}
\\setstretch{1.15}
\\setlength{\\parindent}{0pt}
\\usepackage{enumitem}
\\usepackage{array}
\\usepackage{hyperref}
\\hypersetup{colorlinks=true, urlcolor=blue, linkcolor=black}

% ---- Arabic (XeLaTeX) ----
\\usepackage{fontspec}
\\usepackage{polyglossia}
\\setmainlanguage{arabic}
\\setotherlanguage{english}
\\newfontfamily\\arabicfont[Path=./,Script=Arabic,Scale=1.015]{Amiri-Regular.ttf}

\\pagenumbering{gobble}

\\begin{document}

\\begin{center}
{\\Large \\textbf{إقرار وتعهد منظم فعاليات}}\\\\
\\vspace{0.15cm}\\hrule
\\end{center}

\\vspace{0.25cm}

أنا المُوقّع أدناه، أُقرّ وأتعهد بصفتي \\textbf{منظم فعاليات} على منصة \\textbf{Tegy}، بأن ما يلي يُعد شرطًا لازمًا لاستخدام حسابي في إنشاء الفعاليات وطرح وبيع التذاكر عبر المنصة:

\\vspace{0.25cm}
\\textbf{(1) صحة البيانات والهوية:} أقر بأن بياناتي صحيحة ومطابقة لبطاقة الرقم القومي، وأتحمل كامل المسؤولية القانونية عن أي بيانات غير صحيحة أو مُضلِّلة.

\\textbf{(2) مسؤولية الفعالية:} أقر بأنني المسؤول الوحيد عن الفعاليات التي أنشئها عبر حسابي، بما في ذلك محتوى الفعالية، تنظيمها، تنفيذها، والتصاريح/الموافقات اللازمة (إن وجدت) وأي التزامات تجاه المستخدمين أو الغير.

\\textbf{(3) الالتزام بتنفيذ الفعالية كما هي مُعلنة:} أتعهد بتنفيذ الفعالية وفق التفاصيل المعروضة للمستخدمين على المنصة (التاريخ/الوقت/المكان/سعة التذاكر/السعر/المزايا المُعلنة) وعدم تقديم أي معلومات مضللة.

\\textbf{(4) حظر الاحتيال:} أتعهد بعدم إنشاء فعاليات وهمية أو تحصيل مبالغ دون تقديم الخدمة فعليًا، وأوافق أن أي شبهة احتيال تُعرّض حسابي للإيقاف واتخاذ الإجراءات النظامية/القانونية.

\\textbf{(5) الإلغاء أو التأجيل أو التغيير الجوهري:} في حال إلغاء الفعالية أو تأجيلها أو حدوث تغيير جوهري يؤثر على قرار الشراء، ألتزم بـ:
\\begin{itemize}[nosep,leftmargin=1.1cm]
  \\item إخطار المستخدمين عبر المنصة فورًا وبحد أقصى خلال 24 ساعة من اتخاذ القرار.
  \\item تحمل مسؤولية \\textbf{رد الأموال} للمستخدمين وفق سياسة الاسترداد المعتمدة بالمنصة وشروط الفعالية المعلنة وبما لا يخالف القوانين المصرية.
\\end{itemize}

\\textbf{(6) رد الأموال والتسويات:} أتعهد برد أي مبالغ مستحقة للمستخدمين في الحالات التي تستوجب ذلك وفق سياسة المنصة، وأوافق على قيام المنصة بإجراء التسويات المالية بالطريقة التي تحددها (بما في ذلك خصم الرسوم/العمولات إن وُجدت وفق شروط الاستخدام).

\\textbf{(7) الالتزام بالقانون وحقوق الغير:} أتعهد بعدم مخالفة القوانين المصرية أو النظام العام أو الآداب العامة، وباحترام حقوق الملكية الفكرية وحقوق الغير، وأتحمل وحدي تبعات أي مخالفة.

\\textbf{(8) التعويض وإبراء مسؤولية المنصة:} أتعهد بتعويض المنصة عن أي خسائر/مطالبات/أضرار/تكاليف (بما فيها أتعاب المحاماة) تنتج عن احتيال أو إهمال أو مخالفة مني لهذا الإقرار أو لشروط استخدام المنصة أو بسبب عدم تنفيذ الفعالية أو تغييرها بشكل غير مشروع.

\\textbf{(9) صلاحيات المنصة عند المخالفة:} أوافق على حق المنصة في اتخاذ ما تراه مناسبًا عند الاشتباه في مخالفة، بما يشمل تعليق/إيقاف الحساب، إيقاف بيع التذاكر، تعليق صرف المستحقات، طلب مستندات إضافية، وإحالة الأمر للجهات المختصة.


\\vspace{0.3cm}
\\textbf{إقرار بالقراءة والقبول:}
أُقر أنني قرأت وفهمت البنود أعلاه وأوافق عليها دون إكراه، وأتحمل المسؤولية القانونية كاملة عن أي إخلال بها.

\\vspace{0.6cm}

\\textbf{الاسم بالكامل:} ${safeName}

\\vspace{0.8cm}

\\textbf{رقم بطاقة الرقم القومي:} ${safeId}

\\vspace{0.8cm}

\\textbf{التاريخ:} ${safeDate}

\\vspace{0.8cm}

\\textbf{التوقيع:}

\\end{document}
`;
}

app.get('/api/pdf/generate', requireAuth, async (req, res) => {
    let tmpDir = null;
    try {
        // Get user's KYC details
        const kyc = await pool.query(
            'SELECT full_name_ar, id_number FROM kyc_results WHERE user_id = $1 AND status = $2 ORDER BY created_at DESC LIMIT 1',
            [req.session.userId, 'Approved']
        );

        if (kyc.rows.length === 0) {
            return res.status(400).json({ error: 'KYC verification not completed' });
        }

        const { full_name_ar, id_number } = kyc.rows[0];

        // Get current Egypt date
        const egyptDate = new Date().toLocaleDateString('ar-EG', {
            timeZone: 'Africa/Cairo',
            year: 'numeric',
            month: 'long',
            day: 'numeric'
        });

        console.log('[PDF] Generating for:', full_name_ar, id_number, egyptDate);

        // Create temp directory for LaTeX compilation
        tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'kyc-pdf-'));
        const texFile = path.join(tmpDir, 'pledge.tex');
        const pdfFile = path.join(tmpDir, 'pledge.pdf');

        // Write LaTeX source with user data
        const latexSource = generateLatexSource(full_name_ar, id_number, egyptDate);
        fs.writeFileSync(texFile, latexSource, 'utf8');

        // Copy Amiri font into temp dir so LaTeX can find it via relative path
        const fontSrc = path.join(__dirname, 'fonts', 'Amiri-Regular.ttf');
        const fontDst = path.join(tmpDir, 'Amiri-Regular.ttf');
        fs.copyFileSync(fontSrc, fontDst);

        // Compile with Tectonic (XeLaTeX engine)
        console.log('[PDF] Compiling with Tectonic...');
        try {
            execSync(`"${TECTONIC_BIN}" "${texFile}"`, {
                cwd: tmpDir,
                timeout: 300000, // 5 min timeout (first run downloads packages)
                stdio: 'pipe',
                env: { ...process.env, OSFONTDIR: path.join(__dirname, 'fonts') }
            });
        } catch (compileErr) {
            // Tectonic exits with code 1 on warnings (e.g. "Color stack underflow")
            // but may still produce a valid PDF — check if output PDF exists
            const stderr = compileErr.stderr?.toString() || '';
            const pdfExists = fs.existsSync(pdfFile);
            if (pdfExists) {
                console.warn('[PDF] Tectonic had warnings but PDF was generated:', stderr.substring(0, 200));
            } else {
                console.error('[PDF] Tectonic compilation failed:', stderr || compileErr.message);
                return res.status(500).json({ error: 'PDF compilation failed', details: stderr });
            }
        }

        if (!fs.existsSync(pdfFile)) {
            return res.status(500).json({ error: 'PDF file was not generated' });
        }

        console.log('[PDF] Successfully generated');
        const pdfBytes = fs.readFileSync(pdfFile);

        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename="pledge.pdf"');
        res.send(pdfBytes);
    } catch (err) {
        console.error('PDF generation error:', err);
        res.status(500).json({ error: 'Failed to generate PDF' });
    } finally {
        // Clean up temp directory
        if (tmpDir && fs.existsSync(tmpDir)) {
            try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch (e) { }
        }
    }
});

// =================== ROBOFLOW SIGNATURE DETECTION ===================

async function detectSignatureRoboflow(fileBuffer) {
    const apiKey = process.env.ROBOFLOW_API_KEY;
    const modelId = process.env.ROBOFLOW_MODEL_ID || 'signature-zqoxq-pocrz/1';

    if (!apiKey) {
        console.warn('[Signature] No ROBOFLOW_API_KEY set');
        return { detected: false, confidence: 0, error: 'Not configured' };
    }

    try {
        const base64Image = fileBuffer.toString('base64');
        console.log('[Signature] Sending to Roboflow, size:', fileBuffer.length, 'bytes');

        const response = await fetch(
            'https://serverless.roboflow.com/' + modelId + '?api_key=' + apiKey,
            {
                method: 'POST',
                headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                body: base64Image
            }
        );

        const responseText = await response.text();
        console.log('[Signature] Roboflow status:', response.status);

        if (!response.ok) {
            console.error('[Signature] Roboflow error:', responseText.substring(0, 300));
            return { detected: false, confidence: 0, error: 'Service error' };
        }

        const result = JSON.parse(responseText);
        console.log('[Signature] Result:', JSON.stringify(result).substring(0, 500));

        if (result.predictions && result.predictions.length > 0) {
            const best = result.predictions.reduce((a, b) => a.confidence > b.confidence ? a : b);
            console.log('[Signature] Detected, confidence:', (best.confidence * 100).toFixed(1) + '%');
            return { detected: true, confidence: best.confidence };
        }

        return { detected: false, confidence: 0 };
    } catch (err) {
        console.error('[Signature] Error:', err.message);
        return { detected: false, confidence: 0, error: err.message };
    }
}

app.post('/api/pdf/upload', requireAuth, upload.single('signedPdf'), async (req, res) => {
    try {
        if (!req.file) return res.status(400).json({ error: 'No file uploaded' });

        const kyc = await pool.query(
            'SELECT id FROM kyc_results WHERE user_id = $1 AND status = $2 ORDER BY created_at DESC LIMIT 1',
            [req.session.userId, 'Approved']
        );

        if (kyc.rows.length === 0) {
            return res.status(400).json({ error: 'KYC verification not completed' });
        }

        const fileBuffer = req.file.buffer;
        const fileMimetype = req.file.mimetype;
        console.log('[Upload] Received:', req.file.originalname, fileMimetype, fileBuffer.length, 'bytes');

        // --- Signature Detection via Roboflow ---
        const sigResult = await detectSignatureRoboflow(fileBuffer);
        const signatureDetected = sigResult.detected;
        const signatureConfidence = sigResult.confidence;

        // Auto-approve if confidence > 50%, otherwise needs admin review
        var signupStatus;
        if (signatureDetected && signatureConfidence > 0.5) {
            signupStatus = 'approved';
            console.log('[Upload] Auto-approved, confidence:', (signatureConfidence * 100).toFixed(1) + '%');
        } else {
            signupStatus = 'pending';
            console.log('[Upload] Needs admin review, confidence:', (signatureConfidence * 100).toFixed(1) + '%');
        }

        // Store in DB (BYTEA)
        const existingSignup = await pool.query(
            'SELECT id FROM signups WHERE user_id = $1',
            [req.session.userId]
        );

        if (existingSignup.rows.length > 0) {
            await pool.query(
                'UPDATE signups SET signed_pdf_data = $1, signed_pdf_mimetype = $2, signature_confidence = $3, signature_detected = $4, status = $5, updated_at = NOW() WHERE user_id = $6',
                [fileBuffer, fileMimetype, signatureConfidence, signatureDetected, signupStatus, req.session.userId]
            );
        } else {
            await pool.query(
                'INSERT INTO signups (user_id, kyc_result_id, signed_pdf_data, signed_pdf_mimetype, signature_confidence, signature_detected, status) VALUES ($1, $2, $3, $4, $5, $6, $7)',
                [req.session.userId, kyc.rows[0].id, fileBuffer, fileMimetype, signatureConfidence, signatureDetected, signupStatus]
            );
        }

        if (signupStatus === 'approved') {
            res.json({
                success: true,
                autoApproved: true,
                message: 'Document uploaded and signature verified! Your signup is approved.',
                confidence: signatureConfidence
            });
        } else {
            res.json({
                success: true,
                autoApproved: false,
                message: signatureDetected
                    ? 'Document uploaded. Signature confidence is low \u2014 your signup will be reviewed by an admin.'
                    : 'Document uploaded. No signature was clearly detected \u2014 your signup will be reviewed by an admin.',
                confidence: signatureConfidence
            });
        }
    } catch (err) {
        console.error('PDF upload error:', err);
        res.status(500).json({ error: 'Failed to upload document' });
    }
});

// =================== ADMIN ROUTES ===================

const ADMIN_USERNAME = 'admin';
const ADMIN_PASSWORD = 'admin123';

app.post('/api/admin/login', async (req, res) => {
    const { username, password } = req.body;
    if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
        req.session.isAdmin = true;
        res.json({ success: true });
    } else {
        res.status(401).json({ error: 'Invalid admin credentials' });
    }
});

app.get('/api/admin/signups', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT 
                s.id, s.status, s.created_at,
                s.signature_confidence, s.signature_detected,
                s.signed_pdf_mimetype,
                (s.signed_pdf_data IS NOT NULL) as has_document,
                u.email,
                k.full_name_ar, k.id_number, k.status as kyc_status
            FROM signups s
            JOIN users u ON s.user_id = u.id
            LEFT JOIN kyc_results k ON s.kyc_result_id = k.id
            ORDER BY s.created_at DESC
        `);
        res.json({ signups: result.rows });
    } catch (err) {
        console.error('Admin signups error:', err);
        res.status(500).json({ error: 'Failed to fetch signups' });
    }
});

app.post('/api/admin/approve/:id', requireAdmin, async (req, res) => {
    try {
        await pool.query(
            'UPDATE signups SET status = $1, updated_at = NOW() WHERE id = $2',
            ['approved', req.params.id]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to approve signup' });
    }
});

app.post('/api/admin/reject/:id', requireAdmin, async (req, res) => {
    try {
        await pool.query(
            'UPDATE signups SET status = $1, updated_at = NOW() WHERE id = $2',
            ['rejected', req.params.id]
        );
        res.json({ success: true });
    } catch (err) {
        res.status(500).json({ error: 'Failed to reject signup' });
    }
});

// Download signed document from database
app.get('/api/admin/download/:id', requireAdmin, async (req, res) => {
    try {
        const result = await pool.query(
            'SELECT signed_pdf_data, signed_pdf_mimetype FROM signups WHERE id = $1',
            [req.params.id]
        );
        if (result.rows.length === 0 || !result.rows[0].signed_pdf_data) {
            return res.status(404).json({ error: 'Document not found' });
        }

        const { signed_pdf_data, signed_pdf_mimetype } = result.rows[0];
        const ext = (signed_pdf_mimetype && signed_pdf_mimetype.includes('pdf')) ? 'pdf' : (signed_pdf_mimetype ? signed_pdf_mimetype.split('/')[1] : 'pdf');

        res.setHeader('Content-Type', signed_pdf_mimetype || 'application/pdf');
        res.setHeader('Content-Disposition', 'attachment; filename="signed_document_' + req.params.id + '.' + ext + '"');
        res.send(signed_pdf_data);
    } catch (err) {
        console.error('Download error:', err);
        res.status(500).json({ error: 'Failed to download file' });
    }
});

// =================== START SERVER ===================

initDB().then(() => {
    app.listen(PORT, () => {
        console.log(`KYC Server running on http://localhost:${PORT}`);
    });
});
