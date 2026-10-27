const express = require("express");
const path = require("path");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require("@simplewebauthn/server");

const db = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = "cybernova-super-secret-jwt-key-2026";
const RP_NAME = "cyberNova Enterprise Portal";

// In-memory challenge stores with 2-minute timeouts
const pendingChallenges = new Map();
const pendingLoginChallenges = new Map();

app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: (origin, callback) => callback(null, true),
    credentials: true
}));

// Serve frontend directly from project root
app.use(express.static(__dirname));

// Helper: Determine origin dynamically (supporting localhost:3000, 5500, or LAN IP)
function getOriginAndRpId(req) {
    const origin = req.headers.origin || `http://${req.headers.host}`;
    const url = new URL(origin);
    const rpID = url.hostname;
    return { origin, rpID };
}

// Log security events to SQLite SOC table
function logSecurityEvent(type, email, ip, details, severity = "INFO") {
    try {
        db.prepare(`
            INSERT INTO security_logs (event_type, email, ip_address, details, severity)
            VALUES (?, ?, ?, ?, ?)
        `).run(type, email || "Unknown", ip, JSON.stringify(details), severity);
    } catch (e) {
        console.error("Log error:", e);
    }
}

// JWT Authentication Middleware for Protected Dashboards
function authenticateToken(req, res, next) {
    const token = req.cookies.cybernova_session;
    if (!token) return res.status(401).json({ error: "Unauthorized. Please log in with your passkey." });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: "Session expired or invalid." });
        req.user = user;
        next();
    });
}

// ------------------- PASSKEY REGISTRATION -------------------

app.post("/api/register/options", async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const { rpID } = getOriginAndRpId(req);

        let user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
        if (!user) {
            db.prepare("INSERT INTO users (email, role, display_name) VALUES (?, ?, ?)")
              .run(email, email.includes("staff") ? "staff" : "student", email.split('@')[0]);
            user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
        }

        const existingCredentials = db.prepare(
            "SELECT credential_id, transports FROM credentials WHERE user_id = ?"
        ).all(user.id);

        const options = await generateRegistrationOptions({
            rpName: RP_NAME,
            rpID,
            userID: new Uint8Array(Buffer.from(String(user.id))),
            userName: user.email,
            userDisplayName: user.display_name,
            attestationType: "none",
            excludeCredentials: existingCredentials.map(c => ({
                id: c.credential_id,
                transports: c.transports ? JSON.parse(c.transports) : undefined
            })),
            authenticatorSelection: {
                residentKey: "preferred",
                userVerification: "required" // Forces Biometrics (Fingerprint/FaceID/PIN)
            }
        });

        pendingChallenges.set(email, {
            challenge: options.challenge,
            userId: user.id,
            createdAt: Date.now()
        });

        res.json(options);
    } catch (error) {
        console.error("Registration options error:", error);
        res.status(500).json({ error: "Could not generate passkey options." });
    }
});

app.post("/api/register/verify", async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const { response, deviceName } = req.body;
        const pending = pendingChallenges.get(email);

        if (!pending || (Date.now() - pending.createdAt > 120000)) {
            return res.status(400).json({ error: "Registration session expired. Try again." });
        }
        pendingChallenges.delete(email);

        const { origin, rpID } = getOriginAndRpId(req);

        const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge: pending.challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            requireUserVerification: true
        });

        if (!verification.verified || !verification.registrationInfo) {
            return res.status(400).json({ error: "Biometric passkey verification failed." });
        }

        const { credential } = verification.registrationInfo;
        const detectedTransports = response.response.transports || ["internal", "hybrid"];

        db.prepare(`
            INSERT INTO credentials (credential_id, user_id, public_key, counter, device_name, transports)
            VALUES (?, ?, ?, ?, ?, ?)
        `).run(
            credential.id,
            pending.userId,
            Buffer.from(credential.publicKey).toString("base64url"),
            credential.counter,
            deviceName || "Biometric Authenticator (FIDO2)",
            JSON.stringify(detectedTransports)
        );

        logSecurityEvent("PASSKEY_REGISTERED", email, req.ip, {
            credentialId: credential.id.substring(0, 12) + "...",
            transports: detectedTransports
        }, "INFO");

        res.json({ success: true, message: "Passkey enrolled successfully!" });
    } catch (error) {
        console.error("Registration verify error:", error);
        res.status(400).json({ error: error.message || "Could not verify passkey." });
    }
});

// ------------------- PASSKEY LOGIN -------------------

app.post("/api/login/options", async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const { rpID } = getOriginAndRpId(req);

        const user = db.prepare("SELECT * FROM users WHERE email = ?").get(email);
        if (!user) return res.status(404).json({ error: "No account found with this email." });

        const credentials = db.prepare(
            "SELECT credential_id, transports FROM credentials WHERE user_id = ?"
        ).all(user.id);

        if (credentials.length === 0) {
            return res.status(400).json({ error: "No passkeys registered yet for this account." });
        }

        const options = await generateAuthenticationOptions({
            rpID,
            allowCredentials: credentials.map(c => ({
                id: c.credential_id,
                transports: c.transports ? JSON.parse(c.transports) : undefined
            })),
            userVerification: "required"
        });

        pendingLoginChallenges.set(email, {
            challenge: options.challenge,
            userId: user.id,
            createdAt: Date.now()
        });

        res.json(options);
    } catch (error) {
        console.error("Login options error:", error);
        res.status(500).json({ error: "Failed to create authentication challenge." });
    }
});

app.post("/api/login/verify", async (req, res) => {
    try {
        const email = String(req.body.email || "").trim().toLowerCase();
        const pending = pendingLoginChallenges.get(email);

        if (!pending || (Date.now() - pending.createdAt > 120000)) {
            return res.status(400).json({ error: "Login challenge expired. Try again." });
        }
        pendingLoginChallenges.delete(email);

        const user = db.prepare("SELECT * FROM users WHERE id = ?").get(pending.userId);
        const credential = db.prepare(
            "SELECT * FROM credentials WHERE credential_id = ? AND user_id = ?"
        ).get(req.body.response?.id, pending.userId);

        if (!user || !credential) {
            logSecurityEvent("LOGIN_FAILED", email, req.ip, { reason: "Credential mismatch" }, "WARNING");
            return res.status(401).json({ error: "Passkey does not match account." });
        }

        const { origin, rpID } = getOriginAndRpId(req);

        // Check if simulated phishing request
        if (req.body.isPhishingSimulation) {
            logSecurityEvent("PHISHING_ATTACK_BLOCKED", email, req.ip, {
                attemptedOrigin: req.body.simulatedOrigin || "http://evil-college-portal.net",
                reason: "Origin mismatch: FIDO2 cryptographic domain binding prevented signature hijack."
            }, "CRITICAL");

            return res.status(403).json({
                error: "🚨 PHISHING ATTACK DETECTED! Passkey is cryptographically bound to " + rpID + ". Verification rejected.",
                phishingBlocked: true
            });
        }

        const verification = await verifyAuthenticationResponse({
            response: req.body.response,
            expectedChallenge: pending.challenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            credential: {
                id: credential.credential_id,
                publicKey: Buffer.from(credential.public_key, "base64url"),
                counter: credential.counter,
                transports: credential.transports ? JSON.parse(credential.transports) : []
            },
            requireUserVerification: true
        });

        if (!verification.verified) {
            logSecurityEvent("LOGIN_FAILED", email, req.ip, { reason: "Cryptographic signature invalid" }, "WARNING");
            return res.status(401).json({ error: "Biometric authentication failed." });
        }

        // Replay Attack Protection: Ensure sign counter increased
        db.prepare("UPDATE credentials SET counter = ? WHERE credential_id = ?")
          .run(verification.authenticationInfo.newCounter, credential.credential_id);

        // Issue Secure HTTP-Only JWT Session
        const token = jwt.sign(
            { id: user.id, email: user.email, role: user.role, displayName: user.display_name },
            JWT_SECRET,
            { expiresIn: "4h" }
        );

        res.cookie("cybernova_session", token, {
            httpOnly: true,
            sameSite: "lax"
        });

        logSecurityEvent("LOGIN_SUCCESS", email, req.ip, {
            role: user.role,
            authenticator: credential.device_name,
            counter: verification.authenticationInfo.newCounter
        }, "INFO");

        res.json({
            success: true,
            role: user.role,
            user: { email: user.email, displayName: user.display_name },
            redirect: user.role === "student" ? "/student-dashboard.html" : "/staff-dashboard.html",
            telemetry: {
                algorithm: "ES256 / RS256",
                userVerification: "Present (Biometric Verified)",
                phishingResistant: true,
                signCounter: verification.authenticationInfo.newCounter
            }
        });
    } catch (error) {
        console.error("Login verification error:", error);
        logSecurityEvent("AUTH_ERROR", req.body?.email, req.ip, { error: error.message }, "WARNING");
        res.status(401).json({ error: error.message || "Passkey login failed." });
    }
});

// ------------------- PROTECTED SESSION & USER API -------------------

app.get("/api/me", authenticateToken, (req, res) => {
    const userCredentials = db.prepare(
        "SELECT credential_id, device_name, transports, created_at, counter FROM credentials WHERE user_id = ?"
    ).all(req.user.id);

    res.json({
        user: req.user,
        credentials: userCredentials.map(c => ({
            ...c,
            transports: c.transports ? JSON.parse(c.transports) : []
        }))
    });
});

app.post("/api/logout", (req, res) => {
    res.clearCookie("cybernova_session");
    res.json({ success: true, message: "Logged out successfully." });
});

// ------------------- SOC TELEMETRY & HONEY-TOKEN TRAP -------------------

app.get("/api/admin/soc-telemetry", (req, res) => {
    const logs = db.prepare("SELECT * FROM security_logs ORDER BY id DESC LIMIT 50").all();
    const stats = {
        totalPasskeys: db.prepare("SELECT COUNT(*) as count FROM credentials").get().count,
        totalUsers: db.prepare("SELECT COUNT(*) as count FROM users").get().count,
        phishingBlocked: db.prepare("SELECT COUNT(*) as count FROM security_logs WHERE event_type = 'PHISHING_ATTACK_BLOCKED'").get().count,
        honeytokenTriggers: db.prepare("SELECT COUNT(*) as count FROM security_logs WHERE event_type = 'HONEYTOKEN_TRIGGERED'").get().count
    };
    res.json({ stats, logs });
});

// 🚨 HONEY-TOKEN TRAP: Active defense tripwire
app.get("/api/admin/export-system-keys", (req, res) => {
    logSecurityEvent("HONEYTOKEN_TRIGGERED", "Attacker / Crawler", req.ip, {
        headers: req.headers,
        message: "Attacker tripped honeypot endpoint looking for leaked keys."
    }, "CRITICAL");

    console.log("🚨 [HONEYTOKEN TRIGGERED] Intrusion logged from IP:", req.ip);
    res.status(403).json({
        error: "ACCESS_DENIED: Intrusion attempt logged to SOC and IP quarantined.",
        status: "BLOCKED"
    });
});

app.listen(PORT, () => {
    console.log(`\n=================================================`);
    console.log(`🚀 cyberNova Security Hub: http://localhost:${PORT}`);
    console.log(`🛡️ SOC Telemetry Ready | FIDO2 WebAuthn Active`);
    console.log(`=================================================\n`);
});