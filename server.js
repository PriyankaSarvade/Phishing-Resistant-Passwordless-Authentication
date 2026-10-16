
const express = require("express");
const path = require("path");

const {
    generateRegistrationOptions,
    verifyRegistrationResponse,
    generateAuthenticationOptions,
    verifyAuthenticationResponse
} = require("@simplewebauthn/server");

const db = require("./database");

const app = express();
const cors = require('cors');
app.use(cors({
    origin: ['http://127.0.0.1:5501', 'http://127.0.0.1:5500', 'http://localhost:5500', 'http://localhost:5501'],
    credentials: true
}));
const PORT = 3000;

const RP_NAME = "cyberNova";
const RP_ID = "localhost";
const ORIGIN = "http://localhost:5501";

const pendingChallenges = new Map();
const pendingLoginChallenges = new Map();

app.use(express.json());

// Serve the existing frontend
app.use(express.static(path.join(__dirname, "../public")));

// Backend health check
app.get("/api/health", (req, res) => {
    res.json({
        success: true,
        message: "cyberNova backend is working"
    });
});

// Generate passkey registration options
app.post("/api/register/options", async (req, res) => {
    try {
        const email = String(req.body.email || "")
            .trim()
            .toLowerCase();

        const user = db.prepare(
            "SELECT * FROM users WHERE email = ?"
        ).get(email);

        if (!user) {
            return res.status(404).json({
                error: "Account not found. Contact the administrator."
            });
        }

        const existingCredentials = db.prepare(
            "SELECT credential_id, transports FROM credentials WHERE user_id = ?"
        ).all(user.id);

        const options = await generateRegistrationOptions({
            rpName: RP_NAME,
            rpID: RP_ID,
            userID: new Uint8Array(
                Buffer.from(String(user.id))
            ),
            userName: user.email,
            userDisplayName: user.display_name,
            attestationType: "none",
            excludeCredentials: existingCredentials.map(c => ({
                id: c.credential_id,
                transports: c.transports
                    ? JSON.parse(c.transports)
                    : undefined
            })),
            authenticatorSelection: {
                residentKey: "preferred",
                userVerification: "required"
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
        res.status(500).json({
            error: "Could not start passkey registration."
        });
    }
});

// Verify and save the registered passkey
app.post("/api/register/verify", async (req, res) => {
    try {
        const email = String(req.body.email || "")
            .trim()
            .toLowerCase();

        const response = req.body.response;
        const pending = pendingChallenges.get(email);

        if (!pending) {
            return res.status(400).json({
                error: "Registration expired or not started. Try again."
            });
        }

        // Challenges are single-use and expire after two minutes
        pendingChallenges.delete(email);

        if (Date.now() - pending.createdAt > 2 * 60 * 1000) {
            return res.status(400).json({
                error: "Registration expired. Please try again."
            });
        }

        const verification = await verifyRegistrationResponse({
            response,
            expectedChallenge: pending.challenge,
            expectedOrigin: "http://localhost:5501",
            expectedRPID: RP_ID,
            requireUserVerification: true
        });

        if (!verification.verified || !verification.registrationInfo) {
            return res.status(400).json({
                error: "Passkey verification failed."
            });
        }

        const { credential } = verification.registrationInfo;

        db.prepare(`
            INSERT INTO credentials
            (credential_id, user_id, public_key, counter, transports)
            VALUES (?, ?, ?, ?, ?)
        `).run(
            credential.id,
            pending.userId,
            Buffer.from(credential.publicKey).toString("base64url"),
            credential.counter,
            JSON.stringify(response.response.transports || [])
        );

        res.json({
            success: true,
            message: "Passkey registered successfully!"
        });
    } catch (error) {
        console.error("Passkey verification error:", error);
        res.status(400).json({
            error: "Could not verify or save the passkey."
        });
    }
});


const crypto = require("crypto");

// Generate passkey login options
app.post("/api/login/options", async (req, res) => {            
    try {
        const email = String(req.body.email || "")
            .trim()
            .toLowerCase();

        const user = db.prepare(
            "SELECT * FROM users WHERE email = ?"
        ).get(email);

        if (!user) {
            return res.status(404).json({
                error: "Account not found."
            });
        }

        const credentials = db.prepare(
            "SELECT credential_id, transports FROM credentials WHERE user_id = ?"
        ).all(user.id);

        if (credentials.length === 0) {
            return res.status(400).json({
                error: "Register a passkey first."
            });
        }

        const options = await generateAuthenticationOptions({
            rpID: RP_ID,
            allowCredentials: credentials.map(c => ({
                id: c.credential_id,
                transports: c.transports
                    ? JSON.parse(c.transports)
                    : undefined
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
        res.status(500).json({
            error: "Could not start passkey login."
        });
    }
});

// Verify the passkey during login
app.post("/api/login/verify", async (req, res) => {
    try {
        const email = String(req.body.email || "")
            .trim()
            .toLowerCase();

        const pending = pendingLoginChallenges.get(email);

        if (!pending) {
            return res.status(400).json({
                error: "Login expired. Please try again."
            });
        }

        // Challenges can only be used once
        pendingLoginChallenges.delete(email);

        if (Date.now() - pending.createdAt > 2 * 60 * 1000) {
            return res.status(400).json({
                error: "Login expired. Please try again."
            });
        }

        const user = db.prepare(
            "SELECT * FROM users WHERE id = ?"
        ).get(pending.userId);

        const credential = db.prepare(`
            SELECT * FROM credentials
            WHERE credential_id = ? AND user_id = ?
        `).get(req.body.response?.id, pending.userId);

        if (!user || user.email !== email || !credential) {
            return res.status(401).json({
                error: "Passkey does not match this account."
            });
        }

        const verification = await verifyAuthenticationResponse({
            response: req.body.response,
            expectedChallenge: pending.challenge,
            expectedOrigin: ORIGIN,
            expectedRPID: RP_ID,
            credential: {
                id: credential.credential_id,
                publicKey: Buffer.from(
                    credential.public_key,
                    "base64url"
                ),
                counter: credential.counter,
                transports: credential.transports
                    ? JSON.parse(credential.transports)
                    : []
            },
            requireUserVerification: true
        });

        if (!verification.verified) {
            return res.status(401).json({
                error: "Passkey verification failed."
            });
        }

        db.prepare(
            "UPDATE credentials SET counter = ? WHERE credential_id = ?"
        ).run(
            verification.authenticationInfo.newCounter,
            credential.credential_id
        );

        res.json({
            success: true,
            message: "Passkey verified successfully!",
            role: user.role,
            redirect: user.role === "student"
                ? "/student-dashboard.html"
                : "/staff-dashboard.html"
        });
    } catch (error) {
        console.error("Passkey login error:", error);
        res.status(401).json({
            error: "Passkey login failed. Please try again."
        });
    }
});

app.listen(PORT, () => {
    console.log(`cyberNova running at http://localhost:${PORT}`);
});