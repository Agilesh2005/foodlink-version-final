require("dotenv").config();
const express = require("express");
const session = require("express-session");
const path = require("path");
const bcrypt = require("bcryptjs");

const crypto = require("crypto");

const { getSupabase, isSupabaseConfigured } = require("./supabaseClient");
const {
    notifyAdminNewDonation,
    notifyInspectorAssignment,
    notifyNgosBulkFoodAvailable,
    notifyNgosNewDonationListed,
    notifyNgosFoodReminder,
    notifyNgoExpiryReminder,
    notifyInspectorPassedTask,
    notifyDonorDecision,
    sendPasswordResetEmail,
    sendHourlyReminder
} = require("./emailService");

// ── Stateless signed reset tokens (works across serverless instances) ──────────
function _makeResetToken(email) {
    const payload = Buffer.from(JSON.stringify({
        email,
        exp: Date.now() + 15 * 60 * 1000   // 15 min
    })).toString("base64url");
    const secret = process.env.SESSION_SECRET || "foodlink-secret";
    const sig = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
    return `${payload}.${sig}`;
}

function _verifyResetToken(token) {
    try {
        const [payload, sig] = (token || "").split(".");
        if (!payload || !sig) return null;
        const secret = process.env.SESSION_SECRET || "foodlink-secret";
        const expected = crypto.createHmac("sha256", secret).update(payload).digest("base64url");
        if (sig !== expected) return null;
        const data = JSON.parse(Buffer.from(payload, "base64url").toString());
        if (!data.email || Date.now() > data.exp) return null;
        return data.email;
    } catch { return null; }
}

const app = express();
const PORT = process.env.PORT || 3000;

app.set("trust proxy", 1);
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

// ---------- Supabase Session Store ----------
class SupabaseSessionStore extends session.Store {
    constructor(supabase) {
        super();
        this.supabase = supabase;
        this.fallbackMemory = new Map();
        this.tableAvailable = true;
    }

    async get(sid, callback) {
        if (!this.tableAvailable) {
            const entry = this.fallbackMemory.get(sid);
            if (!entry) return callback(null, null);
            if (entry.expire && new Date(entry.expire) < new Date()) {
                this.fallbackMemory.delete(sid);
                return callback(null, null);
            }
            return callback(null, entry.sess);
        }

        try {
            const { data, error } = await this.supabase
                .from("sessions")
                .select("sess, expire")
                .eq("sid", sid)
                .maybeSingle();

            if (error) {
                if (error.code === "42P01" || error.message?.includes("does not exist")) {
                    this.tableAvailable = false;
                    console.warn("[FoodLink] 'sessions' table not found in Supabase. Using in-memory fallback.");
                    return this.get(sid, callback);
                }
                return callback(error);
            }

            if (!data) return callback(null, null);

            if (data.expire && new Date(data.expire) < new Date()) {
                await this.destroy(sid, () => {});
                return callback(null, null);
            }

            return callback(null, data.sess);
        } catch (err) {
            return callback(err);
        }
    }

    async set(sid, sess, callback) {
        let expire;
        if (sess && sess.cookie && sess.cookie.expires) {
            expire = new Date(sess.cookie.expires).toISOString();
        } else {
            expire = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000).toISOString();
        }

        if (!this.tableAvailable) {
            this.fallbackMemory.set(sid, { sess, expire });
            return callback && callback(null);
        }

        try {
            const { error } = await this.supabase
                .from("sessions")
                .upsert({ sid, sess, expire });

            if (error) {
                if (error.code === "42P01" || error.message?.includes("does not exist")) {
                    this.tableAvailable = false;
                    this.fallbackMemory.set(sid, { sess, expire });
                    return callback && callback(null);
                }
                return callback && callback(error);
            }
            return callback && callback(null);
        } catch (err) {
            return callback && callback(err);
        }
    }

    async destroy(sid, callback) {
        this.fallbackMemory.delete(sid);
        if (!this.tableAvailable) {
            return callback && callback(null);
        }
        try {
            const { error } = await this.supabase
                .from("sessions")
                .delete()
                .eq("sid", sid);
            return callback && callback(error || null);
        } catch (err) {
            return callback && callback(err);
        }
    }

    async touch(sid, sess, callback) {
        return this.set(sid, sess, callback);
    }
}

let sessionMiddleware = null;
let initialized = false;

async function initDatabase() {
    if (initialized) return;

    if (isSupabaseConfigured()) {
        const supabase = getSupabase();
        sessionMiddleware = session({
            secret: process.env.SESSION_SECRET || "foodlink-secret",
            resave: false,
            saveUninitialized: false,
            store: new SupabaseSessionStore(supabase),
            cookie: {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "lax",
                maxAge: 1000 * 60 * 60 * 24 * 7
            }
        });
        initialized = true;
        console.log("[FoodLink] Supabase initialized.");
    } else if (process.env.MONGODB_URI) {
        const mongoose = require("mongoose");
        const { MongoStore } = require("connect-mongo");
        await mongoose.connect(process.env.MONGODB_URI, { serverSelectionTimeoutMS: 10000 });
        sessionMiddleware = session({
            secret: process.env.SESSION_SECRET || "foodlink-secret",
            resave: false,
            saveUninitialized: false,
            store: MongoStore.create({
                client: mongoose.connection.getClient(),
                collectionName: "sessions"
            }),
            cookie: {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
                sameSite: "lax",
                maxAge: 1000 * 60 * 60 * 24 * 7
            }
        });
        initialized = true;
        console.log("[FoodLink] MongoDB initialized as fallback.");
    } else {
        throw new Error("No database configured. Please configure SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY in your .env file.");
    }
}

// Database & session middleware for /api routes
app.use("/api", async function (req, res, next) {
    try {
        await initDatabase();
        sessionMiddleware(req, res, next);
    } catch (error) {
        console.error("[FoodLink] Database initialization failed:", error.message);
        res.status(503).json({
            error: "The database is unavailable. " + error.message
        });
    }
});

// ---------- Helpers & Formatting ----------

function formatFood(f) {
    if (!f) return null;
    return {
        _id: f.id,
        id: f.id,
        name: f.name,
        servings: f.servings,
        veg: f.veg,
        nature: f.nature,
        expires: f.expires,
        address: f.address,
        donor: f.donor,
        donorUser: f.donor_user,
        donor_user: f.donor_user,
        phone: f.phone,
        status: f.status,
        approval: f.approval,
        inspectNote: f.inspect_note,
        inspect_note: f.inspect_note,
        inspectedAt: f.inspected_at,
        inspected_at: f.inspected_at,
        code: f.code,
        assignedInspector: f.assigned_inspector,
        assigned_inspector: f.assigned_inspector,
        passedBy: f.passed_by,
        passed_by: f.passed_by,
        claimedAt: f.claimed_at,
        claimed_at: f.claimed_at,
        claimedBy: f.claimed_by,
        claimed_by: f.claimed_by,
        claimer: f.claimer
    };
}

function needRole(role) {
    return function (req, res, next) {
        if (!req.session || !req.session.user) {
            return res.status(401).json({ error: "Please login" });
        }
        if (req.session.user.role !== role) {
            return res.status(403).json({ error: "Not allowed" });
        }
        next();
    };
}

async function markExpired(supabase) {
    if (!supabase) return;
    try {
        const now = new Date().toISOString();
        // Auto-expire available or claimed foods whose expiry time has passed
        const { data, error } = await supabase
            .from("foods")
            .update({ status: "expired" })
            .in("status", ["available", "claimed"])
            .lt("expires", now)
            .select("id, name, status");

        if (data && data.length > 0) {
            console.log(`[FoodLink Auto-Expire] Marked ${data.length} listing(s) as expired:`, data.map(d => d.name).join(", "));
        }
    } catch (err) {
        console.warn("[FoodLink] markExpired check failed:", err.message);
    }
}

// ---------- API Routes ----------

// Health Check
app.get("/api/health", function (req, res) {
    res.json({
        ok: true,
        database: isSupabaseConfigured() ? "supabase" : (process.env.MONGODB_URI ? "mongodb" : "none")
    });
});

// ---------- Real-Time Authentication (Email-Based) ----------

// Register a real user account in real time using email
app.post("/api/register", async function (req, res) {
    try {
        const { email, password, role, name, phone } = req.body;

        if (!email || !password || !role || !name) {
            return res.status(400).json({ ok: false, error: "Please fill in all required fields." });
        }

        const cleanEmail = String(email).toLowerCase().trim();
        const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
        if (!emailRegex.test(cleanEmail)) {
            return res.status(400).json({ ok: false, error: "Please enter a valid email address." });
        }

        if (String(password).length < 6) {
            return res.status(400).json({ ok: false, error: "Password must be at least 6 characters." });
        }

        const validRoles = ["donor", "ngo"];
        if (!validRoles.includes(role)) {
            return res.status(400).json({ ok: false, error: "Only Donor and NGO accounts can be registered." });
        }

        const supabase = getSupabase();

        // Check if email or username already exists
        let { data: existingUser } = await supabase
            .from("users")
            .select("id")
            .ilike("email", cleanEmail)
            .maybeSingle();

        if (!existingUser) {
            try {
                const { data: userByUsername } = await supabase
                    .from("users")
                    .select("id")
                    .ilike("username", cleanEmail)
                    .maybeSingle();
                if (userByUsername) existingUser = userByUsername;
            } catch (e) {}
        }

        if (existingUser) {
            return res.json({ ok: false, error: "An account with this email already exists." });
        }

        // Hash password securely
        const passwordHash = await bcrypt.hash(password, 10);

        const userData = {
            email: cleanEmail,
            username: cleanEmail, // populates username to satisfy legacy not-null constraint if column exists
            password_hash: passwordHash,
            role: role,
            name: String(name).trim(),
            phone: phone ? String(phone).trim() : null
        };

        let { data: newUser, error: insertErr } = await supabase
            .from("users")
            .insert(userData)
            .select("id, email, name, role")
            .single();

        // If the table doesn't have the username column, retry without it
        if (insertErr && insertErr.message && insertErr.message.includes("username")) {
            delete userData.username;
            const retry = await supabase
                .from("users")
                .insert(userData)
                .select("id, email, name, role")
                .single();
            newUser = retry.data;
            insertErr = retry.error;
        }

        if (insertErr || !newUser) {
            console.error("[FoodLink] Registration error:", insertErr);
            return res.status(500).json({ ok: false, error: "Could not create account: " + (insertErr ? insertErr.message : "Unknown error") });
        }

        // Establish real-time session
        req.session.user = {
            id: newUser.id,
            email: newUser.email,
            username: newUser.email,
            name: newUser.name,
            phone: phone ? String(phone).trim() : null,
            role: newUser.role
        };

        res.json({ ok: true, role: newUser.role });
    } catch (err) {
        console.error("[FoodLink] Registration exception:", err);
        res.status(500).json({ ok: false, error: err.message });
    }
});

// Login real user using email
app.post("/api/login", async function (req, res) {
    try {
        const emailInput = String(req.body.email || req.body.username || "").toLowerCase().trim();
        const passwordInput = String(req.body.password || "");

        if (!emailInput || !passwordInput) {
            return res.json({ ok: false, error: "Email and password required." });
        }

        const supabase = getSupabase();
        let { data: user } = await supabase
            .from("users")
            .select("id, email, password_hash, name, phone, role")
            .ilike("email", emailInput)
            .maybeSingle();

        if (!user) {
            try {
                const { data: userByUsername } = await supabase
                    .from("users")
                    .select("id, email, password_hash, name, phone, role")
                    .ilike("username", emailInput)
                    .maybeSingle();
                if (userByUsername) user = userByUsername;
            } catch (e) {}
        }

        if (!user) {
            return res.json({ ok: false, error: "Incorrect email or password." });
        }

        // Verify password against hash
        let passwordMatches = false;
        if (user.password_hash) {
            passwordMatches = await bcrypt.compare(passwordInput, user.password_hash);
        } else if (user.password) {
            // Backward compatibility for plain text
            passwordMatches = (user.password === passwordInput);
        }

        if (!passwordMatches) {
            return res.json({ ok: false, error: "Incorrect email or password." });
        }

        req.session.user = {
            id: user.id,
            email: user.email,
            username: user.email,
            name: user.name,
            phone: user.phone || null,
            role: user.role
        };

        res.json({ ok: true, role: user.role });
    } catch (err) {
        console.error("[FoodLink] Login error:", err);
        res.status(500).json({ ok: false, error: err.message });
    }
});

// Logout
app.post("/api/logout", function (req, res) {
    if (req.session) {
        req.session.destroy(function () {
            res.json({ ok: true });
        });
    } else {
        res.json({ ok: true });
    }
});

// Get current session user
app.get("/api/me", function (req, res) {
    res.json({ user: (req.session && req.session.user) ? req.session.user : null });
});

// ---------- Forgot / Reset Password ----------

app.post("/api/forgot-password", async function (req, res) {
    const input = String(req.body.email || "").trim().toLowerCase();
    console.log("[FoodLink Forgot-Password] Request received for:", input);
    if (!input) return res.json({ ok: false, error: "Please enter your email address." });

    const supabase = getSupabase();
    // Allow lookup by registered email OR username
    const { data: user, error: userErr } = await supabase
        .from("users")
        .select("id, email, name, username")
        .or(`email.ilike.${input},username.ilike.${input}`)
        .maybeSingle();

    if (!user) {
        console.warn(`[FoodLink Forgot-Password] User not found for '${input}'.`);
        return res.json({ ok: true });
    }

    const targetEmail = user.email || (input.includes("@") ? input : null);
    if (!targetEmail) {
        console.warn(`[FoodLink Forgot-Password] User '${user.username}' has no email address on file.`);
        return res.json({ ok: true });
    }

    // Auto-detect base URL from request (works on Vercel, localhost, any host)
    const protocol = req.get("x-forwarded-proto") || req.protocol || "https";
    const baseUrl = process.env.APP_URL || `${protocol}://${req.get("host")}`;

    // Generate signed stateless token (safe for serverless)
    const token = _makeResetToken(targetEmail);
    const resetUrl = `${baseUrl}/reset-password.html?token=${token}`;

    console.log(`[FoodLink Forgot-Password] Dispatching reset link to ${targetEmail} via Brevo...`);
    try {
        const result = await sendPasswordResetEmail(targetEmail, resetUrl);
        if (!result || !result.success) {
            console.error("[FoodLink Forgot-Password] Reset email send failed:", result?.error || "unknown error");
        } else {
            console.log(`[FoodLink Forgot-Password] Reset email sent successfully to ${targetEmail} | ID:`, result.id);
        }
    } catch (e) {
        console.error("[FoodLink Forgot-Password] Reset email exception:", e.message);
    }

    res.json({ ok: true });
});

app.post("/api/reset-password", async function (req, res) {
    const token = String(req.body.token || "").trim();
    const newPassword = String(req.body.password || "").trim();

    if (!token || !newPassword || newPassword.length < 6) {
        return res.json({ ok: false, error: "Invalid request. Password must be at least 6 characters." });
    }

    const email = _verifyResetToken(token);
    if (!email) {
        return res.json({ ok: false, error: "This reset link has expired. Please request a new one." });
    }

    const hash = await bcrypt.hash(newPassword, 10);
    const supabase = getSupabase();
    const { error } = await supabase
        .from("users")
        .update({ password_hash: hash })
        .ilike("email", email);

    if (error) return res.status(500).json({ ok: false, error: "Could not update password. Please try again." });

    res.json({ ok: true });
});

// ---------- Donor Routes ----------


// Helper to schedule 2 chronological expiry reminder emails to NGOs spaced 45 seconds apart
// First mail: Sent shortly after approval with MORE expiry time (~2 hours)
// Second mail: Sent after 45 seconds with LESS expiry time (~1 hour / nearing expiry)
function scheduleNgoExpiryReminders(food, ngoEmails) {
    const excludedEmail = (process.env.DONOR_EMAIL || "agileshkalaimani@gmail.com").toLowerCase();
    const filteredNgoEmails = (ngoEmails || []).filter(e => e && e.toLowerCase() !== excludedEmail);
    if (filteredNgoEmails.length === 0 || !food) return;
    ngoEmails = filteredNgoEmails;
    console.log(`[FoodLink NGO Reminder] Scheduled 5s reminder for food ${food.id} (${food.name}) to ${ngoEmails.length} NGO(s).`);

    // Send reminder 30 seconds after NGOs are notified of the approved listing
    setTimeout(async () => {
        try {
            const supabase = getSupabase();
            const { data: current, error: fetchErr } = await supabase.from("foods").select("status").eq("id", food.id).single();
            if (fetchErr) {
                console.error("[FoodLink NGO Reminder] DB check error:", fetchErr.message);
            } else if (current && current.status !== "available") {
                console.log(`[FoodLink NGO Reminder] Food ${food.id} is already ${current.status}. Skipping reminder.`);
                return;
            }
            console.log(`[FoodLink NGO Reminder] Sending 5s unclaimed food reminder to ${ngoEmails.join(", ")}...`);
            const res = await notifyNgoExpiryReminder(food, ngoEmails);
            console.log("[FoodLink NGO Reminder] Result:", res?.success ? `Sent (${res.id})` : JSON.stringify(res));
        } catch (err) {
            console.error("[FoodLink NGO Reminder Error]:", err.message);
        }
    }, 5000);
}

app.post("/api/food", needRole("donor"), async function (req, res) {
    const b = req.body;
    if (new Date(b.expires) <= new Date()) {
        return res.json({ ok: false, error: "Expiry time must be in the future." });
    }

    const supabase = getSupabase();
    const foodPayload = {
        name: b.name,
        servings: Number(b.servings),
        veg: Boolean(b.veg),
        nature: b.nature,
        expires: new Date(b.expires).toISOString(),
        address: b.address,
        donor: req.session.user.name,
        donor_user: req.session.user.email || req.session.user.username,
        phone: req.session.user.phone || b.phone || '',
        status: "available",
        approval: "pending"
    };

    const { data: newFood, error } = await supabase
        .from("foods")
        .insert(foodPayload)
        .select()
        .single();

    if (error) {
        console.error("[FoodLink] Error creating food listing:", error);
        return res.status(500).json({ ok: false, error: error.message });
    }

    // Trigger Notification 1: Email Admin that donor added food
    // Directly await email dispatch so serverless or network timeouts don't truncate the request
    try {
        const { data: admins } = await supabase
            .from("users")
            .select("email")
            .eq("role", "admin");

        const adminEmails = (admins || []).map(a => a.email).filter(Boolean);

        // Always include configured admin emails from environment
        if (process.env.ADMIN_EMAIL) {
            process.env.ADMIN_EMAIL.split(",").forEach(e => {
                const trimmed = e.trim();
                if (trimmed && !adminEmails.includes(trimmed)) {
                    adminEmails.push(trimmed);
                }
            });
        }

        // Fallback default admin
        if (adminEmails.length === 0) {
            adminEmails.push("26mx128@psgtech.ac.in");
        }

        console.log("[FoodLink] Sending admin notification to:", adminEmails.join(", "));

        const result = await notifyAdminNewDonation(newFood || foodPayload, adminEmails);
        if (!result || !result.success) {
            console.error("[FoodLink] Admin email send failed:", result?.error || result?.results || "unknown");
        } else {
            console.log("[FoodLink] Admin notification sent successfully | ID:", result.id);
        }

        // Note: NGOs are NOT notified at donor submission. They are ONLY notified after inspector inspection and approval.
    } catch (mailErr) {
        console.error("[FoodLink] Email notification error on donation create:", mailErr.message);
    }

    res.json({ ok: true });
});

app.get("/api/food/mine", needRole("donor"), async function (req, res) {
    const supabase = getSupabase();
    await markExpired(supabase);

    const userEmail = req.session.user.email || req.session.user.username;
    const { data, error } = await supabase
        .from("foods")
        .select("*")
        .eq("donor_user", userEmail)
        .order("created_at", { ascending: false });

    if (error) {
        return res.status(500).json({ error: error.message });
    }

    const list = (data || []).map(formatFood).map(item => {
        delete item.code;
        return item;
    });
    res.json(list);
});

app.post("/api/food/:id/pickup", needRole("donor"), async function (req, res) {
    const supabase = getSupabase();
    const userEmail = req.session.user.email || req.session.user.username;
    const { data: f, error } = await supabase
        .from("foods")
        .select("*")
        .eq("id", req.params.id)
        .eq("donor_user", userEmail)
        .maybeSingle();

    if (error || !f || f.status !== "claimed") {
        return res.json({ ok: false, error: "Listing not found or not in claimed status." });
    }
    if (String(req.body.code).trim() !== String(f.code).trim()) {
        return res.json({ ok: false, error: "Wrong pickup verification code." });
    }

    const { error: updateErr } = await supabase
        .from("foods")
        .update({ status: "picked_up" })
        .eq("id", req.params.id);

    if (updateErr) {
        return res.status(500).json({ ok: false, error: updateErr.message });
    }
    res.json({ ok: true });
});

app.delete("/api/food/:id", needRole("donor"), async function (req, res) {
    const supabase = getSupabase();
    const userEmail = req.session.user.email || req.session.user.username;
    await supabase
        .from("foods")
        .delete()
        .eq("id", req.params.id)
        .eq("donor_user", userEmail);

    res.json({ ok: true });
});

// ---------- NGO Routes ----------

app.get("/api/food/approved", needRole("ngo"), async function (req, res) {
    const supabase = getSupabase();
    await markExpired(supabase);

    const { data, error } = await supabase
        .from("foods")
        .select("*")
        .eq("approval", "approved")
        .order("created_at", { ascending: false });

    if (error) {
        return res.status(500).json({ error: error.message });
    }

    const list = (data || []).map(formatFood).map(item => {
        delete item.code;
        // Show claimer info for transparency (NGOs can see who claimed)
        // Only expose claimer details for items that have been claimed or picked up
        if (item.status !== "claimed" && item.status !== "picked_up") {
            delete item.claimer;
            delete item.claimedBy;
            delete item.claimed_by;
        }
        return item;
    });
    res.json(list);
});

app.post("/api/food/:id/claim", needRole("ngo"), async function (req, res) {
    const code = String(Math.floor(1000 + Math.random() * 9000));
    const supabase = getSupabase();

    const userEmail = req.session.user.email || req.session.user.username;
    const { data, error } = await supabase
        .from("foods")
        .update({
            status: "claimed",
            code: code,
            claimed_at: new Date().toISOString(),
            claimed_by: userEmail,
            claimer: {
                name: req.body.name,
                phone: req.body.phone,
                mail: req.body.mail,
                kind: req.body.kind
            }
        })
        .eq("id", req.params.id)
        .eq("status", "available")
        .eq("approval", "approved")
        .gt("expires", new Date().toISOString())
        .select();

    if (error || !data || data.length === 0) {
        return res.json({ ok: false, error: "This listing is no longer available." });
    }
    res.json({ ok: true });
});

app.get("/api/claims", needRole("ngo"), async function (req, res) {
    const supabase = getSupabase();
    const userEmail = req.session.user.email || req.session.user.username;
    const { data, error } = await supabase
        .from("foods")
        .select("*")
        .eq("claimed_by", userEmail)
        .order("claimed_at", { ascending: false });

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json((data || []).map(formatFood));
});

// ---------- Inspector Routes ----------

app.get("/api/inspections", needRole("inspector"), async function (req, res) {
    const supabase = getSupabase();
    await markExpired(supabase);

    const inspectorEmail = req.session.user.email || req.session.user.username;

    // ONLY show pending food assigned specifically to this inspector by Admin
    let { data: pendingData, error: pendingErr } = await supabase
        .from("foods")
        .select("*")
        .eq("approval", "pending")
        .eq("status", "available")
        .eq("assigned_inspector", inspectorEmail)
        .order("created_at", { ascending: false });

    // Fallback if column not yet queried
    if (pendingErr) {
        pendingData = [];
    }

    const { data: doneData } = await supabase
        .from("foods")
        .select("*")
        .in("approval", ["approved", "rejected"])
        .eq("assigned_inspector", inspectorEmail)
        .order("inspected_at", { ascending: false });

    const pending = (pendingData || []).map(formatFood).map(item => {
        delete item.code;
        return item;
    });
    const done = (doneData || []).map(formatFood).map(item => {
        delete item.code;
        return item;
    });

    res.json({ pending, done });
});

// Inspector passes task to the other inspector (allowed only once per task)
app.post("/api/food/:id/pass", needRole("inspector"), async function (req, res) {
    const supabase = getSupabase();
    const currentEmail = (req.session.user.email || req.session.user.username || "").toLowerCase().trim();

    // Only the current assignee can pass, and only once
    const { data: current } = await supabase
        .from("foods")
        .select("id, name, servings, veg, nature, expires, address, phone, donor, donor_user, assigned_inspector, passed_by")
        .eq("id", req.params.id)
        .maybeSingle();

    if (!current) {
        return res.status(404).json({ ok: false, error: "Listing not found." });
    }

    const assigned = (current.assigned_inspector || "").toLowerCase().trim();
    if (assigned !== currentEmail) {
        console.warn(`[FoodLink] Pass denied: task assigned to '${assigned}', caller is '${currentEmail}'`);
        return res.status(403).json({ ok: false, error: "This task is not assigned to you." });
    }
    if (current.passed_by) {
        return res.status(400).json({ ok: false, error: "This task was already passed to you. You must accept or reject it." });
    }

    // Find the other inspector
    const { data: otherInspectors, error: insErr } = await supabase
        .from("users")
        .select("name, email")
        .eq("role", "inspector")
        .neq("email", currentEmail);

    if (insErr || !otherInspectors || otherInspectors.length === 0) {
        return res.status(400).json({ ok: false, error: "No other inspector available to pass task to." });
    }

    const targetInspector = otherInspectors[0];
    const passerName = req.session.user.name || "Inspector";

    console.log(`[FoodLink] Reassigning food '${current.name}' from ${currentEmail} to ${targetInspector.email}...`);

    // Reassign food to the other inspector and record who passed it
    const { data: updatedFood, error: updateErr } = await supabase
        .from("foods")
        .update({
            assigned_inspector: targetInspector.email,
            passed_by: passerName
        })
        .eq("id", req.params.id)
        .select()
        .single();

    if (updateErr || !updatedFood) {
        console.error("[FoodLink] Update error passing task:", updateErr?.message);
        return res.status(500).json({ ok: false, error: "Could not pass inspection task in database." });
    }

    // 1. Email the other inspector that task was transferred
    try {
        console.log(`[FoodLink] Sending pass task email to other inspector: ${targetInspector.email}...`);
        const passResult = await notifyInspectorPassedTask(
            targetInspector.email,
            targetInspector.name,
            passerName,
            updatedFood
        );
        console.log("[FoodLink] Pass email dispatch status:", passResult?.success ? "SENT" : passResult?.error);
    } catch (mailErr) {
        console.error("[FoodLink] Error emailing other inspector:", mailErr.message);
    }

    // 2. Alert Admin that task was transferred between inspectors
    try {
        const adminEmail = process.env.ADMIN_EMAIL || "26mx128@psgtech.ac.in";
        console.log(`[FoodLink] Alerting admin of pass at ${adminEmail}...`);
        await sendMail({
            to: adminEmail,
            subject: `[Admin Alert] Inspection Task Forwarded: ${updatedFood.name} (from ${passerName} to ${targetInspector.name})`,
            html: layout({
                headerColor: "#b45309",
                headerLabel: "Task Reassignment Notice",
                title: "Inspection Task Forwarded",
                preheader: `${passerName} forwarded ${updatedFood.name} to ${targetInspector.name}`,
                body: `<p>Inspector <strong>${passerName}</strong> was unable to inspect <strong>${updatedFood.name}</strong> (${updatedFood.servings} servings at ${updatedFood.address}) and has forwarded the task to <strong>${targetInspector.name}</strong> (${targetInspector.email}).</p>`,
                ctaText: "Open Admin Dashboard",
                ctaUrl: `${process.env.APP_URL || "https://apexinterview.in"}/admin.html`
            })
        });
    } catch (adminMailErr) {
        console.error("[FoodLink] Admin pass notification error:", adminMailErr.message);
    }

    // 3. Notify donor that food is being re-reviewed
    if (updatedFood && updatedFood.donor_user) {
        try {
            const { data: donor } = await supabase
                .from("users")
                .select("name, email")
                .ilike("email", updatedFood.donor_user)
                .maybeSingle();

            const donorEmail = donor?.email || (updatedFood.donor_user.includes("@") ? updatedFood.donor_user : null);
            const donorName = donor?.name || updatedFood.donor || "Donor";

            if (donorEmail) {
                await notifyDonorDecision(
                    donorEmail,
                    donorName,
                    updatedFood,
                    "passed",
                    { inspectorName: passerName, passedTo: targetInspector.name }
                );
            }
        } catch (mailErr) {
            console.error("[FoodLink] Donor pass email error:", mailErr.message);
        }
    }

    res.json({ ok: true, passedTo: targetInspector.name, targetEmail: targetInspector.email });
});

app.post("/api/food/:id/inspect", needRole("inspector"), async function (req, res) {
    const note = String(req.body.note || "").trim();
    if (!req.body.ok && note === "") {
        return res.json({ ok: false, error: "Please write a reason to reject." });
    }

    const supabase = getSupabase();
    const { data: updatedFood, error } = await supabase
        .from("foods")
        .update({
            approval: req.body.ok ? "approved" : "rejected",
            inspect_note: note,
            inspected_at: new Date().toISOString()
        })
        .eq("id", req.params.id)
        .select()
        .single();

    if (error) {
        return res.status(500).json({ ok: false, error: error.message });
    }

    // Trigger Notification 3: If approved and servings > 50, notify all NGOs
    if (req.body.ok && updatedFood) {
        try {
            const { data: ngos } = await supabase
                .from("users")
                .select("email")
                .eq("role", "ngo");

            const ngoEmails = (ngos || []).map(n => n.email).filter(Boolean);
            console.log("[FoodLink] Sending NGO bulk notification to:", ngoEmails.join(", "));
                        if (ngoEmails.length > 0) {
                const result = await notifyNgosBulkFoodAvailable(updatedFood, ngoEmails);
                if (!result || !result.success) {
                    console.error("[FoodLink] NGO bulk email failed:", result?.error || result?.results || "unknown");
                } else {
                    console.log("[FoodLink] NGO bulk notification sent successfully");
                }
                // Schedule chronological reminders: first mail (more expiry time), then after 45s (less expiry time)
                scheduleNgoExpiryReminders(updatedFood, ngoEmails);
            }
        } catch (mailErr) {
            console.error("[FoodLink] NGO bulk food email error:", mailErr.message);
        }
    }

    // Notify donor of decision
    if (updatedFood && updatedFood.donor_user) {
        try {
            const { data: donor } = await supabase
                .from("users")
                .select("name, email")
                .ilike("email", updatedFood.donor_user)
                .maybeSingle();

            const donorEmail = donor?.email || (updatedFood.donor_user.includes("@") ? updatedFood.donor_user : null);
            const donorName = donor?.name || updatedFood.donor || "Donor";

            if (donorEmail) {
                console.log("[FoodLink] Processing donor decision email for:", donorEmail);
                const result = await notifyDonorDecision(
                    donorEmail,
                    donorName,
                    updatedFood,
                    req.body.ok ? "approved" : "rejected",
                    { inspectorName: req.session.user.name, reason: note }
                );
                if (!result || !result.success) {
                    console.error("[FoodLink] Donor decision email failed:", result?.error || "unknown");
                }
            }
        } catch (mailErr) {
            console.error("[FoodLink] Donor decision email error:", mailErr.message);
        }
    }

    res.json({ ok: true });
});

// ---------- Admin Routes ----------

// Get all registered inspectors for admin assignment dropdown
app.get("/api/admin/inspectors", needRole("admin"), async function (req, res) {
    const supabase = getSupabase();
    const { data, error } = await supabase
        .from("users")
        .select("id, name, email")
        .eq("role", "inspector")
        .order("name", { ascending: true });

    if (error) {
        return res.status(500).json({ error: error.message });
    }
    res.json(data || []);
});

// Admin assigns an inspector to a food listing
app.post("/api/admin/food/:id/assign", needRole("admin"), async function (req, res) {
    const inspectorEmail = String(req.body.inspectorEmail || "").trim().toLowerCase();
    if (!inspectorEmail) {
        return res.status(400).json({ ok: false, error: "Please select an inspector." });
    }

    const supabase = getSupabase();

    // Verify inspector exists
    const { data: inspector } = await supabase
        .from("users")
        .select("name, email")
        .ilike("email", inspectorEmail)
        .eq("role", "inspector")
        .maybeSingle();

    if (!inspector) {
        return res.status(404).json({ ok: false, error: "Inspector not found." });
    }

    // Assign inspector in database (resets the "passed" flag so this inspector can pass it once)
    const { data: food, error } = await supabase
        .from("foods")
        .update({ assigned_inspector: inspector.email, passed_by: null })
        .eq("id", req.params.id)
        .select()
        .single();

    if (error || !food) {
        return res.status(500).json({ ok: false, error: error ? error.message : "Food listing not found" });
    }

    // Trigger Notification 2: Email Assigned Inspector with location & food details
    try {
        console.log("[FoodLink] Sending inspector assignment email to:", inspector.email);
        const result = await notifyInspectorAssignment(inspector.email, inspector.name, food);
        if (!result || !result.success) {
            console.error("[FoodLink] Inspector assignment email failed:", result?.error || "unknown");
        } else {
            console.log("[FoodLink] Inspector assignment email sent successfully");
        }
    } catch (mailErr) {
        console.error("[FoodLink] Inspector email notification error:", mailErr.message);
    }

    res.json({ ok: true, assignedTo: inspector.name, inspectorEmail: inspector.email });
});

app.get("/api/admin/food", needRole("admin"), async function (req, res) {
    const supabase = getSupabase();
    await markExpired(supabase);

    const { data, error } = await supabase
        .from("foods")
        .select("*")
        .order("created_at", { ascending: false });

    if (error) {
        return res.status(500).json({ error: error.message });
    }

    const list = (data || []).map(formatFood).map(item => {
        delete item.code;
        return item;
    });
    res.json(list);
});

app.delete("/api/admin/food/:id", needRole("admin"), async function (req, res) {
    const supabase = getSupabase();
    await supabase
        .from("foods")
        .delete()
        .eq("id", req.params.id);

    res.json({ ok: true });
});

app.post("/api/admin/food/:id/reinspect", needRole("admin"), async function (req, res) {
    const supabase = getSupabase();
    await supabase
        .from("foods")
        .update({
            approval: "pending",
            inspect_note: ""
        })
        .eq("id", req.params.id)
        .eq("status", "available");

    res.json({ ok: true });
});

// ---------- Automated Reminder Routes & Jobs ----------
// Paused by default to prevent inbox flooding; can be toggled from Admin Dashboard or triggered manually
let reminderActive = false;
let isProcessingReminder = false;
let lastReminderSentAt = 0;
// Normal reminder interval: 1 hour (3600000ms). When testing simulation mode, can be adjusted.
const REMINDER_INTERVAL_MS = 60 * 60 * 1000;

async function processHourlyReminderJob(force = false) {
    if (!reminderActive && !force) return null;
    if (isProcessingReminder) return null;

    isProcessingReminder = true;
    try {
        if (!isSupabaseConfigured()) return null;
        const supabase = getSupabase();

        // 1. Auto-expire any expired listings first
        await markExpired(supabase);

        // 2. Fetch pending listings (pending approval & status available)
        const { data: pendingFoods } = await supabase
            .from("foods")
            .select("*")
            .eq("approval", "pending")
            .eq("status", "available");

        // 3. Fetch claimed listings awaiting pickup
        const { data: claimedFoods } = await supabase
            .from("foods")
            .select("*")
            .eq("status", "claimed");

        const pendingList = pendingFoods || [];
        const claimedList = claimedFoods || [];

        if (pendingList.length === 0 && claimedList.length === 0) {
            return { sent: false, message: "No active pending or claimed items requiring a reminder right now." };
        }

        // Rate limit guard: at least 1000ms between automated runs
        const now = Date.now();
        if (!force && (now - lastReminderSentAt < 1000)) {
            return { sent: false, message: "Throttled to 1s intervals." };
        }

        // Fetch admin recipients
        const { data: admins } = await supabase
            .from("users")
            .select("email")
            .eq("role", "admin");

        const adminEmails = (admins || []).map(a => a.email).filter(Boolean);
        if (process.env.ADMIN_EMAIL) {
            process.env.ADMIN_EMAIL.split(",").forEach(e => {
                const trimmed = e.trim();
                if (trimmed && !adminEmails.includes(trimmed)) adminEmails.push(trimmed);
            });
        }
        if (adminEmails.length === 0) {
            adminEmails.push("26mx128@psgtech.ac.in");
        }

        console.log(`[FoodLink Reminder] Dispatching hourly reminder (1s simulation) to ${adminEmails.join(", ")} | Pending: ${pendingList.length}, Claimed: ${claimedList.length}`);
        const mailResult = await sendHourlyReminder({
            pendingFoods: pendingList,
            claimedFoods: claimedList,
            adminEmails
        });

        lastReminderSentAt = Date.now();
        return { sent: true, mailResult };
    } catch (err) {
        console.error("[FoodLink Reminder Error]:", err.message);
        return { sent: false, error: err.message };
    } finally {
        isProcessingReminder = false;
    }
}

// Admin manual trigger for reminder test
app.post("/api/admin/reminders/send", needRole("admin"), async function (req, res) {
    try {
        const result = await processHourlyReminderJob(true);
        res.json({ ok: true, result });
    } catch (err) {
        res.status(500).json({ ok: false, error: err.message });
    }
});

// Admin toggle reminder loop on/off
app.post("/api/admin/reminders/toggle", needRole("admin"), function (req, res) {
    reminderActive = !reminderActive;
    console.log(`[FoodLink] Hourly reminder system toggled: ${reminderActive ? "ACTIVE" : "PAUSED"}`);
    res.json({ ok: true, active: reminderActive });
});

// Admin check reminder status
app.get("/api/admin/reminders/status", needRole("admin"), function (req, res) {
    res.json({ ok: true, active: reminderActive });
});

// ---------- NGO Recurring Reminder Job ----------
// Disabled by default to protect daily quota and avoid inbox flooding
let ngoReminderActive = false;
let isProcessingNgoReminder = false;
let lastNgoReminderAt = 0;
const NGO_REMINDER_INTERVAL_MS = 2000;

async function processNgoReminderJob(force = false) {
    if (!ngoReminderActive && !force) return null;
    if (isProcessingNgoReminder) return null;

    isProcessingNgoReminder = true;
    try {
        if (!isSupabaseConfigured()) return null;
        const supabase = getSupabase();

        // 1. Auto-expire past-due listings
        await markExpired(supabase);

        // 2. Fetch available listings that NGOs can claim
        const { data: availableFoods } = await supabase
            .from("foods")
            .select("*")
            .eq("status", "available")
            .gt("expires", new Date().toISOString());

        const list = availableFoods || [];
        if (list.length === 0) {
            return { sent: false, message: "No active available food to remind NGOs." };
        }

        const now = Date.now();
        if (!force && (now - lastNgoReminderAt < NGO_REMINDER_INTERVAL_MS)) {
            return { sent: false, message: "Throttled to 2s intervals." };
        }

        // Send reminder ONLY to agileshkalaimani@gmail.com to protect quota as requested
        const ngoEmails = [process.env.DONOR_EMAIL || "agileshkalaimani@gmail.com"];

        console.log(`[FoodLink NGO Reminder] Sending reminder to ${ngoEmails[0]} for ${list.length} available listing(s)...`);
        const mailResult = await notifyNgosFoodReminder(list, ngoEmails);
        if (mailResult && mailResult.quotaExceeded) {
            console.warn("[FoodLink NGO Reminder] Quota reached. Auto-pausing reminders.");
            ngoReminderActive = false;
        }

        lastNgoReminderAt = Date.now();
        return { sent: true, mailResult };
    } catch (err) {
        console.error("[FoodLink NGO Reminder Error]:", err.message);
        return { sent: false, error: err.message };
    } finally {
        isProcessingNgoReminder = false;
    }
}

// Note: Automatic 2-second interval timer disabled to prevent consuming email quota.
// Reminders are triggered only on explicit user events or manual admin action.

// Recurring reminder timer: checks on the configured schedule (default: 1 hour)
setInterval(() => {
    try {
        processHourlyReminderJob(false);
    } catch (e) {}
}, REMINDER_INTERVAL_MS);

// Continuous auto-expire timer: scans every 3 seconds in the background
setInterval(async () => {
    try {
        if (isSupabaseConfigured()) {
            await markExpired(getSupabase());
        }
    } catch (e) {}
}, 3000);

// ---------- Start Server ----------
if (require.main === module) {
    initDatabase()
        .then(function () {
            app.listen(PORT, function () {
                console.log("FoodLink running on port " + PORT);
            });
        })
        .catch(function (error) {
            console.error("[FoodLink] Warning: Database connection issue:", error.message);
            app.listen(PORT, function () {
                console.log("FoodLink running on port " + PORT + " (waiting for credentials)");
            });
        });
}

module.exports = app;
