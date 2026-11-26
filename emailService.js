require("dotenv").config();
const { Resend } = require("resend");

const resend = process.env.RESEND_API_KEY ? new Resend(process.env.RESEND_API_KEY) : null;
const fromEmail = process.env.FROM_EMAIL || "FoodLink <agileshnv2005@gmail.com>";

const DEFAULT_APP_URL = "https://apexinterview.in";
const DEFAULT_ADMIN_EMAIL = "26mx128@psgtech.ac.in";
const DEFAULT_DONOR_EMAIL = "agileshkalaimani@gmail.com";

const appUrl = (
    process.env.APP_URL ||
    DEFAULT_APP_URL
).replace(/\/$/, "");

// ─── Core Mailer ───────────────────────────────────────────────────────────────
async function sendMail({ to, subject, html }) {
    const recipients = Array.isArray(to) ? to.filter(Boolean) : [to].filter(Boolean);
    if (recipients.length === 0) {
        console.warn("[FoodLink Email] No valid recipients — skipping.");
        return { success: false, error: "No recipients" };
    }

    // 1. Brevo (Sendinblue) API Mailer (Primary)
    const brevoKey = process.env.BREVO_API_KEY;
    if (brevoKey) {
        let senderName = "FoodLink";
        let senderEmail = "agileshnv2005@gmail.com";
        const senderMatch = fromEmail.match(/^(.*?)\s*<(.+?)>$/);
        if (senderMatch) {
            senderName = senderMatch[1].trim() || senderName;
            senderEmail = senderMatch[2].trim() || senderEmail;
        }

        const results = [];
        for (const recipient of recipients) {
            try {
                const response = await fetch("https://api.brevo.com/v3/smtp/email", {
                    method: "POST",
                    headers: {
                        "accept": "application/json",
                        "api-key": brevoKey,
                        "content-type": "application/json"
                    },
                    body: JSON.stringify({
                        sender: { name: senderName, email: senderEmail },
