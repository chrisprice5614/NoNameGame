require("dotenv").config() // Makes it so we can access .env file
const express = require("express")//npm install express
const db = require("better-sqlite3")("data.db") //npm install better-sqlite3
const body_parser = require("body-parser")
const path = require('path');
const node_fetch = require("node-fetch")
const nodemailer = require("nodemailer")
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);

const online = true;


async function sendEmail(to, subject, html) {
  if(!online)
    return

    let transporter = nodemailer.createTransport({
        host: "smtp.gmail.com",
        port: 465,
        secure: true,
        auth: {
            user: process.env.MAILNAME,
            pass: process.env.MAILSECRET
        },
        tls: {
            rejectUnauthorized: false
        }
    });


    let info = await transporter.sendMail({
        from: '"Chris Price Music" <info@chrispricemusic.net>',
        to: to,
        subject: subject,
        html: `
        <!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Boise Gems Drum & Bugle Corps</title>
  <style>
    body {
      margin: 0;
      padding: 0;
      background-color: #f4f4f4;
    }

    table {
      border-collapse: collapse;
    }

    @media only screen and (max-width: 600px) {
      .content {
        width: 100% !important;
      }
      .logo {
        width: 80px !important;
      }
    }
  </style>
</head>
<body>
  <!-- Main wrapper with padding on cell -->
  <table width="100%" bgcolor="#f4f4f4" cellpadding="0" cellspacing="0" role="presentation">
    <tr>
      <td align="center" style="padding: 24px;">
        <!-- Centered content table -->
        <table class="content" width="600" cellpadding="0" cellspacing="0" style="background-color: #ffffff; padding: 32px; font-family: Arial, sans-serif; color: #333333; border-radius: 6px; max-width: 600px; width: 100%;">
          <!-- Logo -->
          <tr>
            <td align="center" style="padding-bottom: 24px;">
              <a href="https://www.boisegems.org/" target="_blank">
                <img src="https://raw.githubusercontent.com/chrisprice5614/chrisprice.io/refs/heads/main/gem.png" alt="Boise Gems Logo" width="100" class="logo" style="display: block; margin: 0 auto;">
              </a>
            </td>
          </tr>
          <!-- Title -->
          <tr>
            <td align="center" style="font-size: 24px; font-weight: bold; color: #60437D; padding-bottom: 12px;">
              Boise Gems Drum & Bugle Corps
            </td>
          </tr>
          <tr>
          </tr>
          <!-- Body -->
          <tr>
            <td style="font-size: 16px; line-height: 1.6; color: #333;">
              <p>${html}</p>

            
              </p>
              <p style="margin-top: 32px;">
                <strong>The Boise Gems</strong>
              </p>
            </td>
          </tr>
          <!-- Footer -->
          <tr>
            <td align="center" style="font-size: 12px; color: #999999; padding-top: 32px;">
              © 2025 Boise Gems Drum & Bugle Corps ·
              <a href="https://www.boisegems.org/" style="color: #999999; text-decoration: underline;">www.boisegems.org</a>
            </td>
          </tr>
        </table>
      </td>
    </tr>
  </table>
</body>
</html>

        `

    })

}

const createTables = db.transaction(() => {
    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS donations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name STRING,
        message STRING,
        created_at STRING default CURRENT_TIMESTAMP,
        donation INTEGER,
        email STRING
        )
        `
    ).run()

    db.prepare(`
    CREATE TABLE IF NOT EXISTS checkout_sessions (
        id INTEGER PRIMARY KEY,
        session_id TEXT UNIQUE,
        payment_intent_id TEXT,
        status TEXT NOT NULL DEFAULT 'created', -- created | completed | failed | canceled
        name TEXT,
        email TEXT,
        message TEXT,
        amount_cents INTEGER NOT NULL,
        currency TEXT NOT NULL DEFAULT 'usd',
        created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
        updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    `).run();

    db.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_session_id ON checkout_sessions(session_id)`).run();
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_sessions_status ON checkout_sessions(status)`).run();

    try { db.prepare(`ALTER TABLE donations ADD COLUMN stripe_payment_intent_id TEXT`).run(); } catch {}
    db.prepare(`CREATE UNIQUE INDEX IF NOT EXISTS idx_donations_pi ON donations(stripe_payment_intent_id)`).run();
})

createTables()



const app = express()



app.use(express.json())
app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public")) //Using public folder
app.use(express.static('/public'));
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(body_parser.json())
app.use(express.urlencoded({ limit: "10mb", extended: true }));

app.get("/", (req, res) => {
  const row = db.prepare(`
    SELECT
      COUNT(*) AS donationCount,
      COUNT(DISTINCT CASE
        WHEN email IS NOT NULL AND TRIM(email) <> '' THEN LOWER(TRIM(email))
        ELSE CAST(id AS TEXT)
      END) AS donorCount,
      COALESCE(SUM(donation), 0) AS totalCents
    FROM donations
  `).get();


  res.render("index", {
    stats: {
      donors: row.donorCount,
      donations: row.donationCount,
      totalCents: row.totalCents,
      totalDollars: row.totalCents / 100
    }
  });
});

function toCents(amountStr) {
  const n = Number(amountStr);
  if (!isFinite(n)) return NaN;
  return Math.round(n * 100);
}

app.post("/donate", async (req, res) => {
  try {
    const { name, email, amount, message } = req.body;

    const amount_cents = toCents(amount);
    if (!amount_cents || amount_cents < 500) return res.status(400).send("Minimum donation is $5.00");
    if (!name || !email) return res.status(400).send("Name and email are required.");

    const origin = process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`;

    const session = await stripe.checkout.sessions.create({
      mode: "payment",
      payment_method_types: ["card"],
      customer_email: email,
      line_items: [{
        price_data: {
          currency: "usd",
          product_data: {
            name: "Donation — The Game With No Name",
            description: (message || "Support the project").slice(0, 140)
          },
          unit_amount: amount_cents
        },
        quantity: 1
      }],
      success_url: `${origin}/thank-you?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${origin}/?canceled=1`,
      metadata: {
        donor_name: name,
        donor_message: message || ""
      }
    });

    return res.redirect(303, session.url);
  } catch (err) {
    console.error("Create session error:", err);
    return res.status(500).send("Could not start checkout.");
  }
});




function donationEmailTemplate({ name, email, message, amount }) {
  return `<!DOCTYPE html><html><head><meta charset="UTF-8" />
  <title>New Donation — The Game With No Name</title>
  <style>
    body { margin:0;background:#F8F1E3;font-family:Arial,Helvetica,sans-serif;color:#1F1D1C; }
    .wrap { max-width:640px;margin:0 auto;padding:24px; }
    .card { background:#fffaf1;border:1px solid #e3d9c6;border-radius:12px;padding:20px; }
    .h1 { font-size:22px;margin:0 0 10px 0;color:#6E3B16; }
    .row { margin:8px 0; }
    .label { color:#5f5b58;font-size:12px; text-transform:uppercase; letter-spacing:.04em; }
    .val { font-size:16px; }
  </style></head><body>
  <div class="wrap"><div class="card">
  <div class="h1">New donation received</div>
  <div class="row"><div class="label">Amount</div><div class="val">$${amount} USD</div></div>
  <div class="row"><div class="label">Name</div><div class="val">${escapeHtml(name)}</div></div>
  <div class="row"><div class="label">Email</div><div class="val">${escapeHtml(email)}</div></div>
  <div class="row"><div class="label">Message</div><div class="val">${escapeHtml(message)}</div></div>
  </div></div></body></html>`;
}
function escapeHtml(s){return String(s??"").replaceAll("&","&amp;").replaceAll("<","&lt;").replaceAll(">","&gt;").replaceAll('"',"&quot;").replaceAll("'","&#039;");}

app.get("/thank-you", async (req, res) => {
  try {
    const { session_id } = req.query;
    if (!session_id) return res.redirect("/");

    // Ask Stripe for the truth
    const session = await stripe.checkout.sessions.retrieve(session_id, {
      expand: ["payment_intent", "customer_details"]
    });

    const paid =
      session.payment_status === "paid" ||
      session.payment_intent?.status === "succeeded";

    if (!paid) {
      // Payment not finalized yet or canceled
      return res.render("thank-you"); // simple static TY is fine
    }

    const pi = session.payment_intent?.id || null;
    const name = session.metadata?.donor_name || session.customer_details?.name || "Anonymous";
    const email = session.customer_details?.email || session.customer_email || "";
    const message = session.metadata?.donor_message || "";
    const amount_cents = session.amount_total ?? 0;

    // Idempotent insert (prevents duplicates on refresh)
    const exists = pi
      ? db.prepare("SELECT 1 FROM donations WHERE stripe_payment_intent_id = ?").get(pi)
      : null;

    if (!exists) {
      db.prepare(`
        INSERT INTO donations (name, message, donation, email, stripe_payment_intent_id)
        VALUES (?, ?, ?, ?, ?)
      `).run(name, message, amount_cents/100, email, pi);

      // Email admin
      const dollars = (amount_cents / 100).toFixed(2);
      await sendEmail(
        "chrisprice5614@gmail.com",
        "New TGWNN donation",
        donationEmailTemplate({ name, email, message, amount: dollars })
      );
    }

    return res.render("thank-you"); // your existing thank-you page
  } catch (e) {
    console.error("thank-you error:", e);
    return res.render("thank-you"); // keep user experience clean
  }
});


app.get("/back", (req,res) => {
    return res.render("back")
})

app.listen(2024)