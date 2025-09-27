require("dotenv").config() // Makes it so we can access .env file
const express = require("express")//npm install express
const db = require("better-sqlite3")("data.db") //npm install better-sqlite3
const body_parser = require("body-parser")
const path = require('path');
const node_fetch = require("node-fetch")
const nodemailer = require("nodemailer")
const jwt = require("jsonwebtoken")//npm install jsonwebtoken dotenv
const bcrypt = require("bcrypt") //npm install bcrypt
const cookieParser = require("cookie-parser")//npm install cookie-parser
const stripe = require("stripe")(process.env.STRIPE_SECRET_KEY);
const fs = require("fs");
const multer = require("multer");
const crypto = require("crypto");
const sharp = require("sharp");

const online = true;
function normalizeEmail(e) {
  return String(e || "").trim().toLowerCase();
}


function generateSecret(len = 24) {
  return crypto.randomBytes(len).toString("base64url").replace(/[^a-zA-Z0-9]/g, "").slice(0, len);
}


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
        from: '"The Game With No Name" <info@thegamewithnoname.com>',
        to: to,
        subject: subject,
        html: `
        <!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>The Game With No Name — Email</title>
  <style>
    /* --- Mobile resets --- */
    body { margin:0; padding:0; background:#F2E9DC; }
    table { border-collapse:collapse; }
    img { border:0; line-height:100%; outline:none; text-decoration:none; }
    a { text-decoration:underline; }

    /* --- Brand palette (no external assets) ---
       Saddle       #3B2410
       Mesa Clay    #C46A2B
       Dry Grass    #E2C9A3
       Parchment    #FFF9EF
       Night Sky    #1E1A16
    */

    /* --- Responsiveness --- */
    @media only screen and (max-width: 600px) {
      .content { width:100% !important; border-radius:0 !important; padding:24px !important; }
      .wrap { padding:16px !important; }
      .h1 { font-size:24px !important; line-height:1.2 !important; }
      .h2 { font-size:18px !important; }
      .btn { display:block !important; width:100% !important; }
    }

    /* Dark mode hint (many clients ignore, but harmless) */
    @media (prefers-color-scheme: dark) {
      body { background:#1E1A16; }
      .content { background:#2A241E !important; color:#F2E9DC !important; }
      .muted { color:#BCA98C !important; }
      a { color:#E5A46E !important; }
    }
  </style>
</head>
<body style="margin:0; padding:0; background:#F2E9DC;">
  <!-- Preheader (hidden preview text) -->
  <div style="display:none; visibility:hidden; opacity:0; color:transparent; height:0; width:0; overflow:hidden; mso-hide:all;">
    Dispatch from the frontier — updates for The Game With No Name.
  </div>

  <!-- Background wrapper -->
  <table role="presentation" width="100%" bgcolor="#F2E9DC" cellpadding="0" cellspacing="0">
    <tr>
      <td align="center" style="padding:24px;">

        <!-- Card -->
        <table role="presentation" class="content" width="600" cellpadding="0" cellspacing="0" style="max-width:600px; width:100%; background:#FFF9EF; border-radius:8px; box-shadow:0 1px 0 rgba(30,26,22,0.04);">
          <!-- Top bar accent -->
          <tr>
            <td height="6" style="background:#C46A2B; border-top-left-radius:8px; border-top-right-radius:8px;"></td>
          </tr>

          <tr>
            <td class="wrap" style="padding:32px; font-family: Georgia, 'Times New Roman', Times, serif; color:#3B2410;">

              <!-- Title -->
              <div class="h1" style="font-size:28px; line-height:1.25; font-weight:700; letter-spacing:0.5px; text-align:center;">
                THE GAME WITH NO NAME
              </div>

              <!-- Subhead rule -->
              <div style="height:1px; line-height:1px; background:#E2C9A3; margin:16px auto 24px; max-width:160px;"></div>

              <!-- Body copy container (developer injects HTML here) -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0">
                <tr>
                  <td style="font-family: 'Helvetica Neue', Arial, Helvetica, sans-serif; font-size:16px; line-height:1.6; color:#1E1A16;">
                    <!-- Inject your dynamic HTML here -->
                    ${html}
                  </td>
                </tr>
              </table>

              <!-- CTA example (optional) -->
              <!--
              <table role="presentation" align="center" cellpadding="0" cellspacing="0" style="margin:24px auto 0;">
                <tr>
                  <td>
                    <a class="btn" href="https://thegamewithnoname.com/" target="_blank" style="display:inline-block; padding:12px 18px; border-radius:4px; background:#C46A2B; color:#FFF9EF; font-family: 'Helvetica Neue', Arial, Helvetica, sans-serif; font-size:14px; font-weight:700; letter-spacing:0.3px; text-decoration:none;">
                      Saddle Up & Play
                    </a>
                  </td>
                </tr>
              </table>
              -->

              <!-- Footer -->
              <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="margin-top:28px;">
                <tr>
                  <td align="center" class="muted" style="font-family: 'Helvetica Neue', Arial, Helvetica, sans-serif; font-size:12px; color:#7A6046;">
                    © 2025 The Game With No Name ·
                    <a href="https://thegamewithnoname.com/" style="color:#7A6046; text-decoration:underline;">www.thegamewithnoname.com</a>
                  </td>
                </tr>
              </table>

            </td>
          </tr>
        </table>

        <!-- Bottom spacing -->
        <table role="presentation" width="600" cellpadding="0" cellspacing="0" style="max-width:600px; width:100%;">
          <tr><td style="height:16px; line-height:16px; font-size:0;">&nbsp;</td></tr>
        </table>

      </td>
    </tr>
  </table>
</body>
</html>


        `

    })

}

const delay = (ms) => new Promise(res => setTimeout(res, ms));

async function sendBulkEmails(emailList, subject, html) {
  for (let i = 0; i < emailList.length; i++) {
    const to = emailList[i];
    try {
      await sendEmail(to, subject, html);
      console.log(`Sent to ${to}`);
    } catch (err) {
      console.error(`Failed to send to ${to}:`, err.message);
    }

    // Don't delay after the last one
    if (i < emailList.length - 1) {
      await delay(5000); // wait 5 seconds before next send
    }
  }
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

    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS emailList (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email STRING,
        secret STRING
        )
        `
    ).run()

    try { db.prepare(`ALTER TABLE emailList ADD COLUMN secret STRING`).run(); } catch {}

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


    db.prepare(`
    CREATE TABLE IF NOT EXISTS blog_posts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      title TEXT NOT NULL,
      slug  TEXT NOT NULL UNIQUE,
      html  TEXT NOT NULL,
      published INTEGER NOT NULL DEFAULT 0,
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    )
    `).run();
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_blog_published ON blog_posts(published)`).run();
    db.prepare(`CREATE INDEX IF NOT EXISTS idx_blog_created ON blog_posts(created_at)`).run();

    try { db.prepare(`ALTER TABLE blog_posts ADD COLUMN hero TEXT`).run(); } catch {}

})

createTables()



const app = express()

// Format name (first + initials of rest)
function formatName(full) {
  if (!full || !full.trim()) return "Anonymous";
  const parts = full.trim().split(/\s+/);
  if (parts.length === 1) return parts[0];
  return parts[0] + " " + parts.slice(1).map(p => p[0].toUpperCase() + "").join(" ");
}

// Make helper available in all views
app.locals.formatName = formatName;



app.use(express.json())
app.set("view engine", "ejs")
app.set("views", path.join(__dirname, "views"));
app.use(express.static("public")) //Using public folder
app.use(express.static('/public'));
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser(process.env.COOKIE_SECRET || "dev-cookie-secret"));
app.use(express.json());
app.use(body_parser.json())
app.use(express.urlencoded({ limit: "10mb", extended: true }));

const UPLOAD_DIR = path.join(__dirname, "uploads");
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR);

app.use("/uploads", express.static(UPLOAD_DIR, { maxAge: "365d", immutable: true }));

function slugify(s="") {
  return s.toString().toLowerCase()
    .trim()
    .replace(/['"]/g,"")
    .replace(/[^a-z0-9]+/g,"-")
    .replace(/^-+|-+$/g,"")
    .slice(0,100) || "post-" + Date.now();
}

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB
  fileFilter: (req, file, cb) => {
    if (/^image\/(png|jpe?g|webp|gif|svg\+xml)$/i.test(file.mimetype)) cb(null, true);
    else cb(new Error("Images only"), false);
  }
});

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

  // NEW: get newsletter subscriber count
  const newsletterStats = db.prepare(`SELECT COUNT(*) AS cnt FROM emailList`).get();

  let recentPosts = [];
  try {
    recentPosts = db.prepare(`
      SELECT title, slug, created_at, hero
      FROM blog_posts
      WHERE published = 1
      ORDER BY datetime(created_at) DESC
      LIMIT 3
    `).all();
  } catch {
    recentPosts = [];
  }

  res.render("index", {
    stats: {
      donors: row.donorCount,
      donations: row.donationCount,
      totalCents: row.totalCents,
      totalDollars: row.totalCents / 100,
      newsletterCount: newsletterStats.cnt   // <- pass count
    },
    recentPosts
  });
});



function toCents(amountStr) {
  const n = Number(amountStr);
  if (!isFinite(n)) return NaN;
  return Math.round(n * 100);
}

// ==== Admin Auth (cookie name: noAdmin) ====
const ADMIN_COOKIE = "noAdmin";

function signAdminToken(payload = {}) {
  return jwt.sign(
    { role: "admin", ...payload },
    process.env.ADMIN_JWT_SECRET || "dev-admin-secret",
    { expiresIn: "7d" }
  );
}

function verifyAdminToken(token) {
  try {
    return jwt.verify(token, process.env.ADMIN_JWT_SECRET || "dev-admin-secret");
  } catch {
    return null;
  }
}

function isAdmin(req) {
  // try signed cookie first, then unsigned (in case signing not configured)
  const token = (req.signedCookies && req.signedCookies[ADMIN_COOKIE]) || req.cookies[ADMIN_COOKIE];
  if (!token) return false;
  const decoded = verifyAdminToken(token);
  return decoded && decoded.role === "admin";
}

function requireAdmin(req, res, next) {
  if (isAdmin(req)) return next();
  // Not authenticated—show login page
  return res.render("admin-login", {
    error: null
  });
}

// Show donations in admin (most recent first)
app.get("/admin", requireAdmin, (req, res) => {
  // Change this limit if you want more/less on one page
  const LIMIT = 500;

  const donations = db.prepare(`
    SELECT id, name, email, message, donation, created_at
    FROM donations
    ORDER BY datetime(created_at) DESC
    LIMIT ?
  `).all(LIMIT);

  const totals = db.prepare(`
    SELECT
      COUNT(*) AS donationCount,
      COALESCE(SUM(donation), 0) AS totalDollars
    FROM donations
  `).get();

  res.render("admin", { donations, totals, limit: LIMIT });
});

// Detail (printer-friendly Thank-You page)
app.get("/donations/:id", (req, res) => {
  const id = Number(req.params.id);
  const d = db.prepare(`
    SELECT id, name, message, donation, created_at
    FROM donations
    WHERE id = ?
  `).get(id);
  if (!d) return res.status(404).render("donation-missing");
  res.render("donation", { d });
});


// POST /admin/login
app.post("/admin/login", (req, res) => {
  const { password } = req.body || {};
  const expected = process.env.ADMIN_PASSWORD;

  if (!expected) {
    return res.status(500).send("ADMIN_PASSWORD is not set on the server.");
  }

  if (password && password === expected) {
    const token = signAdminToken({ at: Date.now() });
    res.cookie(ADMIN_COOKIE, token, {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.NODE_ENV === "production",
      signed: true,
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });
    return res.redirect("/admin");
  }

  return res.status(401).render("admin-login", {
    error: "Incorrect password."
  });
});

// POST /admin/logout
app.post("/admin/logout", (req, res) => {
  res.clearCookie(ADMIN_COOKIE);
  res.redirect("/admin");
});

function donationThanksEmail({ name, dollars, unsubLink, isNewSub }) {
  return `
    <h2>Thank you for backing The Game With No Name!</h2>
    <p>Howdy ${escapeHtml(name)} — your support of <strong>$${dollars}</strong> means a ton 🤠</p>
    ${isNewSub ? `
      <p>You’ve also been <strong>added to the TGWNN newsletter</strong> so you’ll get dev updates, builds, and behind-the-scenes.</p>
    ` : `
      <p>You’re already on our newsletter list, so you’ll keep getting dev updates, builds, and behind-the-scenes.</p>
    `}
    <hr/>
    <p style="font-size:12px;color:#777">
      Don’t want these emails? <a href="${unsubLink}">Unsubscribe</a>.
    </p>
  `;
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

    try {
    if (email) {
      // subscribe donor if not already subscribed
      const lower = normalizeEmail(email);
      const sub = db.prepare("SELECT id, secret FROM emailList WHERE LOWER(email)=LOWER(?)").get(lower);

      let secret, isNewSub = false;
      if (!sub) {
        secret = generateSecret(16);
        db.prepare("INSERT INTO emailList (email, secret) VALUES (?, ?)").run(lower, secret);
        isNewSub = true;
      } else {
        secret = sub.secret;
      }

      const base = process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`;
      const unsubLink = `${base}/unsub/${secret}`;

      // send donor welcome + thank-you (or just thank-you if already subscribed)
      await sendEmail(
        email,
        "Thanks for your donation — and welcome to the TGWNN newsletter!",
        donationThanksEmail({
          name,
          dollars: (amount_cents / 100).toFixed(2),
          unsubLink,
          isNewSub
        })
      );
    }
  } catch (e) {
    console.error("Donor thank-you/newsletter send failed:", e);
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


// Admin: list posts
app.get("/admin/blog", requireAdmin, (req, res) => {
  const posts = db.prepare(`
    SELECT id, title, slug, published, created_at, updated_at
    FROM blog_posts ORDER BY datetime(created_at) DESC
  `).all();
  res.render("admin-blog-list", { posts });
});

// New post
app.get("/admin/blog/new", requireAdmin, (req, res) => {
  res.render("blog-edit", { post: null, action: "/admin/blog/save" });
});

// Edit post
app.get("/admin/blog/:id/edit", requireAdmin, (req, res) => {
  const post = db.prepare("SELECT * FROM blog_posts WHERE id = ?").get(Number(req.params.id));
  if (!post) return res.status(404).send("Post not found");
  res.render("blog-edit", { post, action: "/admin/blog/save" });
});

// Create/update
// Create/update
app.post("/admin/blog/save", requireAdmin, (req, res) => {
  const { id, title, slug, html, published, hero } = req.body; // <- hero here
  const safeTitle = (title || "").trim();
  const safeSlug  = slugify(slug || title || "");
  const safeHero  = (hero || "").trim(); // can be empty

  if (!safeTitle || !html) return res.status(400).send("Title and HTML required.");

  if (id) {
    db.prepare(`
      UPDATE blog_posts
      SET title=?, slug=?, html=?, hero=?, published=?, updated_at=CURRENT_TIMESTAMP
      WHERE id=?
    `).run(safeTitle, safeSlug, html, safeHero, published ? 1 : 0, Number(id));
  } else {
    db.prepare(`
      INSERT INTO blog_posts (title, slug, html, hero, published)
      VALUES (?, ?, ?, ?, ?)
    `).run(safeTitle, safeSlug, html, safeHero, published ? 1 : 0);
  }
  return res.redirect("/admin/blog");
});


// Toggle publish
app.post("/admin/blog/:id/publish", requireAdmin, (req, res) => {
  const { published } = req.body;
  db.prepare(`UPDATE blog_posts SET published=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`)
    .run(published ? 1 : 0, Number(req.params.id));
  res.redirect("/admin/blog");
});

// Delete
app.post("/admin/blog/:id/delete", requireAdmin, (req, res) => {
  db.prepare(`DELETE FROM blog_posts WHERE id=?`).run(Number(req.params.id));
  res.redirect("/admin/blog");
});

// Image upload -> webp (70%), max long side 720
app.post("/admin/blog/upload", requireAdmin, upload.array("images", 8), async (req, res) => {
  try {
    const results = [];
    for (const file of req.files || []) {
      const img = sharp(file.buffer, { failOn: "none" });
      const meta = await img.metadata();
      const w = meta.width || 0, h = meta.height || 0;
      const longSide = Math.max(w, h) || 720;

      const target = Math.min(720, longSide); // cap long side at 720
      const fitOpts = w >= h ? { width: target } : { height: target };

      const outName = `${Date.now()}-${Math.random().toString(36).slice(2,8)}.webp`;
      const outPath = path.join(UPLOAD_DIR, outName);

      await img.resize(fitOpts).webp({ quality: 70 }).toFile(outPath);

      // Get dims after resize
      const { width: rw, height: rh } = await sharp(outPath).metadata();
      results.push({ url: `/uploads/${outName}`, width: rw, height: rh });
    }
    res.json({ ok: true, files: results });
  } catch (e) {
    console.error(e);
    res.status(500).json({ ok: false, error: "Upload failed" });
  }
});

// Blog index
app.get("/blog", (req, res) => {
  const posts = db.prepare(`
    SELECT title, slug, created_at, hero
    FROM blog_posts
    WHERE published=1
    ORDER BY datetime(created_at) DESC
  `).all();

  res.render("blog-index", { posts });
});

// Blog post
app.get("/blog/:slug", (req, res) => {
  const post = db.prepare(`
  SELECT *
  FROM blog_posts
  WHERE slug=? AND published=1
`).get(req.params.slug);

  if (!post) return res.status(404).render("donation-missing"); // reuse your 404 if you like
  res.render("blog-post", { post });
});

// Single hero upload -> webp (70%), max long side 1200
app.post("/admin/blog/upload-hero", requireAdmin, upload.single("hero"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok:false, error:"No file" });
    const img = sharp(req.file.buffer, { failOn: "none" });
    const meta = await img.metadata();
    const w = meta.width || 0, h = meta.height || 0;
    const longSide = Math.max(w, h) || 1200;
    const target = Math.min(1200, longSide);
    const fitOpts = w >= h ? { width: target } : { height: target };

    const outName = `hero-${Date.now()}-${Math.random().toString(36).slice(2,8)}.webp`;
    const outPath = path.join(UPLOAD_DIR, outName);

    await img.resize(fitOpts).webp({ quality: 70 }).toFile(outPath);
    const { width: rw, height: rh } = await sharp(outPath).metadata();

    return res.json({ ok:true, file: { url: `/uploads/${outName}`, width: rw, height: rh } });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ ok:false, error:"Upload failed" });
  }
});

app.post("/subscribe", async (req, res) => {
  try {
    const raw = (req.body && req.body.email) || "";
    const email = normalizeEmail(raw);
    if (!email) return res.status(400).json({ message: "Email required" });

    // Check if already exists
    const existing = db.prepare(
      "SELECT id, email, secret FROM emailList WHERE LOWER(email) = LOWER(?)"
    ).get(email);

    if (existing) {
      return res.json({ message: "You’re already subscribed!" });
    }

    const secret = generateSecret(16);
    db.prepare("INSERT INTO emailList (email, secret) VALUES (?, ?)").run(email, secret);

    const base =
      process.env.PUBLIC_BASE_URL ||
      `${req.protocol}://${req.get("host")}`;
    const unsubLink = `${base}/unsub/${secret}`;

    // Send welcome email (includes unsubscribe)
    const welcomeHtml = `
      <p>Welcome to <strong>The Game With No Name</strong> newsletter!</p>
      <p>You’ll get dev updates, builds, and behind-the-scenes right here.</p>
      <hr/>
      <p style="font-size:12px;color:#777">
        Don’t want these? <a href="${unsubLink}">Unsubscribe</a>.
      </p>
    `;

    await sendEmail(email, "Welcome to TGWNN Newsletter 🤠", welcomeHtml);

    return res.json({ message: "You’ve been subscribed! Check your email." });
  } catch (err) {
    console.error("Subscribe error:", err);
    return res.status(500).json({ message: "Error subscribing" });
  }
});


app.get("/unsub/:secret", (req, res) => {
  try {
    const { secret } = req.params || {};
    if (!secret) return res.status(400).send("Invalid link.");

    const result = db.prepare("DELETE FROM emailList WHERE secret = ?").run(secret);

    if (result.changes > 0) {
      return res.send(`
        <!doctype html><meta charset="utf-8">
        <title>Unsubscribed</title>
        <div style="max-width:560px;margin:40px auto;font-family:Arial,Helvetica,sans-serif;line-height:1.5">
          <h1 style="margin:0 0 8px">You’ve been unsubscribed.</h1>
          <p>You will no longer receive emails from <em>The Game With No Name</em>.</p>
          <p><a href="/">Return to homepage</a></p>
        </div>
      `);
    } else {
      return res.send(`
        <!doctype html><meta charset="utf-8">
        <title>Invalid link</title>
        <div style="max-width:560px;margin:40px auto;font-family:Arial,Helvetica,sans-serif;line-height:1.5">
          <h1 style="margin:0 0 8px">Invalid or expired link</h1>
          <p>This unsubscribe link has already been used or is not valid.</p>
          <p><a href="/">Return to homepage</a></p>
        </div>
      `);
    }
  } catch (err) {
    console.error("Unsub error:", err);
    return res.status(500).send("Error unsubscribing. Please try again later.");
  }
});

function appendUnsub(html, unsubUrl) {
  return `${html}
    <hr/>
    <p style="font-size:12px;color:#777">
      Don’t want these emails? <a href="${unsubUrl}">Unsubscribe</a>.
    </p>`;
}

// Example broadcast (sequential, spaced out)
async function sendNewsletterToAll(subject, baseHtml) {
  const base = process.env.PUBLIC_BASE_URL || "https://thegamewithnoname.com";
  const subs = db.prepare("SELECT email, secret FROM emailList").all();

  for (let i = 0; i < subs.length; i++) {
    const { email, secret } = subs[i];
    const unsub = `${base}/unsub/${secret}`;
    try {
      await sendEmail(email, subject, appendUnsub(baseHtml, unsub));
      console.log("Sent to", email);
    } catch (e) {
      console.error("Failed to send to", email, e.message);
    }
    if (i < subs.length - 1) await delay(5000);
  }
}

// Page: editor + preview (ADMIN ONLY)
app.get("/admin/newsletter", requireAdmin, (req, res) => {
  const stats = db.prepare("SELECT COUNT(*) AS n FROM emailList").get();
  const subsCount = stats?.n || 0;

  // Sensible defaults you can tweak
  const defaultSubject = "TGWNN Dev Update";
  const defaultHtml = `
    <h2>Howdy from The Game With No Name 🤠</h2>
    <p>Quick update from the frontier:</p>
    <ul>
      <li>New pre-alpha build notes</li>
      <li>Level polish and weapon pass</li>
      <li>Upcoming playtest schedule</li>
    </ul>
    <p>Thanks for backing and sharing!</p>
  `.trim();

  res.render("admin-newsletter", { subsCount, defaultSubject, defaultHtml });
});

// Send to everyone (ADMIN ONLY)
app.post("/admin/newsletter/send", requireAdmin, async (req, res) => {
  try {
    const { subject, html } = req.body || {};
    if (!subject || !html) {
      return res.status(400).json({ ok: false, message: "Subject and HTML are required." });
    }

    const base = process.env.PUBLIC_BASE_URL || `${req.protocol}://${req.get("host")}`;
    const subs = db.prepare("SELECT email, secret FROM emailList").all();

    let sent = 0, failed = 0;
    for (let i = 0; i < subs.length; i++) {
      const { email, secret } = subs[i];
      const unsubUrl = `${base}/unsub/${secret}`;
      try {
        await sendEmail(email, subject, appendUnsub(html, unsubUrl));
        sent++;
      } catch (e) {
        console.error("Newsletter send failed:", email, e.message);
        failed++;
      }
      if (i < subs.length - 1) await delay(5000); // 5s spacing
    }

    return res.json({ ok: true, sent, failed, total: subs.length });
  } catch (err) {
    console.error("newsletter/send error:", err);
    return res.status(500).json({ ok: false, message: "Failed to send newsletter." });
  }
});


app.listen(2024)