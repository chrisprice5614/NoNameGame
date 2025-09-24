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
const sharp = require("sharp");

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

  // NEW: get the 3 most recent published blog posts
  let recentPosts = [];
  try {
    recentPosts = db.prepare(`
    SELECT title, slug, created_at, hero
    FROM blog_posts
    WHERE published = 1
    ORDER BY datetime(created_at) DESC
    LIMIT 3
  `).all();

  } catch (e) {
    // if table doesn't exist yet, keep recentPosts empty
    recentPosts = [];
  }

  res.render("index", {
    stats: {
      donors: row.donorCount,
      donations: row.donationCount,
      totalCents: row.totalCents,
      totalDollars: row.totalCents / 100
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



app.listen(2024)