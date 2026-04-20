require("dotenv").config();
const express = require("express");
const { MongoClient, ObjectId } = require("mongodb");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");

const app = express();

// ── CORS ─────────────────────────────────────────
// Allow requests from Live Server (5500) during dev, and same-origin in prod
const allowedOrigins = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "http://localhost:5500",
  "http://127.0.0.1:5500",
  "http://localhost:5173", // Vite default
  process.env.CLIENT_URL,
].filter(Boolean);

app.use(
  cors({
    origin: function (origin, callback) {
      // Allow requests with no origin (mobile apps, curl, Postman)
      if (!origin) return callback(null, true);
      if (allowedOrigins.includes(origin)) return callback(null, true);
      return callback(new Error("CORS: origin not allowed — " + origin));
    },
    credentials: true,
  }),
);

app.use(express.json());

// ── STATIC FILES ─────────────────────────────────
// Serve everything in the current directory (index.html, CSS, JS, etc.)
app.use(express.static(path.join(__dirname)));

// ── CONFIG ───────────────────────────────────────
const MONGO_URI = process.env.MONGO_URI;
const JWT_SECRET = process.env.JWT_SECRET;
const PORT = process.env.PORT || 3000;

if (!MONGO_URI) {
  console.error("❌ MONGO_URI is not set in .env");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("❌ JWT_SECRET is not set in .env");
  process.exit(1);
}

// ── DB CONNECTION ────────────────────────────────
let db;
MongoClient.connect(MONGO_URI)
  .then((client) => {
    db = client.db("packroute");
    console.log("✅ MongoDB connected");
    app.listen(PORT, () => {
      console.log(`🚀 Server running at http://localhost:${PORT}`);
      console.log(`   Open http://localhost:${PORT} in your browser`);
      console.log(`   (Do NOT use Live Server — use this URL directly)`);
    });
  })
  .catch((err) => {
    console.error("❌ MongoDB connection failed:", err.message);
    process.exit(1);
  });

// ── AUTH MIDDLEWARE ──────────────────────────────
function auth(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No token" });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "Invalid token" });
  }
}

// ── DB READY GUARD ───────────────────────────────
// Prevents crashes if a request comes in before MongoDB connects
function dbReady(req, res, next) {
  if (!db) return res.status(503).json({ error: "Database not ready yet" });
  next();
}
app.use("/api", dbReady);

// ══════════════════════════════
// AUTH ROUTES
// ══════════════════════════════

// POST /api/auth/signup
app.post("/api/auth/signup", async (req, res) => {
  try {
    const { firstName, lastName, email, password, role } = req.body;
    if (!firstName || !lastName || !email || !password)
      return res.status(400).json({ error: "All fields required" });
    if (password.length < 8)
      return res
        .status(400)
        .json({ error: "Password must be at least 8 characters" });
    const existing = await db
      .collection("users")
      .findOne({ email: email.toLowerCase() });
    if (existing)
      return res.status(409).json({ error: "Email already registered" });
    const hash = await bcrypt.hash(password, 10);
    const user = {
      firstName,
      lastName,
      email: email.toLowerCase(),
      password: hash,
      role: role || "both",
      bio: "",
      phone: "",
      rating: 5.0,
      deliveries: 0,
      createdAt: new Date(),
    };
    const result = await db.collection("users").insertOne(user);
    const token = jwt.sign(
      {
        id: result.insertedId.toString(),
        email: user.email,
        name: `${firstName} ${lastName}`,
      },
      JWT_SECRET,
      { expiresIn: "7d" },
    );
    res.json({
      token,
      user: {
        id: result.insertedId,
        firstName,
        lastName,
        email: user.email,
        role: user.role,
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/auth/login
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: "Email and password required" });
    const user = await db
      .collection("users")
      .findOne({ email: email.toLowerCase() });
    if (!user)
      return res.status(401).json({ error: "Invalid email or password" });
    const match = await bcrypt.compare(password, user.password);
    if (!match)
      return res.status(401).json({ error: "Invalid email or password" });
    const token = jwt.sign(
      {
        id: user._id.toString(),
        email: user.email,
        name: `${user.firstName} ${user.lastName}`,
      },
      JWT_SECRET,
      { expiresIn: "7d" },
    );
    res.json({
      token,
      user: {
        id: user._id,
        firstName: user.firstName,
        lastName: user.lastName,
        email: user.email,
        role: user.role,
      },
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/auth/me
app.get("/api/auth/me", auth, async (req, res) => {
  try {
    const user = await db
      .collection("users")
      .findOne(
        { _id: new ObjectId(req.user.id) },
        { projection: { password: 0 } },
      );
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════
// REQUESTS ROUTES
// ══════════════════════════════

// GET /api/requests?filter=all|urgent|open|light&from=&to=
app.get("/api/requests", auth, async (req, res) => {
  try {
    const { filter, from, to } = req.query;
    let query = {};
    if (filter === "urgent") query.status = "urgent";
    else if (filter === "open") query.status = "open";
    else if (filter === "light") query.weight = { $lt: 1 };
    else query.status = { $in: ["open", "urgent"] };
    if (from) query.from = { $regex: from, $options: "i" };
    if (to) query.to = { $regex: to, $options: "i" };
    const requests = await db
      .collection("requests")
      .find(query)
      .sort({ createdAt: -1 })
      .limit(50)
      .toArray();
    const enriched = await Promise.all(
      requests.map(async (r) => {
        const sender = await db.collection("users").findOne(
          { _id: new ObjectId(r.senderId) },
          {
            projection: {
              password: 0,
              firstName: 1,
              lastName: 1,
              rating: 1,
              deliveries: 1,
            },
          },
        );
        return {
          ...r,
          senderName: sender
            ? `${sender.firstName} ${sender.lastName}`
            : "Unknown",
          senderRating: sender?.rating || 5.0,
          senderDeliveries: sender?.deliveries || 0,
        };
      }),
    );
    res.json(enriched);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// GET /api/requests/:id
app.get("/api/requests/:id", auth, async (req, res) => {
  try {
    const r = await db
      .collection("requests")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!r) return res.status(404).json({ error: "Request not found" });
    const sender = await db
      .collection("users")
      .findOne(
        { _id: new ObjectId(r.senderId) },
        { projection: { password: 0 } },
      );
    res.json({
      ...r,
      senderName: sender ? `${sender.firstName} ${sender.lastName}` : "Unknown",
      senderRating: sender?.rating || 5.0,
      senderDeliveries: sender?.deliveries || 0,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/requests
app.post("/api/requests", auth, async (req, res) => {
  try {
    const {
      from,
      to,
      fromAddr,
      toAddr,
      category,
      weight,
      size,
      description,
      tags,
      reward,
      deadline,
      handoff,
      visibility,
    } = req.body;
    if (!from || !to || !description || !reward || !deadline || !weight)
      return res.status(400).json({ error: "Missing required fields" });
    const request = {
      senderId: req.user.id,
      from,
      to,
      fromAddr: fromAddr || from,
      toAddr: toAddr || to,
      category: category || "Other",
      weight: parseFloat(weight),
      size: size || "Small box",
      description,
      tags: tags || [],
      reward: parseFloat(reward),
      deadline,
      handoff: handoff || "Flexible",
      visibility: visibility || "public",
      status: "open",
      views: 0,
      proposals: 0,
      qna: [],
      createdAt: new Date(),
    };
    const result = await db.collection("requests").insertOne(request);
    res.json({ ...request, _id: result.insertedId });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// PATCH /api/requests/:id/status
app.patch("/api/requests/:id/status", auth, async (req, res) => {
  try {
    const { status } = req.body;
    const r = await db
      .collection("requests")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!r) return res.status(404).json({ error: "Not found" });
    if (r.senderId !== req.user.id)
      return res.status(403).json({ error: "Forbidden" });
    await db
      .collection("requests")
      .updateOne({ _id: new ObjectId(req.params.id) }, { $set: { status } });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// DELETE /api/requests/:id
app.delete("/api/requests/:id", auth, async (req, res) => {
  try {
    const r = await db
      .collection("requests")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!r) return res.status(404).json({ error: "Not found" });
    if (r.senderId !== req.user.id)
      return res.status(403).json({ error: "Forbidden" });
    await db
      .collection("requests")
      .deleteOne({ _id: new ObjectId(req.params.id) });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/requests/:id/view
app.post("/api/requests/:id/view", auth, async (req, res) => {
  try {
    await db
      .collection("requests")
      .updateOne({ _id: new ObjectId(req.params.id) }, { $inc: { views: 1 } });
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/requests/:id/question
app.post("/api/requests/:id/question", auth, async (req, res) => {
  try {
    const { question } = req.body;
    if (!question?.trim())
      return res.status(400).json({ error: "Question required" });
    const qna = {
      id: new ObjectId().toString(),
      question,
      questionBy: req.user.name,
      questionById: req.user.id,
      answer: null,
      askedAt: new Date(),
    };
    await db
      .collection("requests")
      .updateOne({ _id: new ObjectId(req.params.id) }, { $push: { qna } });
    res.json(qna);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// POST /api/requests/:id/answer/:qnaId
app.post("/api/requests/:id/answer/:qnaId", auth, async (req, res) => {
  try {
    const { answer } = req.body;
    const r = await db
      .collection("requests")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!r) return res.status(404).json({ error: "Not found" });
    if (r.senderId !== req.user.id)
      return res.status(403).json({ error: "Only sender can answer" });
    await db.collection("requests").updateOne(
      { _id: new ObjectId(req.params.id), "qna.id": req.params.qnaId },
      {
        $set: {
          "qna.$.answer": answer,
          "qna.$.answeredAt": new Date(),
        },
      },
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════
// MY REQUESTS
// ══════════════════════════════
app.get("/api/my-requests", auth, async (req, res) => {
  try {
    const { status } = req.query;
    let query = { senderId: req.user.id };
    if (status && status !== "all") query.status = status;
    const requests = await db
      .collection("requests")
      .find(query)
      .sort({ createdAt: -1 })
      .toArray();
    res.json(requests);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════
// ACCEPT / PROPOSALS
// ══════════════════════════════
app.post("/api/requests/:id/accept", auth, async (req, res) => {
  try {
    const r = await db
      .collection("requests")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!r) return res.status(404).json({ error: "Not found" });
    if (r.senderId === req.user.id)
      return res
        .status(400)
        .json({ error: "You cannot accept your own request" });
    await db
      .collection("requests")
      .updateOne(
        { _id: new ObjectId(req.params.id) },
        { $inc: { proposals: 1 } },
      );
    let convo = await db.collection("conversations").findOne({
      reqId: req.params.id,
      $or: [{ user1Id: req.user.id }, { user2Id: req.user.id }],
    });
    if (!convo) {
      const sender = await db
        .collection("users")
        .findOne(
          { _id: new ObjectId(r.senderId) },
          { projection: { password: 0, firstName: 1, lastName: 1 } },
        );
      const convoDoc = {
        reqId: req.params.id,
        reqRoute: `${r.from} → ${r.to}`,
        reqReward: r.reward,
        user1Id: req.user.id,
        user1Name: req.user.name,
        user2Id: r.senderId,
        user2Name: sender ? `${sender.firstName} ${sender.lastName}` : "Sender",
        messages: [
          {
            from: r.senderId,
            fromName: sender
              ? `${sender.firstName} ${sender.lastName}`
              : "Sender",
            text: `Hi! Thanks for accepting my delivery request from ${r.from} to ${r.to}. Looking forward to coordinating!`,
            t: new Date().toISOString(),
            read: false,
          },
        ],
        lastMessage: "Thanks for accepting my request...",
        lastAt: new Date(),
        createdAt: new Date(),
      };
      const result = await db.collection("conversations").insertOne(convoDoc);
      convo = { ...convoDoc, _id: result.insertedId };
    }
    res.json({ success: true, conversationId: convo._id.toString() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════
// CONVERSATIONS / CHAT
// ══════════════════════════════

app.get("/api/conversations", auth, async (req, res) => {
  try {
    const convos = await db
      .collection("conversations")
      .find({
        $or: [{ user1Id: req.user.id }, { user2Id: req.user.id }],
      })
      .sort({ lastAt: -1 })
      .toArray();
    res.json(
      convos.map((c) => ({
        ...c,
        peer: c.user1Id === req.user.id ? c.user2Name : c.user1Name,
        peerId: c.user1Id === req.user.id ? c.user2Id : c.user1Id,
      })),
    );
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.get("/api/conversations/:id", auth, async (req, res) => {
  try {
    const c = await db
      .collection("conversations")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!c) return res.status(404).json({ error: "Not found" });
    if (c.user1Id !== req.user.id && c.user2Id !== req.user.id)
      return res.status(403).json({ error: "Forbidden" });
    res.json({
      ...c,
      peer: c.user1Id === req.user.id ? c.user2Name : c.user1Name,
      peerId: c.user1Id === req.user.id ? c.user2Id : c.user1Id,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.post("/api/conversations/:id/messages", auth, async (req, res) => {
  try {
    const { text } = req.body;
    if (!text?.trim())
      return res.status(400).json({ error: "Message text required" });
    const c = await db
      .collection("conversations")
      .findOne({ _id: new ObjectId(req.params.id) });
    if (!c) return res.status(404).json({ error: "Not found" });
    if (c.user1Id !== req.user.id && c.user2Id !== req.user.id)
      return res.status(403).json({ error: "Forbidden" });
    const message = {
      from: req.user.id,
      fromName: req.user.name,
      text: text.trim(),
      t: new Date().toISOString(),
      read: false,
    };
    await db.collection("conversations").updateOne(
      { _id: new ObjectId(req.params.id) },
      {
        $push: { messages: message },
        $set: { lastMessage: text.trim(), lastAt: new Date() },
      },
    );
    res.json(message);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════
// SETTINGS
// ══════════════════════════════
app.patch("/api/settings/profile", auth, async (req, res) => {
  try {
    const { firstName, lastName, phone, bio } = req.body;
    if (!firstName || !lastName)
      return res.status(400).json({ error: "Name required" });
    await db.collection("users").updateOne(
      { _id: new ObjectId(req.user.id) },
      {
        $set: {
          firstName,
          lastName,
          phone: phone || "",
          bio: bio || "",
        },
      },
    );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

app.patch("/api/settings/password", auth, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword)
      return res.status(400).json({ error: "Both passwords required" });
    if (newPassword.length < 8)
      return res
        .status(400)
        .json({ error: "New password must be at least 8 characters" });
    const user = await db
      .collection("users")
      .findOne({ _id: new ObjectId(req.user.id) });
    if (!user) return res.status(404).json({ error: "User not found" });
    const match = await bcrypt.compare(currentPassword, user.password);
    if (!match)
      return res.status(401).json({ error: "Current password is incorrect" });
    const hash = await bcrypt.hash(newPassword, 10);
    await db
      .collection("users")
      .updateOne(
        { _id: new ObjectId(req.user.id) },
        { $set: { password: hash } },
      );
    res.json({ success: true });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ══════════════════════════════
// SPA FALLBACK
// Must be LAST — catch all non-API routes and serve index.html
// ══════════════════════════════
app.get(/^(?!\/api).*/, (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});
