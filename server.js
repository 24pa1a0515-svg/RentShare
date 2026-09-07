/* ------------------------------------------------------------------
 * RentShare – Student Rental & Sharing Platform
 * Backend: Node.js + Express (single file)
 *
 * Run:
 *   npm install
 *   node server.js
 *
 * Data is stored in database.json (created empty, never pre-populated).
 * ------------------------------------------------------------------ */

const path = require('path');
const fs = require('fs');
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = process.env.PORT || 4000;
const JWT_SECRET = process.env.JWT_SECRET || 'rentshare-dev-secret-change-me';
const DB_FILE = path.join(__dirname, 'database.json');

const EMPTY_DB = {
  users: [],
  items: [],
  rentals: [],
  conversations: [],
  messages: [],
  reviews: [],
  notifications: [],
};

/* ---------------- tiny JSON database ---------------- */

function readDB() {
  try {
    const raw = fs.readFileSync(DB_FILE, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    return Object.assign({}, EMPTY_DB, parsed);
  } catch (e) {
    return JSON.parse(JSON.stringify(EMPTY_DB));
  }
}

function writeDB(db) {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2));
  fs.renameSync(tmp, DB_FILE);
}

if (!fs.existsSync(DB_FILE)) writeDB(JSON.parse(JSON.stringify(EMPTY_DB)));

function uid() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 8);
}

/* ---------------- helpers ---------------- */

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]{2,}$/;
const CATEGORIES = [
  'Calculators', 'Books', 'Lab Equipment', 'Electronics', 'Project Kits',
  'Cycles', 'Furniture', 'Cameras', 'Sports Equipment', 'Other Essentials',
];
const CONDITIONS = ['New', 'Like New', 'Good', 'Fair'];
const STATUSES = ['Requested', 'Accepted', 'Active', 'Returned', 'Completed', 'Cancelled', 'Rejected'];
const OPEN_STATUSES = ['Requested', 'Accepted', 'Active', 'Returned'];

function publicUser(u) {
  if (!u) return null;
  return { id: u.id, name: u.name, college: u.college, branch: u.branch, year: u.year, at: u.at };
}

function selfUser(u) {
  if (!u) return null;
  return {
    id: u.id, name: u.name, college: u.college, branch: u.branch,
    year: u.year, email: u.email, at: u.at,
  };
}

function str(v) {
  return typeof v === 'string' ? v.trim() : v == null ? '' : String(v).trim();
}

function num(v) {
  const n = Number(v);
  return isFinite(n) ? n : NaN;
}

function notify(db, userId, text, type, link) {
  if (!userId) return;
  db.notifications.unshift({
    id: uid(), userId, text, type: type || 'general',
    link: link || '', at: Date.now(), read: false,
  });
}

function signToken(user) {
  return jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: '7d' });
}

function currentUser(db, req) {
  const header = req.headers.authorization || '';
  const raw = header.startsWith('Bearer ') ? header.slice(7) : '';
  if (!raw) return null;
  try {
    const payload = jwt.verify(raw, JWT_SECRET);
    return db.users.find((u) => u.id === payload.sub) || null;
  } catch (e) {
    return null;
  }
}

function auth(req, res, next) {
  const db = readDB();
  const user = currentUser(db, req);
  if (!user) return res.status(401).json({ error: 'Authentication required. Please log in again.' });
  req.db = db;
  req.user = user;
  next();
}

function convoKey(a, b, itemId) {
  return [a, b].sort().join('|') + '#' + (itemId || '');
}

function calcRental(item, mode, start, end) {
  const ms = new Date(end) - new Date(start);
  if (!start || !end || isNaN(ms) || ms <= 0) return null;
  const hours = ms / 3600000;
  let units, cost;
  if (mode === 'hour') {
    units = Math.max(1, Math.ceil(hours));
    cost = units * Number(item.perHour);
  } else {
    units = Math.max(1, Math.ceil(hours / 24));
    cost = units * Number(item.perDay);
  }
  const deposit = Number(item.deposit) || 0;
  return { mode, units, cost, deposit, total: cost + deposit };
}

function overlaps(aStart, aEnd, bStart, bEnd) {
  return new Date(aStart) < new Date(bEnd) && new Date(bStart) < new Date(aEnd);
}

/* Digital Item Fingerprinting – architecture only. Identifiers are generated
   for real items created by real users; no verification result is ever faked. */
function itemFingerprint(id) {
  return 'RS-' + String(id).toUpperCase().slice(-8);
}

/* ---------------- app ---------------- */

const app = express();
app.use(cors({ origin: true, methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'] }));
app.use(express.json({ limit: '8mb' }));
app.use(express.static(__dirname));

/* ---------- auth ---------- */

app.post('/api/auth/register', async (req, res) => {
  const db = readDB();
  const b = req.body || {};
  const d = {
    name: str(b.name), college: str(b.college), branch: str(b.branch),
    year: str(b.year), email: str(b.email).toLowerCase(),
  };
  const password = typeof b.password === 'string' ? b.password : '';
  const errors = {};

  ['name', 'college', 'branch', 'year', 'email'].forEach((k) => {
    if (!d[k]) errors[k] = 'This field is required.';
  });
  if (!password) errors.password = 'This field is required.';
  else if (password.length < 6) errors.password = 'Password must be at least 6 characters.';
  if (d.email && !EMAIL_RE.test(d.email)) errors.email = 'Enter a valid email address.';
  if (d.email && db.users.some((u) => u.email === d.email)) {
    errors.email = 'An account with this email already exists.';
  }
  if (Object.keys(errors).length) return res.status(400).json({ errors });

  const user = {
    id: uid(),
    name: d.name,
    college: d.college,
    branch: d.branch,
    year: d.year,
    email: d.email,
    passwordHash: await bcrypt.hash(password, 10),
    at: Date.now(),
  };
  db.users.push(user);
  writeDB(db);
  res.status(201).json({ token: signToken(user), user: selfUser(user) });
});

app.post('/api/auth/login', async (req, res) => {
  const db = readDB();
  const email = str((req.body || {}).email).toLowerCase();
  const password = typeof (req.body || {}).password === 'string' ? req.body.password : '';
  const errors = {};
  if (!email) errors.email = 'This field is required.';
  else if (!EMAIL_RE.test(email)) errors.email = 'Enter a valid email address.';
  if (!password) errors.password = 'This field is required.';
  if (Object.keys(errors).length) return res.status(400).json({ errors });

  const user = db.users.find((u) => u.email === email);
  const ok = user && (await bcrypt.compare(password, user.passwordHash || ''));
  if (!ok) return res.status(401).json({ errors: { password: 'Invalid email or password.' } });

  res.json({ token: signToken(user), user: selfUser(user) });
});

app.get('/api/auth/me', auth, (req, res) => {
  res.json({ user: selfUser(req.user) });
});

/* ---------- users ---------- */

async function updateProfile(req, res) {
  const db = req.db;
  const b = req.body || {};
  const d = {
    name: str(b.name), college: str(b.college), branch: str(b.branch),
    year: str(b.year), email: str(b.email).toLowerCase(),
  };
  const password = typeof b.password === 'string' ? b.password : '';
  const errors = {};
  ['name', 'college', 'branch', 'email'].forEach((k) => {
    if (!d[k]) errors[k] = 'This field is required.';
  });
  if (d.email && !EMAIL_RE.test(d.email)) errors.email = 'Enter a valid email address.';
  if (d.email && db.users.some((u) => u.id !== req.user.id && u.email === d.email)) {
    errors.email = 'This email is already in use.';
  }
  if (password && password.length < 6) errors.password = 'Password must be at least 6 characters.';
  if (Object.keys(errors).length) return res.status(400).json({ errors });

  const rec = db.users.find((u) => u.id === req.user.id);
  rec.name = d.name;
  rec.college = d.college;
  rec.branch = d.branch;
  rec.year = d.year || rec.year;
  rec.email = d.email;
  if (password) rec.passwordHash = await bcrypt.hash(password, 10);
  writeDB(db);
  res.json({ user: selfUser(rec) });
}

app.put('/api/profile', auth, updateProfile);
app.put('/api/users/profile', auth, updateProfile);

app.get('/api/users/:id', (req, res) => {
  const db = readDB();
  const user = db.users.find((u) => u.id === req.params.id);
  if (!user) return res.status(404).json({ error: 'Student not found.' });
  const items = db.items.filter((i) => i.ownerId === user.id);
  const reviews = db.reviews.filter((r) => r.ownerId === user.id);
  const rating = reviews.length
    ? Math.round((reviews.reduce((s, r) => s + r.rating, 0) / reviews.length) * 10) / 10
    : null;
  res.json({ user: publicUser(user), stats: { items: items.length, reviews: reviews.length, rating } });
});

/* ---------- items ---------- */

function validateItem(b) {
  const errors = {};
  const d = {
    name: str(b.name), category: str(b.category), description: str(b.description),
    image: str(b.image), condition: str(b.condition), location: str(b.location),
  };
  ['name', 'category', 'description', 'condition', 'location'].forEach((k) => {
    if (!d[k]) errors[k] = 'This field is required.';
  });
  if (d.name && d.name.length > 80) errors.name = 'Keep the name under 80 characters.';
  if (d.description && d.description.length > 1200) errors.description = 'Keep the description under 1200 characters.';
  if (d.category && CATEGORIES.indexOf(d.category) < 0) errors.category = 'Select a valid category.';
  if (d.condition && CONDITIONS.indexOf(d.condition) < 0) errors.condition = 'Select a valid condition.';
  ['perHour', 'perDay', 'deposit'].forEach((k) => {
    const n = num(b[k]);
    if (isNaN(n) || n < 0) errors[k] = 'Enter a valid amount.';
    else if (n > 1000000) errors[k] = 'That amount looks too large.';
    else d[k] = n;
  });
  d.available = !(b.available === false || b.available === 0 || b.available === '0');
  // Digital fingerprinting support (optional, user supplied only).
  d.conditionImages = Array.isArray(b.conditionImages) ? b.conditionImages.filter((x) => typeof x === 'string').slice(0, 6) : [];
  d.conditionNotes = str(b.conditionNotes).slice(0, 600);
  return { d, errors };
}

app.get('/api/items', (req, res) => {
  const db = readDB();
  const q = str(req.query.q).toLowerCase();
  const cat = str(req.query.category);
  const minPrice = num(req.query.minPrice);
  const maxPrice = num(req.query.maxPrice);
  const available = str(req.query.available);
  let list = db.items.slice();
  if (q) {
    list = list.filter((i) =>
      (i.name + ' ' + i.description + ' ' + i.category).toLowerCase().indexOf(q) > -1);
  }
  if (cat) list = list.filter((i) => i.category === cat);
  if (!isNaN(minPrice)) list = list.filter((i) => Number(i.perDay) >= minPrice);
  if (!isNaN(maxPrice)) list = list.filter((i) => Number(i.perDay) <= maxPrice);
  if (available === '1' || available === 'true') list = list.filter((i) => !!i.available);
  if (available === '0' || available === 'false') list = list.filter((i) => !i.available);
  res.json({ items: list.sort((a, b) => b.at - a.at) });
});

app.get('/api/items/:id', (req, res) => {
  const db = readDB();
  const item = db.items.find((i) => i.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Item not found.' });
  const reviews = db.reviews.filter((r) => r.itemId === item.id);
  res.json({
    item,
    owner: publicUser(db.users.find((u) => u.id === item.ownerId)),
    reviews,
  });
});

app.post('/api/items', auth, (req, res) => {
  const { d, errors } = validateItem(req.body || {});
  if (Object.keys(errors).length) return res.status(400).json({ errors });
  const id = uid();
  const item = Object.assign({
    id,
    ownerId: req.user.id,
    at: Date.now(),
    fingerprint: itemFingerprint(id),
    damageRecords: [],
  }, d);
  req.db.items.push(item);
  writeDB(req.db);
  res.status(201).json({ item });
});

app.put('/api/items/:id', auth, (req, res) => {
  const item = req.db.items.find((i) => i.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Item not found.' });
  if (item.ownerId !== req.user.id) return res.status(403).json({ error: 'You can only edit your own items.' });
  const { d, errors } = validateItem(req.body || {});
  if (Object.keys(errors).length) return res.status(400).json({ errors });
  Object.assign(item, d);
  if (!item.fingerprint) item.fingerprint = itemFingerprint(item.id);
  if (!Array.isArray(item.damageRecords)) item.damageRecords = [];
  writeDB(req.db);
  res.json({ item });
});

app.delete('/api/items/:id', auth, (req, res) => {
  const item = req.db.items.find((i) => i.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Item not found.' });
  if (item.ownerId !== req.user.id) return res.status(403).json({ error: 'You can only delete your own items.' });
  const open = req.db.rentals.some((r) => r.itemId === item.id && OPEN_STATUSES.indexOf(r.status) > -1);
  if (open) return res.status(400).json({ error: 'This item has an open rental. Complete or cancel it first.' });
  req.db.items = req.db.items.filter((i) => i.id !== item.id);
  writeDB(req.db);
  res.json({ ok: true });
});

/* ---------- rentals ---------- */

app.post('/api/rentals', auth, (req, res) => {
  const db = req.db;
  const b = req.body || {};
  const item = db.items.find((i) => i.id === str(b.itemId));
  if (!item) return res.status(404).json({ error: 'Item not found.' });
  if (item.ownerId === req.user.id) {
    return res.status(403).json({ error: 'You cannot rent an item you listed.' });
  }
  if (!item.available) return res.status(400).json({ error: 'This item is currently unavailable.' });

  const mode = b.mode === 'hour' ? 'hour' : 'day';
  const errors = {};
  if (!str(b.start)) errors.start = 'Select a start time.';
  if (!str(b.end)) errors.end = 'Select an end time.';
  const calc = calcRental(item, mode, str(b.start), str(b.end));
  if (!errors.start && !errors.end && !calc) errors.form = 'End time must be after the start time.';
  if (Object.keys(errors).length) return res.status(400).json({ errors });

  const duplicate = db.rentals.find((r) =>
    r.itemId === item.id && r.renterId === req.user.id && OPEN_STATUSES.indexOf(r.status) > -1);
  if (duplicate) {
    return res.status(409).json({
      error: 'You already have an open request for this item (' + duplicate.status + ').',
    });
  }
  const conflict = db.rentals.find((r) =>
    r.itemId === item.id &&
    ['Accepted', 'Active'].indexOf(r.status) > -1 &&
    overlaps(str(b.start), str(b.end), r.start, r.end));
  if (conflict) {
    return res.status(409).json({ error: 'This item is already booked for part of that time window.' });
  }

  const rental = {
    id: uid(), itemId: item.id, ownerId: item.ownerId, renterId: req.user.id,
    mode: calc.mode, units: calc.units, start: str(b.start), end: str(b.end),
    cost: calc.cost, deposit: calc.deposit, total: calc.total,
    status: 'Requested', at: Date.now(), reviewed: false,
    // Secure rental handover architecture (no state is ever pre-filled).
    fingerprint: item.fingerprint || itemFingerprint(item.id),
    handoverStatus: 'Pending', returnStatus: 'Pending',
    conditionAtHandover: '', conditionAtReturn: '',
    handoverImages: [], returnImages: [], damageRecords: [],
    history: [{ status: 'Requested', at: Date.now(), by: req.user.id }],
  };
  db.rentals.push(rental);
  notify(db, item.ownerId, req.user.name + ' requested to rent your "' + item.name + '".',
    'rental_requested', '#/dashboard');
  writeDB(db);
  res.status(201).json({ rental });
});

function myRentals(db, userId) {
  return {
    outgoing: db.rentals.filter((r) => r.renterId === userId).sort((a, b) => b.at - a.at),
    incoming: db.rentals.filter((r) => r.ownerId === userId).sort((a, b) => b.at - a.at),
  };
}

app.get('/api/rentals', auth, (req, res) => res.json(myRentals(req.db, req.user.id)));

app.get('/api/rentals/my', auth, (req, res) => {
  const m = myRentals(req.db, req.user.id);
  res.json({ rentals: m.outgoing, outgoing: m.outgoing, incoming: m.incoming });
});

app.get('/api/rentals/requests', auth, (req, res) => {
  res.json({ rentals: myRentals(req.db, req.user.id).incoming });
});

app.get('/api/rentals/incoming', auth, (req, res) => {
  res.json({ rentals: myRentals(req.db, req.user.id).incoming });
});

app.get('/api/rentals/outgoing', auth, (req, res) => {
  res.json({ rentals: myRentals(req.db, req.user.id).outgoing });
});

const OWNER_TRANSITIONS = {
  Requested: ['Accepted', 'Rejected'],
  Accepted: ['Active', 'Cancelled'],
  Active: ['Returned'],
  Returned: ['Completed'],
};
const RENTER_TRANSITIONS = { Requested: ['Cancelled'], Accepted: ['Cancelled'] };

function applyStatus(req, res, status) {
  const db = req.db;
  const rental = db.rentals.find((r) => r.id === req.params.id);
  if (!rental) return res.status(404).json({ error: 'Rental not found.' });
  if (STATUSES.indexOf(status) < 0) return res.status(400).json({ error: 'Unknown rental status.' });

  const isOwner = rental.ownerId === req.user.id;
  const isRenter = rental.renterId === req.user.id;
  if (!isOwner && !isRenter) return res.status(403).json({ error: 'You are not part of this rental.' });

  const allowed = (isOwner ? OWNER_TRANSITIONS[rental.status] : RENTER_TRANSITIONS[rental.status]) || [];
  if (allowed.indexOf(status) < 0) {
    return res.status(400).json({ error: 'Cannot change status from ' + rental.status + ' to ' + status + '.' });
  }

  rental.status = status;
  if (!Array.isArray(rental.history)) rental.history = [];
  rental.history.push({ status, at: Date.now(), by: req.user.id });
  if (status === 'Active') rental.handoverStatus = 'Handed over';
  if (status === 'Returned') rental.returnStatus = 'Returned';
  if (status === 'Completed') rental.returnStatus = 'Verified by owner';
  if (status === 'Rejected' || status === 'Cancelled') {
    rental.handoverStatus = 'Not required';
    rental.returnStatus = 'Not required';
  }

  const item = db.items.find((i) => i.id === rental.itemId);
  const itemName = item ? item.name : 'an item';
  const types = {
    Accepted: 'rental_accepted', Rejected: 'rental_rejected', Active: 'rental_active',
    Returned: 'rental_returned', Completed: 'rental_completed', Cancelled: 'rental_cancelled',
  };
  notify(db, isOwner ? rental.renterId : rental.ownerId,
    'Rental for "' + itemName + '" is now ' + status + '.', types[status] || 'rental',
    isOwner ? '#/rentals' : '#/dashboard');
  writeDB(db);
  res.json({ rental });
}

app.post('/api/rentals/:id/accept', auth, (req, res) => applyStatus(req, res, 'Accepted'));
app.post('/api/rentals/:id/reject', auth, (req, res) => applyStatus(req, res, 'Rejected'));
app.put('/api/rentals/:id/accept', auth, (req, res) => applyStatus(req, res, 'Accepted'));
app.put('/api/rentals/:id/reject', auth, (req, res) => applyStatus(req, res, 'Rejected'));
app.put('/api/rentals/:id/status', auth, (req, res) => applyStatus(req, res, str((req.body || {}).status)));
app.patch('/api/rentals/:id/status', auth, (req, res) => applyStatus(req, res, str((req.body || {}).status)));

/* ---------- conversations & messages ---------- */

app.post('/api/conversations', auth, (req, res) => {
  const db = req.db;
  const otherId = str((req.body || {}).otherId);
  const itemId = str((req.body || {}).itemId);
  if (otherId === req.user.id) return res.status(400).json({ error: 'You cannot message yourself.' });
  const other = db.users.find((u) => u.id === otherId);
  if (!other) return res.status(404).json({ error: 'Student not found.' });
  if (itemId && !db.items.find((i) => i.id === itemId)) {
    return res.status(404).json({ error: 'Item not found.' });
  }

  const key = convoKey(req.user.id, otherId, itemId);
  let convo = db.conversations.find((c) => c.key === key);
  if (!convo) {
    convo = { id: uid(), key, members: [req.user.id, otherId], itemId: itemId || '', at: Date.now() };
    db.conversations.push(convo);
    writeDB(db);
  }
  res.json({ conversation: convo });
});

app.get('/api/conversations', auth, (req, res) => {
  const db = req.db;
  const mine = db.conversations.filter((c) => c.members.indexOf(req.user.id) > -1);
  res.json({
    conversations: mine
      .map((c) => {
        const msgs = db.messages.filter((m) => m.convoId === c.id);
        const last = msgs.sort((a, b) => b.at - a.at)[0] || null;
        return Object.assign({}, c, {
          lastMessage: last,
          unread: msgs.filter((m) => m.to === req.user.id && !m.read).length,
        });
      })
      .sort((a, b) => (b.lastMessage ? b.lastMessage.at : b.at) - (a.lastMessage ? a.lastMessage.at : a.at)),
  });
});

function conversationMessages(req, res, convoId) {
  const db = req.db;
  const convo = db.conversations.find((c) => c.id === convoId);
  if (!convo) return res.status(404).json({ error: 'Conversation not found.' });
  if (convo.members.indexOf(req.user.id) < 0) {
    return res.status(403).json({ error: 'You do not have access to this conversation.' });
  }
  let changed = false;
  db.messages.forEach((m) => {
    if (m.convoId === convo.id && m.to === req.user.id && !m.read) { m.read = true; changed = true; }
  });
  if (changed) writeDB(db);
  res.json({
    conversation: convo,
    messages: db.messages.filter((m) => m.convoId === convo.id).sort((a, b) => a.at - b.at),
  });
}

app.get('/api/conversations/:id/messages', auth, (req, res) => conversationMessages(req, res, req.params.id));
app.get('/api/messages/:conversationId', auth, (req, res) => conversationMessages(req, res, req.params.conversationId));

app.post('/api/messages', auth, (req, res) => {
  const db = req.db;
  const b = req.body || {};
  const text = str(b.text);
  if (!text) return res.status(400).json({ errors: { text: 'Message cannot be empty.' } });
  if (text.length > 2000) return res.status(400).json({ errors: { text: 'Message is too long.' } });

  const convoId = str(b.convoId || b.conversationId);
  const convo = db.conversations.find((c) => c.id === convoId);
  if (!convo) return res.status(404).json({ error: 'Conversation not found.' });
  if (convo.members.indexOf(req.user.id) < 0) {
    return res.status(403).json({ error: 'You do not have access to this conversation.' });
  }
  const to = convo.members.filter((m) => m !== req.user.id)[0];
  const message = {
    id: uid(), convoId: convo.id, from: req.user.id, to,
    text: text, at: Date.now(), read: false,
  };
  db.messages.push(message);
  notify(db, to, 'New message from ' + req.user.name + '.', 'message', '#/messages');
  writeDB(db);
  res.status(201).json({ message });
});

app.post('/api/messages/read', auth, (req, res) => {
  const db = req.db;
  const convoId = str((req.body || {}).convoId);
  let changed = false;
  db.messages.forEach((m) => {
    if (m.to === req.user.id && !m.read && (!convoId || m.convoId === convoId)) { m.read = true; changed = true; }
  });
  if (changed) writeDB(db);
  res.json({ ok: true });
});

/* ---------- reviews ---------- */

function listReviews(db, itemId, ownerId) {
  let list = db.reviews.slice();
  if (itemId) list = list.filter((r) => r.itemId === itemId);
  if (ownerId) list = list.filter((r) => r.ownerId === ownerId);
  return list.sort((a, b) => b.at - a.at);
}

app.get('/api/reviews', (req, res) => {
  const db = readDB();
  res.json({ reviews: listReviews(db, str(req.query.itemId), str(req.query.ownerId)) });
});

app.get('/api/reviews/:itemId', (req, res) => {
  const db = readDB();
  const list = listReviews(db, req.params.itemId, '');
  const rating = list.length
    ? Math.round((list.reduce((s, r) => s + r.rating, 0) / list.length) * 10) / 10
    : null;
  res.json({
    reviews: list.map((r) => Object.assign({}, r, {
      reviewer: publicUser(db.users.find((u) => u.id === r.userId)),
    })),
    rating,
    count: list.length,
  });
});

app.post('/api/reviews', auth, (req, res) => {
  const db = req.db;
  const b = req.body || {};
  const rental = db.rentals.find((r) => r.id === str(b.rentalId));
  const errors = {};
  const rating = num(b.rating);
  const text = str(b.text);

  if (!rental) return res.status(404).json({ error: 'Rental not found.' });
  if (rental.renterId !== req.user.id) {
    return res.status(403).json({ error: 'Only the renter can review this rental.' });
  }
  if (rental.status !== 'Completed') {
    return res.status(400).json({ error: 'You can review only after the rental is completed.' });
  }
  if (rental.reviewed) return res.status(400).json({ error: 'This rental already has a review.' });
  if (!(rating >= 1 && rating <= 5)) errors.rating = 'Select a star rating.';
  if (!text) errors.text = 'Please write a short review.';
  else if (text.length > 1000) errors.text = 'Keep the review under 1000 characters.';
  if (Object.keys(errors).length) return res.status(400).json({ errors });

  const review = {
    id: uid(), rentalId: rental.id, itemId: rental.itemId, userId: req.user.id,
    ownerId: rental.ownerId, rating: Math.round(rating), text, at: Date.now(),
  };
  db.reviews.push(review);
  rental.reviewed = true;
  notify(db, rental.ownerId, req.user.name + ' left a ' + review.rating + '-star review.',
    'review', '#/profile');
  writeDB(db);
  res.status(201).json({ review });
});

/* ---------- notifications ---------- */

app.get('/api/notifications', auth, (req, res) => {
  res.json({
    notifications: req.db.notifications.filter((n) => n.userId === req.user.id),
    unread: req.db.notifications.filter((n) => n.userId === req.user.id && !n.read).length,
  });
});

app.put('/api/notifications/:id/read', auth, (req, res) => {
  const db = req.db;
  const n = db.notifications.find((x) => x.id === req.params.id);
  if (!n) return res.status(404).json({ error: 'Notification not found.' });
  if (n.userId !== req.user.id) return res.status(403).json({ error: 'Not your notification.' });
  if (!n.read) { n.read = true; writeDB(db); }
  res.json({ notification: n });
});

app.post('/api/notifications/read', auth, (req, res) => {
  const db = req.db;
  let changed = false;
  db.notifications.forEach((n) => {
    if (n.userId === req.user.id && !n.read) { n.read = true; changed = true; }
  });
  if (changed) writeDB(db);
  res.json({ ok: true });
});

/* ---------- aggregate snapshot used by the frontend ---------- */

app.get('/api/state', (req, res) => {
  const db = readDB();
  const user = currentUser(db, req);
  const base = {
    users: db.users.map(publicUser),
    items: db.items.slice().sort((a, b) => b.at - a.at),
    reviews: db.reviews.slice(),
    categories: CATEGORIES,
    stats: { students: db.users.length, items: db.items.length, rentals: db.rentals.length },
  };
  if (!user) {
    return res.json(Object.assign(base, {
      me: null, rentals: [], convos: [], msgs: [], notifs: [],
    }));
  }
  const convos = db.conversations.filter((c) => c.members.indexOf(user.id) > -1);
  const convoIds = convos.map((c) => c.id);
  res.json(Object.assign(base, {
    me: selfUser(user),
    rentals: db.rentals.filter((r) => r.ownerId === user.id || r.renterId === user.id),
    convos: convos.sort((a, b) => b.at - a.at),
    msgs: db.messages.filter((m) => convoIds.indexOf(m.convoId) > -1).sort((a, b) => a.at - b.at),
    notifs: db.notifications.filter((n) => n.userId === user.id),
  }));
});

app.use('/api', (req, res) => res.status(404).json({ error: 'Unknown endpoint.' }));

/* central error handler – never leak stack traces to clients */
app.use('/api', (err, req, res, next) => {
  console.error('[RentShare]', err && err.message ? err.message : err);
  if (res.headersSent) return next(err);
  res.status(500).json({ error: 'Something went wrong on the server. Please try again.' });
});

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => {
  console.log('RentShare backend running on http://localhost:' + PORT);
});
