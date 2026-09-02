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
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2));
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

function publicUser(u) {
  if (!u) return null;
  return { id: u.id, name: u.name, college: u.college, branch: u.branch, year: u.year };
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

function notify(db, userId, text) {
  if (!userId) return;
  db.notifications.unshift({ id: uid(), userId, text, at: Date.now(), read: false });
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
  if (!user) return res.status(401).json({ error: 'Authentication required.' });
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

/* ---------------- app ---------------- */

const app = express();
app.use(cors({ origin: true }));
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
  res.json({ token: signToken(user), user: selfUser(user) });
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

app.put('/api/profile', auth, async (req, res) => {
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
  if (d.category && CATEGORIES.indexOf(d.category) < 0) errors.category = 'Select a valid category.';
  if (d.condition && CONDITIONS.indexOf(d.condition) < 0) errors.condition = 'Select a valid condition.';
  ['perHour', 'perDay', 'deposit'].forEach((k) => {
    const n = num(b[k]);
    if (isNaN(n) || n < 0) errors[k] = 'Enter a valid amount.';
    else d[k] = n;
  });
  d.available = !(b.available === false || b.available === 0 || b.available === '0');
  return { d, errors };
}

app.get('/api/items', (req, res) => {
  const db = readDB();
  const q = str(req.query.q).toLowerCase();
  const cat = str(req.query.category);
  let list = db.items.slice();
  if (q) {
    list = list.filter((i) =>
      (i.name + ' ' + i.description + ' ' + i.category).toLowerCase().indexOf(q) > -1);
  }
  if (cat) list = list.filter((i) => i.category === cat);
  res.json({ items: list.sort((a, b) => b.at - a.at) });
});

app.get('/api/items/:id', (req, res) => {
  const db = readDB();
  const item = db.items.find((i) => i.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Item not found.' });
  res.json({ item, owner: publicUser(db.users.find((u) => u.id === item.ownerId)) });
});

app.post('/api/items', auth, (req, res) => {
  const { d, errors } = validateItem(req.body || {});
  if (Object.keys(errors).length) return res.status(400).json({ errors });
  const item = Object.assign({ id: uid(), ownerId: req.user.id, at: Date.now() }, d);
  req.db.items.push(item);
  writeDB(req.db);
  res.json({ item });
});

app.put('/api/items/:id', auth, (req, res) => {
  const item = req.db.items.find((i) => i.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Item not found.' });
  if (item.ownerId !== req.user.id) return res.status(403).json({ error: 'You can only edit your own items.' });
  const { d, errors } = validateItem(req.body || {});
  if (Object.keys(errors).length) return res.status(400).json({ errors });
  Object.assign(item, d);
  writeDB(req.db);
  res.json({ item });
});

app.delete('/api/items/:id', auth, (req, res) => {
  const item = req.db.items.find((i) => i.id === req.params.id);
  if (!item) return res.status(404).json({ error: 'Item not found.' });
  if (item.ownerId !== req.user.id) return res.status(403).json({ error: 'You can only delete your own items.' });
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

  const rental = {
    id: uid(), itemId: item.id, ownerId: item.ownerId, renterId: req.user.id,
    mode: calc.mode, units: calc.units, start: str(b.start), end: str(b.end),
    cost: calc.cost, deposit: calc.deposit, total: calc.total,
    status: 'Requested', at: Date.now(), reviewed: false,
  };
  db.rentals.push(rental);
  notify(db, item.ownerId, req.user.name + ' requested to rent your "' + item.name + '".');
  writeDB(db);
  res.json({ rental });
});

app.get('/api/rentals', auth, (req, res) => {
  const db = req.db;
  res.json({
    outgoing: db.rentals.filter((r) => r.renterId === req.user.id).sort((a, b) => b.at - a.at),
    incoming: db.rentals.filter((r) => r.ownerId === req.user.id).sort((a, b) => b.at - a.at),
  });
});

app.get('/api/rentals/incoming', auth, (req, res) => {
  res.json({ rentals: req.db.rentals.filter((r) => r.ownerId === req.user.id).sort((a, b) => b.at - a.at) });
});

app.get('/api/rentals/outgoing', auth, (req, res) => {
  res.json({ rentals: req.db.rentals.filter((r) => r.renterId === req.user.id).sort((a, b) => b.at - a.at) });
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
  if (STATUSES.indexOf(status) < 0) return res.status(400).json({ error: 'Unknown status.' });

  const isOwner = rental.ownerId === req.user.id;
  const isRenter = rental.renterId === req.user.id;
  if (!isOwner && !isRenter) return res.status(403).json({ error: 'Not your rental.' });

  const allowed = (isOwner ? OWNER_TRANSITIONS[rental.status] : RENTER_TRANSITIONS[rental.status]) || [];
  if (allowed.indexOf(status) < 0) {
    return res.status(400).json({ error: 'Cannot change status from ' + rental.status + ' to ' + status + '.' });
  }

  rental.status = status;
  const item = db.items.find((i) => i.id === rental.itemId);
  notify(db, isOwner ? rental.renterId : rental.ownerId,
    'Rental for "' + (item ? item.name : 'an item') + '" is now ' + status + '.');
  writeDB(db);
  res.json({ rental });
}

app.post('/api/rentals/:id/accept', auth, (req, res) => applyStatus(req, res, 'Accepted'));
app.post('/api/rentals/:id/reject', auth, (req, res) => applyStatus(req, res, 'Rejected'));
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
  res.json({
    conversations: db.conversations
      .filter((c) => c.members.indexOf(req.user.id) > -1)
      .sort((a, b) => b.at - a.at),
  });
});

app.get('/api/conversations/:id/messages', auth, (req, res) => {
  const db = req.db;
  const convo = db.conversations.find((c) => c.id === req.params.id);
  if (!convo || convo.members.indexOf(req.user.id) < 0) {
    return res.status(404).json({ error: 'Conversation not found.' });
  }
  res.json({
    messages: db.messages.filter((m) => m.convoId === convo.id).sort((a, b) => a.at - b.at),
  });
});

app.post('/api/messages', auth, (req, res) => {
  const db = req.db;
  const b = req.body || {};
  const text = str(b.text);
  if (!text) return res.status(400).json({ error: 'Message cannot be empty.' });

  const convo = db.conversations.find((c) => c.id === str(b.convoId));
  if (!convo || convo.members.indexOf(req.user.id) < 0) {
    return res.status(404).json({ error: 'Conversation not found.' });
  }
  const to = convo.members.filter((m) => m !== req.user.id)[0];
  const message = {
    id: uid(), convoId: convo.id, from: req.user.id, to,
    text: text.slice(0, 2000), at: Date.now(),
  };
  db.messages.push(message);
  notify(db, to, 'New message from ' + req.user.name + '.');
  writeDB(db);
  res.json({ message });
});

/* ---------- reviews ---------- */

app.get('/api/reviews', (req, res) => {
  const db = readDB();
  const itemId = str(req.query.itemId);
  const ownerId = str(req.query.ownerId);
  let list = db.reviews.slice();
  if (itemId) list = list.filter((r) => r.itemId === itemId);
  if (ownerId) list = list.filter((r) => r.ownerId === ownerId);
  res.json({ reviews: list.sort((a, b) => b.at - a.at) });
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
  if (Object.keys(errors).length) return res.status(400).json({ errors });

  const review = {
    id: uid(), rentalId: rental.id, itemId: rental.itemId, userId: req.user.id,
    ownerId: rental.ownerId, rating: Math.round(rating), text, at: Date.now(),
  };
  db.reviews.push(review);
  rental.reviewed = true;
  notify(db, rental.ownerId, req.user.name + ' left a ' + review.rating + '-star review.');
  writeDB(db);
  res.json({ review });
});

/* ---------- notifications ---------- */

app.get('/api/notifications', auth, (req, res) => {
  res.json({ notifications: req.db.notifications.filter((n) => n.userId === req.user.id) });
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

app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

app.listen(PORT, () => {
  console.log('RentShare backend running on http://localhost:' + PORT);
});
