const express = require('express');
const cors = require('cors');
const path = require('path');
const fs = require('fs');
const admin = require('firebase-admin');

const app = express();
const PORT = process.env.PORT || 4000;
const PROJECT_ID = process.env.FIREBASE_PROJECT_ID || 'rentshare-28a55';

/* ---------- Initialize Firebase Admin SDK ---------- */
let adminInitialized = false;

try {
  let credential = null;

  if (process.env.FIREBASE_SERVICE_ACCOUNT) {
    try {
      const raw = process.env.FIREBASE_SERVICE_ACCOUNT.trim();
      const jsonStr = raw.startsWith('{') ? raw : Buffer.from(raw, 'base64').toString('utf8');
      credential = admin.credential.cert(JSON.parse(jsonStr));
      console.log('Firebase Admin initialized from FIREBASE_SERVICE_ACCOUNT env variable.');
    } catch (e) {
      console.warn('Failed to parse FIREBASE_SERVICE_ACCOUNT env var:', e.message);
    }
  } else if (process.env.FIREBASE_SERVICE_ACCOUNT_PATH && fs.existsSync(process.env.FIREBASE_SERVICE_ACCOUNT_PATH)) {
    credential = admin.credential.cert(require(path.resolve(process.env.FIREBASE_SERVICE_ACCOUNT_PATH)));
    console.log(`Firebase Admin initialized from file: ${process.env.FIREBASE_SERVICE_ACCOUNT_PATH}`);
  } else if (process.env.GOOGLE_APPLICATION_CREDENTIALS && fs.existsSync(process.env.GOOGLE_APPLICATION_CREDENTIALS)) {
    credential = admin.credential.applicationDefault();
    console.log(`Firebase Admin initialized via GOOGLE_APPLICATION_CREDENTIALS: ${process.env.GOOGLE_APPLICATION_CREDENTIALS}`);
  }

  if (credential) {
    admin.initializeApp({
      credential,
      projectId: PROJECT_ID
    });
  } else {
    admin.initializeApp({
      projectId: PROJECT_ID
    });
    console.log(`Firebase Admin initialized with projectId: ${PROJECT_ID} (default/ADC configuration).`);
  }

  adminInitialized = true;
} catch (err) {
  console.error('Firebase Admin initialization warning:', err.message);
}

const db = admin.firestore();
const auth = admin.auth();

/* ---------- Middleware ---------- */
app.use(cors());
app.use(express.json());
app.use(express.static(__dirname));

/* ---------- Authentication Middleware ---------- */
async function verifyFirebaseAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized: Missing or invalid Authorization header.' });
  }

  const idToken = authHeader.split('Bearer ')[1].trim();
  if (!idToken) {
    return res.status(401).json({ error: 'Unauthorized: Empty token provided.' });
  }

  try {
    const decodedToken = await auth.verifyIdToken(idToken);
    req.user = decodedToken;
    next();
  } catch (err) {
    console.error('Error verifying Firebase ID token:', err.message);
    return res.status(401).json({ error: 'Unauthorized: Invalid or expired Firebase ID token.' });
  }
}

/* ---------- Authoritative Rental Helpers ---------- */
function calcRental(listing, mode, startStr, endStr) {
  const start = new Date(startStr);
  const end = new Date(endStr);
  if (isNaN(start.getTime()) || isNaN(end.getTime()) || start >= end) {
    return null;
  }

  const diffMs = end.getTime() - start.getTime();
  let units = 0;
  let cost = 0;

  if (mode === 'hour') {
    units = Math.max(1, Math.ceil(diffMs / (1000 * 60 * 60)));
    cost = units * (Number(listing.perHour) || 0);
  } else {
    units = Math.max(1, Math.ceil(diffMs / (1000 * 60 * 60 * 24)));
    cost = units * (Number(listing.perDay) || 0);
  }

  const deposit = Number(listing.deposit) || 0;
  return {
    mode: mode === 'hour' ? 'hour' : 'day',
    units,
    cost,
    deposit,
    total: cost + deposit
  };
}

/* ---------- API Routes ---------- */

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'ok',
    app: 'RentShare Backend',
    projectId: PROJECT_ID,
    adminInitialized,
    timestamp: new Date().toISOString()
  });
});

/**
 * POST /api/rentals/request
 * Securely validate and create a rental request.
 */
app.post('/api/rentals/request', verifyFirebaseAuth, async (req, res) => {
  try {
    const renterId = req.user.uid;
    const { itemId, mode, start, end } = req.body;

    if (!itemId) {
      return res.status(400).json({ error: 'Item ID is required.' });
    }
    if (!start || !end) {
      return res.status(400).json({ error: 'Start time and end time are required.' });
    }

    const startDate = new Date(start);
    const endDate = new Date(end);
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      return res.status(400).json({ error: 'Invalid start or end date format.' });
    }
    if (startDate >= endDate) {
      return res.status(400).json({ error: 'End time must be strictly after the start time.' });
    }

    // 1. Fetch authoritative listing from Firestore
    const itemDoc = await db.collection('listings').doc(itemId).get();
    if (!itemDoc.exists) {
      return res.status(404).json({ error: 'Listing not found.' });
    }
    const listing = itemDoc.data();

    // 2. Prevent owners from renting their own items
    if (listing.ownerId === renterId) {
      return res.status(400).json({ error: 'Owners cannot rent their own items.' });
    }

    // 3. Authoritative calculation of rental duration, cost, and deposit
    const rentalCalc = calcRental(listing, mode, start, end);
    if (!rentalCalc) {
      return res.status(400).json({ error: 'Invalid rental parameters or duration.' });
    }

    // 4. Query Firestore for conflicting bookings for this item
    const existingRentalsSnapshot = await db.collection('rentals').where('itemId', '==', itemId).get();
    const existingRentals = [];
    existingRentalsSnapshot.forEach(doc => {
      existingRentals.push(Object.assign({ id: doc.id }, doc.data()));
    });

    // Check duplicate requests by the same user for overlapping period
    const duplicateRequest = existingRentals.find(ex => {
      if (ex.renterId !== renterId) return false;
      if (ex.status !== 'Requested' && ex.status !== 'Accepted' && ex.status !== 'Active') return false;
      const exStart = new Date(ex.start);
      const exEnd = new Date(ex.end);
      return (startDate < exEnd && endDate > exStart);
    });
    if (duplicateRequest) {
      return res.status(409).json({
        error: `You already have an existing rental request for this item during this period (${duplicateRequest.status}).`
      });
    }

    // Check if item is already booked (Accepted / Active) by any user during this period
    const bookedConflict = existingRentals.find(ex => {
      if (ex.status !== 'Accepted' && ex.status !== 'Active') return false;
      const exStart = new Date(ex.start);
      const exEnd = new Date(ex.end);
      return (startDate < exEnd && endDate > exStart);
    });
    if (bookedConflict) {
      return res.status(409).json({
        error: `This item is already booked from ${new Date(bookedConflict.start).toLocaleString()} to ${new Date(bookedConflict.end).toLocaleString()}. Please select a different time slot.`
      });
    }

    // 5. Store rental document authoritatively in Firestore
    const rentalData = {
      itemId,
      ownerId: listing.ownerId,
      renterId,
      mode: rentalCalc.mode,
      units: rentalCalc.units,
      start: startDate.toISOString(),
      end: endDate.toISOString(),
      cost: rentalCalc.cost,
      deposit: rentalCalc.deposit,
      total: rentalCalc.total,
      status: 'Requested',
      reviewed: false,
      at: Date.now(),
      createdAt: Date.now()
    };

    const docRef = await db.collection('rentals').add(rentalData);

    // 6. Notify the item owner in Firestore
    try {
      const renterUserDoc = await db.collection('users').doc(renterId).get();
      const renterName = (renterUserDoc.exists && renterUserDoc.data().name) ? renterUserDoc.data().name : 'A student';

      await db.collection('notifications').add({
        userId: listing.ownerId,
        text: `${renterName} requested to rent your "${listing.name}".`,
        type: 'rental_request',
        link: '#/dashboard',
        at: Date.now(),
        createdAt: Date.now()
      });
    } catch (notifErr) {
      console.warn('Notification creation warning:', notifErr.message);
    }

    return res.status(201).json({
      success: true,
      id: docRef.id,
      rental: Object.assign({ id: docRef.id }, rentalData)
    });
  } catch (err) {
    console.error('Server error in /api/rentals/request:', err);
    return res.status(500).json({ error: 'Server error processing rental request: ' + err.message });
  }
});

/**
 * POST /api/rentals/accept
 * Owner accepts a rental request after re-verifying conflicts.
 */
app.post('/api/rentals/accept', verifyFirebaseAuth, async (req, res) => {
  try {
    const ownerId = req.user.uid;
    const { rentalId } = req.body;

    if (!rentalId) {
      return res.status(400).json({ error: 'Rental ID is required.' });
    }

    const rentalRef = db.collection('rentals').doc(rentalId);
    const rentalDoc = await rentalRef.get();
    if (!rentalDoc.exists) {
      return res.status(404).json({ error: 'Rental request not found.' });
    }

    const rental = rentalDoc.data();
    if (rental.ownerId !== ownerId) {
      return res.status(403).json({ error: 'Only the item owner can accept this rental request.' });
    }
    if (rental.status !== 'Requested') {
      return res.status(400).json({ error: `Cannot accept rental with status "${rental.status}".` });
    }

    const rStart = new Date(rental.start);
    const rEnd = new Date(rental.end);

    // Re-check Firestore to prevent race conditions
    const snapshot = await db.collection('rentals').where('itemId', '==', rental.itemId).get();
    const allRentals = [];
    snapshot.forEach(doc => allRentals.push(Object.assign({ id: doc.id }, doc.data())));

    const conflict = allRentals.find(ex => {
      if (ex.id === rentalId) return false;
      if (ex.status !== 'Accepted' && ex.status !== 'Active') return false;
      const exStart = new Date(ex.start);
      const exEnd = new Date(ex.end);
      return (rStart < exEnd && rEnd > exStart);
    });

    if (conflict) {
      return res.status(409).json({
        error: `Cannot accept: Another rental is already booked from ${new Date(conflict.start).toLocaleString()} to ${new Date(conflict.end).toLocaleString()}.`
      });
    }

    // Accept this rental
    await rentalRef.update({
      status: 'Accepted',
      updatedAt: Date.now()
    });

    // Auto-reject any conflicting pending 'Requested' rentals for this item
    const conflictingPending = allRentals.filter(ex => {
      if (ex.id === rentalId || ex.status !== 'Requested') return false;
      const exStart = new Date(ex.start);
      const exEnd = new Date(ex.end);
      return (rStart < exEnd && rEnd > exStart);
    });

    for (const cp of conflictingPending) {
      db.collection('rentals').doc(cp.id).update({
        status: 'Rejected',
        updatedAt: Date.now()
      }).catch(e => console.warn('Auto-reject update error:', e.message));

      db.collection('notifications').add({
        userId: cp.renterId,
        text: 'Your rental request was declined because the time slot was booked by another student.',
        type: 'status_rejected',
        link: '#/rentals',
        at: Date.now(),
        createdAt: Date.now()
      }).catch(e => console.warn('Notification error:', e.message));
    }

    // Notify renter
    const itemDoc = await db.collection('listings').doc(rental.itemId).get();
    const itemName = itemDoc.exists ? itemDoc.data().name : 'item';
    await db.collection('notifications').add({
      userId: rental.renterId,
      text: `Your rental request for "${itemName}" was accepted!`,
      type: 'status_accepted',
      link: '#/rentals',
      at: Date.now(),
      createdAt: Date.now()
    });

    return res.json({ success: true, status: 'Accepted' });
  } catch (err) {
    console.error('Server error in /api/rentals/accept:', err);
    return res.status(500).json({ error: 'Server error accepting rental: ' + err.message });
  }
});

/**
 * POST /api/rentals/reject
 * Owner rejects a rental request.
 */
app.post('/api/rentals/reject', verifyFirebaseAuth, async (req, res) => {
  try {
    const ownerId = req.user.uid;
    const { rentalId } = req.body;

    if (!rentalId) {
      return res.status(400).json({ error: 'Rental ID is required.' });
    }

    const rentalRef = db.collection('rentals').doc(rentalId);
    const rentalDoc = await rentalRef.get();
    if (!rentalDoc.exists) {
      return res.status(404).json({ error: 'Rental request not found.' });
    }

    const rental = rentalDoc.data();
    if (rental.ownerId !== ownerId) {
      return res.status(403).json({ error: 'Only the item owner can reject this rental request.' });
    }

    await rentalRef.update({
      status: 'Rejected',
      updatedAt: Date.now()
    });

    const itemDoc = await db.collection('listings').doc(rental.itemId).get();
    const itemName = itemDoc.exists ? itemDoc.data().name : 'item';
    await db.collection('notifications').add({
      userId: rental.renterId,
      text: `Rental request for "${itemName}" was declined.`,
      type: 'status_rejected',
      link: '#/rentals',
      at: Date.now(),
      createdAt: Date.now()
    });

    return res.json({ success: true, status: 'Rejected' });
  } catch (err) {
    console.error('Server error in /api/rentals/reject:', err);
    return res.status(500).json({ error: 'Server error rejecting rental: ' + err.message });
  }
});

/**
 * POST /api/rentals/cancel
 * Renter cancels their pending rental request.
 */
app.post('/api/rentals/cancel', verifyFirebaseAuth, async (req, res) => {
  try {
    const renterId = req.user.uid;
    const { rentalId } = req.body;

    if (!rentalId) {
      return res.status(400).json({ error: 'Rental ID is required.' });
    }

    const rentalRef = db.collection('rentals').doc(rentalId);
    const rentalDoc = await rentalRef.get();
    if (!rentalDoc.exists) {
      return res.status(404).json({ error: 'Rental request not found.' });
    }

    const rental = rentalDoc.data();
    if (rental.renterId !== renterId) {
      return res.status(403).json({ error: 'Only the renter can cancel this rental request.' });
    }
    if (rental.status !== 'Requested') {
      return res.status(400).json({ error: 'Only pending requests can be cancelled.' });
    }

    await rentalRef.update({
      status: 'Cancelled',
      updatedAt: Date.now()
    });

    return res.json({ success: true, status: 'Cancelled' });
  } catch (err) {
    console.error('Server error in /api/rentals/cancel:', err);
    return res.status(500).json({ error: 'Server error cancelling rental: ' + err.message });
  }
});

/**
 * POST /api/rentals/active
 * Owner marks an accepted rental as active.
 */
app.post('/api/rentals/active', verifyFirebaseAuth, async (req, res) => {
  try {
    const ownerId = req.user.uid;
    const { rentalId } = req.body;

    if (!rentalId) {
      return res.status(400).json({ error: 'Rental ID is required.' });
    }

    const rentalRef = db.collection('rentals').doc(rentalId);
    const rentalDoc = await rentalRef.get();
    if (!rentalDoc.exists) {
      return res.status(404).json({ error: 'Rental request not found.' });
    }

    const rental = rentalDoc.data();
    if (rental.ownerId !== ownerId) {
      return res.status(403).json({ error: 'Only the item owner can mark this rental as active.' });
    }
    if (rental.status !== 'Accepted') {
      return res.status(400).json({ error: 'Rental must be Accepted before marking Active.' });
    }

    await rentalRef.update({
      status: 'Active',
      updatedAt: Date.now()
    });

    const itemDoc = await db.collection('listings').doc(rental.itemId).get();
    const itemName = itemDoc.exists ? itemDoc.data().name : 'item';
    await db.collection('notifications').add({
      userId: rental.renterId,
      text: `Rental for "${itemName}" is now Active.`,
      type: 'status_active',
      link: '#/rentals',
      at: Date.now(),
      createdAt: Date.now()
    });

    return res.json({ success: true, status: 'Active' });
  } catch (err) {
    console.error('Server error in /api/rentals/active:', err);
    return res.status(500).json({ error: 'Server error marking rental active: ' + err.message });
  }
});

/**
 * POST /api/rentals/return
 * Mark an active rental as returned.
 */
app.post('/api/rentals/return', verifyFirebaseAuth, async (req, res) => {
  try {
    const userId = req.user.uid;
    const { rentalId } = req.body;

    if (!rentalId) {
      return res.status(400).json({ error: 'Rental ID is required.' });
    }

    const rentalRef = db.collection('rentals').doc(rentalId);
    const rentalDoc = await rentalRef.get();
    if (!rentalDoc.exists) {
      return res.status(404).json({ error: 'Rental request not found.' });
    }

    const rental = rentalDoc.data();
    if (rental.ownerId !== userId && rental.renterId !== userId) {
      return res.status(403).json({ error: 'Unauthorized to update this rental.' });
    }
    if (rental.status !== 'Active') {
      return res.status(400).json({ error: 'Rental must be Active to mark Returned.' });
    }

    await rentalRef.update({
      status: 'Returned',
      updatedAt: Date.now()
    });

    const targetUser = (userId === rental.ownerId) ? rental.renterId : rental.ownerId;
    const itemDoc = await db.collection('listings').doc(rental.itemId).get();
    const itemName = itemDoc.exists ? itemDoc.data().name : 'item';
    await db.collection('notifications').add({
      userId: targetUser,
      text: `Rental for "${itemName}" was marked Returned.`,
      type: 'status_returned',
      link: '#/rentals',
      at: Date.now(),
      createdAt: Date.now()
    });

    return res.json({ success: true, status: 'Returned' });
  } catch (err) {
    console.error('Server error in /api/rentals/return:', err);
    return res.status(500).json({ error: 'Server error marking rental returned: ' + err.message });
  }
});

/**
 * POST /api/rentals/complete
 * Owner marks returned rental as completed.
 */
app.post('/api/rentals/complete', verifyFirebaseAuth, async (req, res) => {
  try {
    const ownerId = req.user.uid;
    const { rentalId } = req.body;

    if (!rentalId) {
      return res.status(400).json({ error: 'Rental ID is required.' });
    }

    const rentalRef = db.collection('rentals').doc(rentalId);
    const rentalDoc = await rentalRef.get();
    if (!rentalDoc.exists) {
      return res.status(404).json({ error: 'Rental request not found.' });
    }

    const rental = rentalDoc.data();
    if (rental.ownerId !== ownerId) {
      return res.status(403).json({ error: 'Only the item owner can complete this rental.' });
    }
    if (rental.status !== 'Returned' && rental.status !== 'Active') {
      return res.status(400).json({ error: 'Rental cannot be completed from current status.' });
    }

    await rentalRef.update({
      status: 'Completed',
      updatedAt: Date.now()
    });

    const itemDoc = await db.collection('listings').doc(rental.itemId).get();
    const itemName = itemDoc.exists ? itemDoc.data().name : 'item';
    await db.collection('notifications').add({
      userId: rental.renterId,
      text: `Rental for "${itemName}" has been Completed. Please leave a review!`,
      type: 'status_completed',
      link: '#/rentals',
      at: Date.now(),
      createdAt: Date.now()
    });

    return res.json({ success: true, status: 'Completed' });
  } catch (err) {
    console.error('Server error in /api/rentals/complete:', err);
    return res.status(500).json({ error: 'Server error completing rental: ' + err.message });
  }
});

/**
 * GET /api/rentals
 * Return authoritative rentals for the authenticated user.
 */
app.get('/api/rentals', verifyFirebaseAuth, async (req, res) => {
  try {
    const userId = req.user.uid;
    const [renterSnapshot, ownerSnapshot] = await Promise.all([
      db.collection('rentals').where('renterId', '==', userId).get(),
      db.collection('rentals').where('ownerId', '==', userId).get()
    ]);

    const rentalsMap = new Map();
    renterSnapshot.forEach(doc => rentalsMap.set(doc.id, Object.assign({ id: doc.id }, doc.data())));
    ownerSnapshot.forEach(doc => rentalsMap.set(doc.id, Object.assign({ id: doc.id }, doc.data())));

    const rentals = Array.from(rentalsMap.values()).sort((a, b) => {
      return (b.at || b.createdAt || 0) - (a.at || a.createdAt || 0);
    });

    return res.json({ success: true, rentals });
  } catch (err) {
    console.error('Server error in GET /api/rentals:', err);
    return res.status(500).json({ error: 'Server error fetching rentals: ' + err.message });
  }
});

/* ---------- Fallback to Single Page App ---------- */
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`RentShare secure backend running at http://localhost:${PORT}`);
});
