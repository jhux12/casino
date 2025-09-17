import { initializeApp } from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-app.js';
import {
  getAuth,
  onAuthStateChanged,
  signInWithEmailAndPassword,
  signOut,
  sendPasswordResetEmail,
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-auth.js';
import {
  getFirestore,
  collection,
  doc,
  getDoc,
  getDocs,
  setDoc,
  updateDoc,
  addDoc,
  onSnapshot,
  query,
  orderBy,
  limit,
  serverTimestamp,
  runTransaction,
} from 'https://www.gstatic.com/firebasejs/10.12.2/firebase-firestore.js';

const ADMIN_EMAIL = 'jhuxf12@outlook.com';
const BALANCE_STORAGE_KEY = 'neonCasinoBalance';
const USER_REGISTRY_KEY = 'neonCasinoUserRegistry';
const ACTIVE_WINDOW_MINUTES = 15;
const ONLINE_STALE_MINUTES = 5;

const toneStyles = {
  emerald: 'bg-emerald-500/10 border border-emerald-500/40 text-emerald-200',
  sky: 'bg-sky-500/10 border border-sky-500/40 text-sky-200',
  amber: 'bg-amber-500/10 border border-amber-500/40 text-amber-200',
  rose: 'bg-rose-500/10 border border-rose-500/40 text-rose-200',
  violet: 'bg-violet-500/10 border border-violet-500/40 text-violet-200',
};

const vipStyles = {
  Bronze: 'border border-amber-500/30 text-amber-200 bg-amber-500/10',
  Silver: 'border border-slate-300/30 text-slate-100 bg-slate-300/10',
  Gold: 'border border-yellow-500/30 text-yellow-200 bg-yellow-500/10',
  Platinum: 'border border-blue-400/30 text-blue-100 bg-blue-400/10',
  Diamond: 'border border-cyan-400/30 text-cyan-100 bg-cyan-400/10',
  Obsidian: 'border border-purple-500/30 text-purple-200 bg-purple-500/10',
  Executive: 'border border-emerald-500/30 text-emerald-200 bg-emerald-500/10',
};

const statusStyles = {
  Active: 'border border-emerald-400/40 text-emerald-200 bg-emerald-500/10',
  'Cooling Off': 'border border-amber-400/40 text-amber-200 bg-amber-500/10',
  'Under Review': 'border border-sky-400/40 text-sky-200 bg-sky-500/10',
  Suspended: 'border border-rose-500/40 text-rose-200 bg-rose-500/10',
};

const statusIndicators = {
  Active: 'bg-emerald-400',
  'Cooling Off': 'bg-amber-400',
  'Under Review': 'bg-sky-400',
  Suspended: 'bg-rose-500',
};

const riskStyles = {
  Low: 'border border-emerald-400/40 text-emerald-200 bg-emerald-500/10',
  Medium: 'border border-amber-400/40 text-amber-200 bg-amber-500/10',
  Elevated: 'border border-orange-400/40 text-orange-200 bg-orange-500/10',
  Critical: 'border border-rose-500/40 text-rose-200 bg-rose-500/10',
};

const roleStyles = {
  Player: 'border border-gray-700 text-gray-300 bg-gray-800/40',
  VIP: 'border border-purple-400/40 text-purple-200 bg-purple-500/10',
  Moderator: 'border border-blue-400/40 text-blue-200 bg-blue-500/10',
  Administrator: 'border border-primary/40 text-primary bg-primary/10',
};

const state = {
  authUser: null,
  adminProfile: null,
  auth: null,
  db: null,
  users: [],
  visibleUsers: [],
  activeUserId: null,
  auditEntries: [],
  userActivity: [],
  filters: {
    search: '',
    status: 'all',
    role: 'all',
    vip: 'all',
  },
  formInitialData: null,
  formDirty: false,
  usersUnsub: null,
  auditUnsub: null,
  activityUnsub: null,
  lastSync: null,
  usersFallback: false,
  usersFromLocal: false,
  cacheToastShown: false,
  presenceIntervalId: null,
};

const elements = {
  shell: document.querySelector('[data-admin-shell]'),
  tableBody: document.querySelector('[data-user-table]'),
  cardList: document.querySelector('[data-user-cards]'),
  tableCount: document.querySelector('[data-table-count]'),
  tableTotal: document.querySelector('[data-table-total]'),
  searchInput: document.querySelector('[data-user-search]'),
  filters: {
    status: document.querySelector('[data-filter="status"]'),
    role: document.querySelector('[data-filter="role"]'),
    vip: document.querySelector('[data-filter="vip"]'),
  },
  summary: {
    totalUsers: document.querySelector('[data-summary="total-users"]'),
    totalBalance: document.querySelector('[data-summary="total-balance"]'),
    newSignups: document.querySelector('[data-summary="new-signups"]'),
    adminCount: document.querySelector('[data-summary="admin-count"]'),
    activeNow: document.querySelector('[data-summary="active-now"]'),
    flagged: document.querySelector('[data-summary="flagged"]'),
  },
  lastSync: document.querySelector('[data-last-sync]'),
  detailPanel: document.querySelector('[data-detail-panel]'),
  activityList: document.querySelector('[data-activity-list]'),
  auditList: document.querySelector('[data-audit-list]'),
  selectedView: document.querySelector('[data-selected-view]'),
  emptyView: document.querySelector('[data-empty-view]'),
  userForm: document.querySelector('[data-user-form]'),
  balanceInput: document.querySelector('[data-balance-input]'),
  toast: document.querySelector('[data-toast]'),
  toastMessage: document.querySelector('[data-toast-message]'),
  toastClose: document.querySelector('[data-toast-close]'),
  auditButton: document.querySelector('[data-open-audit]'),
  refreshUsers: document.querySelector('[data-refresh-users]'),
  refreshAudit: document.querySelector('[data-refresh-audit]'),
  exportUsers: document.querySelector('[data-export-users]'),
  lastSyncTarget: document.querySelector('[data-last-sync]'),
  activeUsers: document.querySelector('[data-active-users]'),
  activeUsersEmpty: document.querySelector('[data-active-users-empty]'),
};

elements.detail = elements.detailPanel
  ? {
      name: elements.detailPanel.querySelector('[data-detail-name]'),
      email: elements.detailPanel.querySelector('[data-detail-email]'),
      id: elements.detailPanel.querySelector('[data-detail-id]'),
      role: elements.detailPanel.querySelector('[data-detail-role]'),
      status: elements.detailPanel.querySelector('[data-detail-status]'),
      vip: elements.detailPanel.querySelector('[data-detail-vip]'),
      balance: elements.detailPanel.querySelector('[data-detail-balance]'),
      deposits: elements.detailPanel.querySelector('[data-detail-deposits]'),
      wagered: elements.detailPanel.querySelector('[data-detail-wagered]'),
      payouts: elements.detailPanel.querySelector('[data-detail-payouts]'),
      lastActive: elements.detailPanel.querySelector('[data-detail-last-active]'),
      location: elements.detailPanel.querySelector('[data-detail-location]'),
      tags: elements.detailPanel.querySelector('[data-detail-tags]'),
      cooldown: elements.detailPanel.querySelector('[data-detail-cooldown]'),
      cooldownText: elements.detailPanel.querySelector('[data-detail-cooldown-text]'),
    }
  : {};

elements.nav = {
  signedIn: document.querySelectorAll('[data-admin-auth-signed-in]'),
  signedOut: document.querySelectorAll('[data-admin-auth-signed-out]'),
  identityName: document.querySelectorAll('[data-admin-identity-name]'),
  identityEmail: document.querySelectorAll('[data-admin-identity-email]'),
  signOut: document.querySelectorAll('[data-admin-signout]'),
};

const gate = createGateController();
const toast = createToast();

initNavigation();
initAOSAndFeather();
startPresenceTicker();

const firebaseConfig = readFirebaseConfig();

if (!firebaseConfig) {
  gate.showError('Firebase configuration is missing. Update the <script id="firebase-config"> block with your web app credentials.');
} else {
  try {
    const app = initializeApp(firebaseConfig);
    const auth = getAuth(app);
    const db = getFirestore(app);
    initAdminApp({ auth, db });
  } catch (error) {
    console.error('Failed to initialize Firebase', error);
    gate.showError('We were unable to connect to Firebase. Verify your configuration and reload the page.');
  }
}

function initAdminApp({ auth, db }) {
  state.auth = auth;
  state.db = db;
  if (elements.shell) {
    elements.shell.hidden = true;
  }

  setupLoginFlow(auth);
  setupNavSignOut(auth);
  setupFilterControls();
  setupQuickActions(auth, db);

  gate.showLoading();

  onAuthStateChanged(auth, async user => {
    cleanupListeners();
    if (!user) {
      state.authUser = null;
      state.adminProfile = null;
      setNavSignedOut();
      if (elements.shell) {
        elements.shell.hidden = true;
      }
      gate.showLogin();
      return;
    }

    gate.showLoading();

    const fallbackProfile = buildFallbackAdminProfile(user);
    let profile = null;
    let profileError = null;

    try {
      profile = await ensureAdminProfile(db, user);
    } catch (error) {
      profileError = error;
      console.error('Failed to synchronize administrator profile from Firestore', error);
    }

    state.authUser = user;

    let effectiveProfile = profile;
    let forcedAdmin = false;
    if (!effectiveProfile || effectiveProfile.isAdmin !== true) {
      if (fallbackProfile.isAdmin) {
        const existingProfile = effectiveProfile || {};
        effectiveProfile = {
          ...fallbackProfile,
          ...existingProfile,
          displayName: existingProfile.displayName || fallbackProfile.displayName,
          email: existingProfile.email || fallbackProfile.email,
          isAdmin: true,
        };
        forcedAdmin = true;
      }
    }

    state.adminProfile = effectiveProfile || fallbackProfile;

    if (!state.adminProfile?.isAdmin) {
      setNavSignedOut();
      if (elements.shell) {
        elements.shell.hidden = true;
      }
      gate.showUnauthorized(
        `The account ${state.adminProfile?.email || user.email || 'unknown'} is not authorized for administrator access.`,
      );
      return;
    }

    setNavSignedIn(state.adminProfile);
    gate.close();
    if (elements.shell) {
      elements.shell.hidden = false;
    }

    if (profileError) {
      toast.show('Connected in limited admin mode. Firebase data will sync when permissions allow.', 'warning');
    } else if (forcedAdmin) {
      toast.show('Administrator access enforced locally. Verify Firestore rules to persist changes.', 'warning');
    }

    let userDirectoryError = null;
    let auditError = null;
    try {
      await fetchUsersOnce(db);
    } catch (error) {
      userDirectoryError = error;
      console.error('Initial user directory load failed', error);
      toast.show('Unable to load existing players. Realtime updates will keep trying.', 'danger');
      loadUsersFromLocalRegistry({ notify: true });
    }
    try {
      await fetchAuditOnce(db);
    } catch (error) {
      auditError = error;
      console.error('Initial audit log load failed', error);
      toast.show('Audit timeline could not be loaded. Realtime updates will retry automatically.', 'danger');
    }

    subscribeToUsers(db);
    subscribeToAudit(db);

    if (!userDirectoryError && !auditError && state.users.length) {
      if (state.usersFallback) {
        toast.show('Admin data loaded with basic ordering. Create an index to unlock live sorting.', 'warning');
      } else {
        toast.show('Admin data synchronized with Firebase.', 'success');
      }
    }
  });
}

function setupLoginFlow(auth) {
  const form = gate.loginForm;
  const emailInput = gate.loginEmail;
  const passwordInput = gate.loginPassword;
  const submitButton = gate.loginSubmit;
  const resetButton = gate.resetButton;

  function setFormLoading(isLoading) {
    if (!submitButton) {
      return;
    }
    submitButton.disabled = isLoading;
    submitButton.classList.toggle('opacity-60', isLoading);
    submitButton.textContent = isLoading ? 'Signing In…' : 'Sign In';
  }

  function clearError() {
    if (gate.loginError) {
      gate.loginError.classList.add('hidden');
      gate.loginError.textContent = '';
    }
  }

  function showError(message) {
    if (gate.loginError) {
      gate.loginError.textContent = message;
      gate.loginError.classList.remove('hidden');
    }
  }

  if (form) {
    form.addEventListener('submit', async event => {
      event.preventDefault();
      clearError();
      const email = (emailInput?.value || '').trim();
      const password = passwordInput?.value || '';
      if (!email || !password) {
        showError('Enter your email and password to continue.');
        return;
      }
      setFormLoading(true);
      try {
        await signInWithEmailAndPassword(auth, email, password);
      } catch (error) {
        console.error('Login failed', error);
        showError(getFriendlyErrorMessage(error));
      } finally {
        setFormLoading(false);
      }
    });
  }

  if (resetButton) {
    resetButton.addEventListener('click', async () => {
      clearError();
      const email = (emailInput?.value || '').trim();
      if (!email) {
        showError('Enter the email address to send the reset link.');
        return;
      }
      resetButton.disabled = true;
      try {
        await sendPasswordResetEmail(auth, email);
        toast.show(`Password reset instructions sent to ${email}.`, 'info');
      } catch (error) {
        console.error('Reset email failed', error);
        showError(getFriendlyErrorMessage(error));
      } finally {
        resetButton.disabled = false;
      }
    });
  }

  if (gate.retryButton) {
    gate.retryButton.addEventListener('click', () => {
      gate.showLogin();
    });
  }
}

function setupNavSignOut(auth) {
  elements.nav.signOut.forEach(button => {
    button.addEventListener('click', async () => {
      try {
        await signOut(auth);
        toast.show('Signed out of the admin console.', 'info');
      } catch (error) {
        console.error('Sign out failed', error);
        toast.show('Unable to sign out. Try again.', 'danger');
      }
    });
  });
}

function setupFilterControls() {
  if (elements.searchInput) {
    elements.searchInput.addEventListener('input', event => {
      state.filters.search = (event.target.value || '').trim().toLowerCase();
      updateVisibleUsers();
    });
  }

  Object.entries(elements.filters).forEach(([key, element]) => {
    if (!element) {
      return;
    }
    element.addEventListener('change', event => {
      state.filters[key] = event.target.value;
      updateVisibleUsers();
    });
  });
}

function setupQuickActions(auth, db) {
  if (elements.toastClose) {
    elements.toastClose.addEventListener('click', () => toast.hide());
  }

  document.querySelectorAll('[data-balance-adjust]').forEach(button => {
    button.addEventListener('click', () => {
      if (!elements.balanceInput) {
        return;
      }
      const delta = Number.parseFloat(button.getAttribute('data-balance-adjust') || '0');
      const current = Number.parseFloat(elements.balanceInput.value || '0');
      const nextValue = Math.max(0, Number.isFinite(current) ? current + delta : delta);
      elements.balanceInput.value = nextValue.toFixed(2);
      state.formDirty = true;
    });
  });

  document.querySelectorAll('[data-balance-reset]').forEach(button => {
    button.addEventListener('click', () => {
      resetFormToInitial();
      toast.show('Values reset to the latest saved state.', 'info');
    });
  });

  document.querySelectorAll('[data-balance-action="zero"]').forEach(button => {
    button.addEventListener('click', () => {
      if (!elements.balanceInput) {
        return;
      }
      elements.balanceInput.value = '0.00';
      state.formDirty = true;
    });
  });

  document.querySelectorAll('[data-reset-user]').forEach(button => {
    button.addEventListener('click', () => {
      resetFormToInitial();
      toast.show('Pending changes discarded.', 'info');
    });
  });

  if (elements.auditButton) {
    elements.auditButton.addEventListener('click', () => {
      elements.auditList?.scrollIntoView({ behavior: 'smooth', block: 'start' });
      toast.show('Navigated to the audit timeline.', 'info');
    });
  }

  if (elements.refreshUsers) {
    elements.refreshUsers.addEventListener('click', async () => {
      try {
        await fetchUsersOnce(state.db);
        if (state.usersFallback) {
          toast.show('User directory refreshed. Ordering is limited until an index is created.', 'warning');
        } else {
          toast.show('User directory refreshed.', 'success');
        }
      } catch (error) {
        console.error('Manual user refresh failed', error);
        toast.show('Unable to refresh users. Check your connection.', 'danger');
        loadUsersFromLocalRegistry({ notify: true });
      }
    });
  }

  if (elements.refreshAudit) {
    elements.refreshAudit.addEventListener('click', async () => {
      try {
        await fetchAuditOnce(state.db);
        toast.show('Audit log updated.', 'success');
      } catch (error) {
        console.error('Manual audit refresh failed', error);
        toast.show('Unable to refresh audit timeline.', 'danger');
      }
    });
  }

  if (elements.exportUsers) {
    elements.exportUsers.addEventListener('click', () => {
      exportUsersToCsv();
    });
  }

  const activityRefresh = document.querySelector('[data-admin-action="refresh-activity"]');
  if (activityRefresh) {
    activityRefresh.addEventListener('click', () => {
      if (!state.activeUserId) {
        toast.show('Select a player first.', 'warning');
        return;
      }
      subscribeToActivity(state.activeUserId, true);
      toast.show('Activity feed refreshed.', 'success');
    });
  }

  if (elements.userForm) {
    elements.userForm.addEventListener('input', () => {
      state.formDirty = true;
    });
    elements.userForm.addEventListener('change', () => {
      state.formDirty = true;
    });
    elements.userForm.addEventListener('submit', event => handleUserFormSubmit(event, auth, db));
  }

  document.querySelectorAll('[data-admin-action]').forEach(button => {
    button.addEventListener('click', async () => {
      if (!state.activeUserId) {
        toast.show('Select a player first.', 'warning');
        return;
      }
      const action = button.getAttribute('data-admin-action');
      const user = state.users.find(item => item.id === state.activeUserId);
      if (!user) {
        toast.show('Player data unavailable. Wait for synchronization.', 'warning');
        return;
      }
      try {
        const dbInstance = state.db || getFirestore();
        switch (action) {
          case 'impersonate':
            await logAuditEvent(dbInstance, {
              userId: user.id,
              userName: user.name,
              userEmail: user.email,
              action: 'Sandbox impersonation started',
              description: 'Opened a secure sandbox session for diagnostics.',
              tone: 'sky',
            });
            toast.show('Sandbox impersonation session opened (demo).', 'info');
            break;
          case 'send-reset':
            await sendPasswordResetEmail(auth, user.email);
            await logAuditEvent(dbInstance, {
              userId: user.id,
              userName: user.name,
              userEmail: user.email,
              action: 'Password reset email sent',
              description: 'Administrator dispatched a password reset email.',
              tone: 'emerald',
            });
            toast.show('Password reset email sent.', 'success');
            break;
          case 'send-summary':
            await logAuditEvent(dbInstance, {
              userId: user.id,
              userName: user.name,
              userEmail: user.email,
              action: 'Account summary emailed',
              description: 'Account snapshot queued for delivery to the player.',
              tone: 'violet',
            });
            toast.show('Account summary queued for delivery.', 'success');
            break;
          case 'suspend':
            await updateDoc(doc(dbInstance, 'users', user.id), {
              status: 'Suspended',
              payoutHold: true,
              updatedAt: serverTimestamp(),
            });
            await logAuditEvent(dbInstance, {
              userId: user.id,
              userName: user.name,
              userEmail: user.email,
              action: 'Account suspended',
              description: 'Administrator suspended the account and enabled withdrawal hold.',
              tone: 'rose',
            });
            toast.show('Account suspended and withdrawal hold enabled.', 'warning');
            applyLocalUserPatch(user.id, {
              status: 'Suspended',
              payoutHold: true,
              updatedAt: new Date(),
              lastActiveAt: new Date(),
              isOnline: false,
            });
            break;
          case 'schedule-call':
            await logAuditEvent(dbInstance, {
              userId: user.id,
              userName: user.name,
              userEmail: user.email,
              action: 'Wellbeing call scheduled',
              description: 'Responsible gaming outreach scheduled for the player.',
              tone: 'amber',
            });
            toast.show('Wellbeing call scheduled.', 'success');
            break;
          default:
            break;
        }
      } catch (error) {
        console.error('Action failed', error);
        toast.show('Unable to complete the requested action.', 'danger');
      }
    });
  });
}

function cleanupListeners() {
  if (typeof state.usersUnsub === 'function') {
    state.usersUnsub();
    state.usersUnsub = null;
  }
  if (typeof state.auditUnsub === 'function') {
    state.auditUnsub();
    state.auditUnsub = null;
  }
  if (typeof state.activityUnsub === 'function') {
    state.activityUnsub();
    state.activityUnsub = null;
  }
  state.users = [];
  state.visibleUsers = [];
  state.activeUserId = null;
  state.auditEntries = [];
  state.userActivity = [];
  state.usersFallback = false;
  state.usersFromLocal = false;
  state.cacheToastShown = false;
  state.lastSync = null;
  updateVisibleUsers();
  updateSummary();
  renderAudit();
  renderActivity();
  updateLastSync();
}

function buildFallbackAdminProfile(user) {
  if (!user) {
    return {
      id: 'unknown-admin',
      displayName: 'Administrator',
      email: '',
      isAdmin: false,
    };
  }

  const email = typeof user.email === 'string' ? user.email.trim() : '';
  const normalizedEmail = email || '';
  const displayName = user.displayName || (normalizedEmail ? normalizedEmail.split('@')[0] : 'Administrator');
  const isRequestedAdmin = normalizedEmail.toLowerCase() === ADMIN_EMAIL.toLowerCase();

  return {
    id: user.uid || 'local-admin',
    displayName: displayName || 'Administrator',
    email: normalizedEmail,
    isAdmin: isRequestedAdmin,
  };
}

async function ensureAdminProfile(db, user) {
  const userRef = doc(db, 'users', user.uid);
  let snapshot = null;
  try {
    snapshot = await getDoc(userRef);
  } catch (error) {
    console.warn('Unable to read administrator profile. Continuing with fallbacks.', error);
  }
  const baseDisplayName = user.displayName || (user.email ? user.email.split('@')[0] : 'Administrator');
  const isRequestedAdmin = (user.email || '').toLowerCase() === ADMIN_EMAIL.toLowerCase();
  const defaults = {
    displayName: baseDisplayName || 'Administrator',
    email: user.email ?? null,
    balance: 0,
    role: isRequestedAdmin ? 'Administrator' : 'Player',
    status: 'Active',
    vipTier: isRequestedAdmin ? 'Executive' : 'Bronze',
    riskLevel: 'Low',
    lifetimeDeposits: 0,
    lifetimeWagered: 0,
    lifetimePayouts: 0,
    segments: isRequestedAdmin ? ['Admin'] : [],
    notes: '',
    twoFactor: false,
    emailVerified: user.emailVerified ?? false,
    payoutHold: false,
    createdAt: serverTimestamp(),
    updatedAt: serverTimestamp(),
    lastLoginAt: serverTimestamp(),
    lastActiveAt: serverTimestamp(),
    isAdmin: isRequestedAdmin,
  };

  let data = snapshot?.exists() ? snapshot.data() || {} : {};
  const updates = {};

  const safeMerge = payload => {
    if (!payload || typeof payload !== 'object') {
      return;
    }
    data = { ...data, ...payload };
  };

  const safeUpdate = async (payload, context) => {
    if (!payload || !Object.keys(payload).length) {
      return;
    }
    try {
      await updateDoc(userRef, payload);
      safeMerge(payload);
    } catch (error) {
      console.warn(context || 'Unable to sync admin profile updates', error);
    }
  };

  if (!snapshot?.exists()) {
    try {
      await setDoc(userRef, defaults);
      data = { ...defaults };
    } catch (error) {
      console.warn('Unable to create administrator profile. Using local defaults.', error);
      data = { ...defaults, createdAt: null, updatedAt: null };
    }
  } else {
    if (!data.displayName && defaults.displayName) {
      updates.displayName = defaults.displayName;
    }
    if (!data.email && user.email) {
      updates.email = user.email;
    }
    if (typeof data.balance !== 'number') {
      updates.balance = 0;
    }
    if (!data.status) {
      updates.status = 'Active';
    }
    if (!data.role) {
      updates.role = 'Player';
    }
    if (!data.vipTier) {
      updates.vipTier = 'Bronze';
    }
    if (!data.riskLevel) {
      updates.riskLevel = 'Low';
    }
    if (!Array.isArray(data.segments)) {
      updates.segments = defaults.segments;
    }
    if (typeof data.emailVerified !== 'boolean') {
      updates.emailVerified = user.emailVerified ?? false;
    }
    if (isRequestedAdmin) {
      if (data.isAdmin !== true) {
        updates.isAdmin = true;
      }
      const existingRole = typeof data.role === 'string' ? data.role.toLowerCase() : '';
      if (existingRole !== 'administrator') {
        updates.role = 'Administrator';
      }
      if (data.vipTier !== 'Executive') {
        updates.vipTier = 'Executive';
      }
      const segmentSource = Object.prototype.hasOwnProperty.call(updates, 'segments')
        ? updates.segments
        : data.segments;
      const currentSegments = Array.isArray(segmentSource) ? segmentSource : [];
      if (!currentSegments.includes('Admin')) {
        updates.segments = Array.from(new Set([...currentSegments, 'Admin']));
      }
    }
    if (Object.keys(updates).length) {
      updates.updatedAt = serverTimestamp();
      await safeUpdate(updates, 'Unable to sync administrator defaults');
    }
  }

  const merged = { ...data };
  const isAdmin =
    isRequestedAdmin ||
    merged.isAdmin === true ||
    (typeof merged.role === 'string' && merged.role.toLowerCase() === 'administrator');

  if (isAdmin && !Array.isArray(merged.segments)) {
    merged.segments = ['Admin'];
  }

  if (isAdmin && Array.isArray(merged.segments) && !merged.segments.includes('Admin')) {
    merged.segments = Array.from(new Set([...merged.segments, 'Admin']));
    await safeUpdate({ segments: merged.segments, updatedAt: serverTimestamp() }, 'Unable to sync admin segments');
  }

  if (isAdmin && merged.vipTier !== 'Executive') {
    await safeUpdate({ vipTier: 'Executive', updatedAt: serverTimestamp() }, 'Unable to sync admin vip tier');
    merged.vipTier = 'Executive';
  }

  if (isAdmin && (typeof merged.role !== 'string' || merged.role.toLowerCase() !== 'administrator')) {
    await safeUpdate({ role: 'Administrator', updatedAt: serverTimestamp() }, 'Unable to sync admin role');
    merged.role = 'Administrator';
  }

  if (isAdmin && user.email && merged.email !== user.email) {
    await safeUpdate({ email: user.email, updatedAt: serverTimestamp() }, 'Unable to sync admin email to profile');
    merged.email = user.email;
  }

  try {
    await setDoc(
      userRef,
      {
        lastLoginAt: serverTimestamp(),
        lastActiveAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      },
      { merge: true }
    );
  } catch (error) {
    console.warn('Unable to update lastLoginAt', error);
  }

  return {
    id: user.uid,
    displayName: merged.displayName || baseDisplayName || 'Administrator',
    email: merged.email || user.email || '',
    isAdmin,
  };
}

function subscribeToUsers(db) {
  if (!db) {
    console.warn('Firestore instance missing. Skipping realtime user subscription.');
    return;
  }

  const usersRef = collection(db, 'users');
  const orderedQuery = query(usersRef, orderBy('updatedAt', 'desc'));

  const attach = (targetRef, isFallback) => {
    const unsubscribe = onSnapshot(
      targetRef,
      snapshot => {
        ingestUserSnapshot(snapshot, isFallback);
      },
      error => {
        const code = error?.code;
        if (code === 'permission-denied') {
          console.error('User stream permission denied. Falling back to cached registry.', error);
          toast.show('Realtime access denied. Showing cached player registry only.', 'warning');
          unsubscribe();
          loadUsersFromLocalRegistry({ notify: true });
          return;
        }
        if (code === 'failed-precondition') {
          console.warn('User stream missing index. Switching to fallback ordering.', error);
          toast.show('Realtime ordering requires an index. Showing basic ordering for now.', 'warning');
          unsubscribe();
          if (!isFallback) {
            attach(usersRef, true);
          }
          return;
        }
        console.error('User snapshot error', error);
        toast.show('Realtime updates interrupted. Attempting to reconnect…', 'danger');
        unsubscribe();
        if (!isFallback) {
          attach(usersRef, true);
        }
      }
    );
    state.usersUnsub = unsubscribe;
  };

  try {
    attach(orderedQuery, false);
  } catch (error) {
    if (error?.code === 'permission-denied') {
      console.error('Unable to attach realtime user stream due to permissions.', error);
      loadUsersFromLocalRegistry({ notify: true });
      return;
    }
    console.warn('Falling back to unordered user stream', error);
    attach(usersRef, true);
  }
}

function ingestUserSnapshot(snapshot, isFallback = false) {
  if (!snapshot) {
    return;
  }
  const records = snapshot.docs.map(docSnap => normalizeUserDoc(docSnap));
  state.users = records;
  state.usersFallback = isFallback;
  state.usersFromLocal = false;
  state.cacheToastShown = false;
  updateVisibleUsers();
  updateSummary();
  state.lastSync = new Date();
  updateLastSync();
  syncLocalRegistry();
}

function subscribeToAudit(db) {
  if (!db) {
    console.warn('Firestore instance missing. Skipping realtime audit subscription.');
    return;
  }
  const auditRef = query(collection(db, 'adminAudit'), orderBy('createdAt', 'desc'), limit(25));
  state.auditUnsub = onSnapshot(
    auditRef,
    snapshot => {
      state.auditEntries = snapshot.docs.map(docSnap => normalizeAuditDoc(docSnap));
      renderAudit();
    },
    error => {
      console.error('Audit snapshot error', error);
      toast.show('Audit feed disconnected. Use refresh to retry.', 'danger');
    }
  );
}

function subscribeToActivity(userId, force = false) {
  if (!userId) {
    if (typeof state.activityUnsub === 'function') {
      state.activityUnsub();
      state.activityUnsub = null;
    }
    state.userActivity = [];
    renderActivity();
    return;
  }
  const db = state.db || getFirestore();
  if (!db) {
    console.warn('Firestore unavailable. Skipping activity subscription.');
    return;
  }
  const activityRef = query(collection(db, 'users', userId, 'activity'), orderBy('createdAt', 'desc'), limit(20));
  if (state.activityUnsub && !force) {
    return;
  }
  if (state.activityUnsub) {
    state.activityUnsub();
  }
  state.activityUnsub = onSnapshot(
    activityRef,
    snapshot => {
      state.userActivity = snapshot.docs.map(docSnap => normalizeActivityDoc(docSnap));
      renderActivity();
    },
    error => {
      console.error('Activity snapshot error', error);
    }
  );
}

async function fetchUsersOnce(dbOverride) {
  const db = dbOverride || state.db || getFirestore();
  if (!db) {
    throw new Error('Firestore instance unavailable');
  }
  const usersRef = collection(db, 'users');
  try {
    const snapshot = await getDocs(query(usersRef, orderBy('updatedAt', 'desc')));
    ingestUserSnapshot(snapshot, false);
  } catch (error) {
    const code = error?.code;
    if (code === 'failed-precondition') {
      console.warn('Falling back to unordered user fetch', error);
      const fallbackSnapshot = await getDocs(usersRef);
      ingestUserSnapshot(fallbackSnapshot, true);
      return;
    }
    throw error;
  }
}

async function fetchAuditOnce(dbOverride) {
  const db = dbOverride || state.db || getFirestore();
  if (!db) {
    throw new Error('Firestore instance unavailable');
  }
  const snapshot = await getDocs(query(collection(db, 'adminAudit'), orderBy('createdAt', 'desc'), limit(25)));
  state.auditEntries = snapshot.docs.map(docSnap => normalizeAuditDoc(docSnap));
  renderAudit();
}

function updateVisibleUsers() {
  const filters = state.filters;
  const search = filters.search;
  const filtered = state.users
    .filter(user => {
      if (search) {
        const segments = Array.isArray(user.segments) ? user.segments.join(' ').toLowerCase() : '';
        if (
          !user.name.toLowerCase().includes(search) &&
          !(user.email || '').toLowerCase().includes(search) &&
          !segments.includes(search)
        ) {
          return false;
        }
      }
      if (filters.status !== 'all' && user.status !== filters.status) {
        return false;
      }
      if (filters.role !== 'all' && user.role !== filters.role) {
        return false;
      }
      if (filters.vip !== 'all' && user.vipTier !== filters.vip) {
        return false;
      }
      return true;
    })
    .sort((a, b) => a.lastActiveMinutes - b.lastActiveMinutes);

  state.visibleUsers = filtered;
  if (!filtered.length) {
    state.activeUserId = null;
  } else if (!state.activeUserId || !filtered.some(user => user.id === state.activeUserId)) {
    state.activeUserId = filtered[0].id;
  }
  renderTable();
  renderDetail();
  if (state.activeUserId) {
    subscribeToActivity(state.activeUserId);
  } else {
    subscribeToActivity(null);
  }
  if (elements.tableCount) {
    elements.tableCount.textContent = filtered.length.toLocaleString();
  }
  if (elements.tableTotal) {
    elements.tableTotal.textContent = state.users.length.toLocaleString();
  }
}

function renderTable() {
  const tableBody = elements.tableBody;
  const cardList = elements.cardList;
  const emptyMessage = 'No matching players. Adjust filters or invite a new user.';

  if (!state.visibleUsers.length) {
    if (tableBody) {
      tableBody.innerHTML = `<tr><td colspan="6" class="px-4 py-6 text-center text-sm text-gray-400">${escapeHtml(
        emptyMessage
      )}</td></tr>`;
    }
    if (cardList) {
      cardList.innerHTML = `
        <div class="rounded-2xl border border-gray-800/70 bg-black/30 px-4 py-6 text-center text-sm text-gray-400">
          ${escapeHtml(emptyMessage)}
        </div>
      `;
    }
    return;
  }

  if (tableBody) {
    const rows = state.visibleUsers
      .map(user => {
        const isActive = user.id === state.activeUserId;
        const badgeStatus = statusStyles[user.status] || 'border border-gray-700 text-gray-300 bg-gray-800/40';
        const vipBadge = vipStyles[user.vipTier] || 'border border-gray-700 text-gray-300 bg-gray-800/40';
        const riskBadge = riskStyles[user.riskLevel] || 'border border-gray-700 text-gray-300 bg-gray-800/40';
        const roleBadge = roleStyles[user.role] || 'border border-gray-700 text-gray-300 bg-gray-800/40';
        const statusIndicator = user.isOnline
          ? 'bg-emerald-400 animate-pulse shadow-[0_0_0_4px_rgba(16,185,129,0.35)]'
          : user.lastActiveMinutes <= ACTIVE_WINDOW_MINUTES
          ? 'bg-amber-400 shadow-[0_0_0_4px_rgba(251,191,36,0.25)]'
          : statusIndicators[user.status] || 'bg-gray-500';
        const rowClasses = [
          'group',
          'cursor-pointer',
          'transition',
          'border-l-2',
          'border-transparent',
          'hover:bg-gray-900/40',
          isActive ? 'bg-primary/5 border-primary/70 shadow-[0_0_20px_rgba(0,194,255,0.12)]' : '',
        ]
          .filter(Boolean)
          .join(' ');
        const segments = Array.isArray(user.segments)
          ? user.segments
              .map(segment => `
                <span class="text-[11px] uppercase tracking-[0.2em] text-gray-500 bg-gray-800/70 border border-gray-700/80 rounded-full px-2 py-0.5">${escapeHtml(
                  segment
                )}</span>
              `)
              .join('')
          : '';
        const joinedLabel = user.createdAt
          ? user.createdAt.toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' })
          : 'Unknown';
        return `
          <tr data-user-row data-user-id="${user.id}" class="${rowClasses}">
            <td class="px-4 py-3">
              <div class="flex items-start gap-3">
                <div class="relative">
                  <span class="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-primary/30 to-secondary/30 font-semibold text-white">${getInitials(
                    user.name
                  )}</span>
                  <span class="absolute -bottom-1 -right-1 h-2.5 w-2.5 rounded-full ${statusIndicator} ring-2 ring-gray-900"></span>
                </div>
                <div>
                  <p class="font-semibold text-white">${escapeHtml(user.name)}</p>
                  <p class="text-xs text-gray-400">${escapeHtml(user.email || '—')}</p>
                  <div class="flex flex-wrap gap-1 mt-1">${segments}</div>
                </div>
              </div>
            </td>
            <td class="px-4 py-3">
              <span class="badge ${badgeStatus}">${escapeHtml(user.status)}</span>
            </td>
            <td class="px-4 py-3">
              <div class="space-y-1">
                <p class="font-semibold text-white">${formatCurrency(user.balance)}</p>
                <p class="text-[11px] text-gray-500">Payouts: ${formatCurrency(user.lifetimePayouts)}</p>
              </div>
            </td>
            <td class="px-4 py-3">
              <div class="flex flex-col gap-2">
                <span class="badge ${vipBadge}">${escapeHtml(user.vipTier)} VIP</span>
                <span class="badge ${roleBadge}">${escapeHtml(user.role)}</span>
              </div>
            </td>
            <td class="px-4 py-3">
              <p class="font-medium text-white">${escapeHtml(user.lastActive)}</p>
              <p class="text-[11px] text-gray-500">Joined ${joinedLabel}</p>
            </td>
            <td class="px-4 py-3">
              <span class="badge ${riskBadge}">${escapeHtml(user.riskLevel)}</span>
            </td>
          </tr>
        `;
      })
      .join('');

    tableBody.innerHTML = rows;
    tableBody.querySelectorAll('[data-user-row]').forEach(row => {
      row.addEventListener('click', () => {
        const id = row.getAttribute('data-user-id');
        handleUserSelection(id, { forceActivity: true });
      });
    });
  }

  if (cardList) {
    const cards = state.visibleUsers
      .map(user => {
        const isActive = user.id === state.activeUserId;
        const badgeStatus = statusStyles[user.status] || 'border border-gray-700 text-gray-300 bg-gray-800/40';
        const vipBadge = vipStyles[user.vipTier] || 'border border-gray-700 text-gray-300 bg-gray-800/40';
        const riskBadge = riskStyles[user.riskLevel] || 'border border-gray-700 text-gray-300 bg-gray-800/40';
        const roleBadge = roleStyles[user.role] || 'border border-gray-700 text-gray-300 bg-gray-800/40';
        const statusIndicator = user.isOnline
          ? 'bg-emerald-400 animate-pulse shadow-[0_0_0_4px_rgba(16,185,129,0.35)]'
          : user.lastActiveMinutes <= ACTIVE_WINDOW_MINUTES
          ? 'bg-amber-400 shadow-[0_0_0_4px_rgba(251,191,36,0.25)]'
          : statusIndicators[user.status] || 'bg-gray-500';
        const cardClasses = [
          'w-full',
          'text-left',
          'rounded-2xl',
          'border',
          'px-4',
          'py-4',
          'transition',
          'focus-visible:outline-none',
          'focus-visible:ring-2',
          'focus-visible:ring-primary/60',
          'focus-visible:ring-offset-0',
          'hover:border-primary/40',
          'hover:shadow-[0_0_18px_rgba(0,194,255,0.2)]',
          'bg-black/40',
          'border-gray-800/80',
          'cursor-pointer',
          'flex',
          'flex-col',
          'gap-3',
        ];
        if (isActive) {
          cardClasses.push('border-primary/70', 'bg-primary/10', 'shadow-[0_0_25px_rgba(0,194,255,0.25)]');
        }
        const segments = Array.isArray(user.segments)
          ? user.segments
              .map(segment => `
                <span class="text-[10px] uppercase tracking-[0.25em] text-gray-500 bg-gray-900/60 border border-gray-800/80 rounded-full px-2 py-0.5">${escapeHtml(
                  segment
                )}</span>
              `)
              .join('')
          : '';
        return `
          <button type="button" data-user-card data-user-id="${user.id}" class="${cardClasses.join(' ')}">
            <div class="flex items-start gap-3">
              <div class="relative">
                <span class="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-primary/30 to-secondary/30 font-semibold text-white">${getInitials(
                  user.name
                )}</span>
                <span class="absolute -bottom-1 -right-1 h-2.5 w-2.5 rounded-full ${statusIndicator} ring-2 ring-gray-900"></span>
              </div>
              <div class="min-w-0 flex-1 space-y-1">
                <p class="truncate font-semibold text-white">${escapeHtml(user.name)}</p>
                <p class="truncate text-xs text-gray-400">${escapeHtml(user.email || '—')}</p>
                <p class="text-[11px] text-gray-500">${escapeHtml(user.lastActive)}</p>
              </div>
            </div>
            <div class="flex flex-wrap gap-2 pt-1">
              <span class="badge ${badgeStatus}">${escapeHtml(user.status)}</span>
              <span class="badge ${vipBadge}">${escapeHtml(user.vipTier)} VIP</span>
              <span class="badge ${roleBadge}">${escapeHtml(user.role)}</span>
            </div>
            <div class="grid grid-cols-2 gap-2 text-xs text-gray-400">
              <div>
                <p class="text-[11px] uppercase tracking-[0.3em] text-gray-500">Balance</p>
                <p class="font-semibold text-white mt-0.5">${formatCurrency(user.balance)}</p>
              </div>
              <div>
                <p class="text-[11px] uppercase tracking-[0.3em] text-gray-500">Risk</p>
                <p class="font-semibold text-white mt-0.5">${escapeHtml(user.riskLevel)}</p>
              </div>
            </div>
            ${segments ? `<div class="flex flex-wrap gap-2 pt-2">${segments}</div>` : ''}
          </button>
        `;
      })
      .join('');

    cardList.innerHTML = cards;
    cardList.querySelectorAll('[data-user-card]').forEach(card => {
      card.addEventListener('click', () => {
        const id = card.getAttribute('data-user-id');
        handleUserSelection(id, { forceActivity: true });
      });
    });
  }
}

function handleUserSelection(id, { forceActivity = false } = {}) {
  if (!id) {
    return;
  }
  const isSameUser = state.activeUserId === id;
  state.activeUserId = id;
  state.formDirty = false;
  renderTable();
  renderDetail();
  renderActiveUsers();
  if (!isSameUser || forceActivity) {
    subscribeToActivity(id, true);
  }
}

function renderActiveUsers() {
  const container = elements.activeUsers;
  const emptyState = elements.activeUsersEmpty;
  if (!container) {
    return;
  }

  const activeUsers = state.users
    .filter(user => user.isOnline || user.lastActiveMinutes <= ACTIVE_WINDOW_MINUTES)
    .sort((a, b) => {
      if (a.isOnline && !b.isOnline) return -1;
      if (!a.isOnline && b.isOnline) return 1;
      const diff = a.lastActiveMinutes - b.lastActiveMinutes;
      if (diff !== 0) return diff;
      return a.name.localeCompare(b.name);
    })
    .slice(0, 12);

  if (!activeUsers.length) {
    container.innerHTML = '';
    container.classList.add('hidden');
    if (emptyState) {
      emptyState.classList.remove('hidden');
    }
    return;
  }

  container.classList.remove('hidden');
  if (emptyState) {
    emptyState.classList.add('hidden');
  }

  container.innerHTML = activeUsers
    .map(user => {
      const isSelected = user.id === state.activeUserId;
      const indicatorClass = user.isOnline
        ? 'bg-emerald-400 animate-pulse shadow-[0_0_0_4px_rgba(16,185,129,0.35)]'
        : user.lastActiveMinutes <= 5
        ? 'bg-amber-300 shadow-[0_0_0_4px_rgba(251,191,36,0.25)]'
        : 'bg-amber-500 shadow-[0_0_0_4px_rgba(217,119,6,0.25)]';
      const cardClasses = [
        'min-w-[220px]',
        'rounded-2xl',
        'border',
        'px-4',
        'py-3',
        'bg-black/40',
        'border-gray-800/80',
        'flex',
        'items-center',
        'gap-3',
        'text-left',
        'transition',
        'cursor-pointer',
        'focus-visible:outline-none',
        'focus-visible:ring-2',
        'focus-visible:ring-primary/60',
        'focus-visible:ring-offset-0',
        'hover:border-primary/40',
        'hover:shadow-[0_0_18px_rgba(0,194,255,0.2)]',
      ];
      if (isSelected) {
        cardClasses.push('border-primary/70', 'bg-primary/10', 'shadow-[0_0_25px_rgba(0,194,255,0.25)]');
      }
      const balanceLabel = formatCurrency(user.balance);
      return `
        <button type="button" data-active-user data-user-id="${user.id}" class="${cardClasses.join(' ')}">
          <div class="relative">
            <span class="flex h-10 w-10 items-center justify-center rounded-full bg-gradient-to-br from-primary/30 to-secondary/30 font-semibold text-white">${getInitials(
              user.name
            )}</span>
            <span class="absolute -bottom-1 -right-1 h-2.5 w-2.5 rounded-full ${indicatorClass} ring-2 ring-gray-900"></span>
          </div>
          <div class="min-w-0 flex-1 space-y-1">
            <p class="truncate text-sm font-semibold text-white">${escapeHtml(user.name)}</p>
            <p class="truncate text-xs text-gray-400">${escapeHtml(user.email || '—')}</p>
            <p class="text-[11px] text-gray-500">${escapeHtml(user.lastActive)}</p>
            <p class="text-[11px] text-gray-500">${escapeHtml(balanceLabel)} • ${escapeHtml(user.vipTier)} VIP</p>
          </div>
        </button>
      `;
    })
    .join('');

  container.querySelectorAll('[data-active-user]').forEach(button => {
    button.addEventListener('click', () => {
      const id = button.getAttribute('data-user-id');
      handleUserSelection(id, { forceActivity: true });
    });
  });
}

function renderDetail() {
  const user = state.users.find(item => item.id === state.activeUserId) || null;
  if (!elements.detailPanel || !elements.selectedView || !elements.emptyView) {
    return;
  }

  if (!user) {
    elements.selectedView.classList.add('hidden');
    elements.emptyView.classList.remove('hidden');
    state.formInitialData = null;
    state.userActivity = [];
    renderActivity();
    return;
  }

  elements.selectedView.classList.remove('hidden');
  elements.emptyView.classList.add('hidden');

  const detail = elements.detail;
  if (detail.name) detail.name.textContent = user.name;
  if (detail.email) {
    detail.email.textContent = user.email || '—';
    detail.email.setAttribute('href', user.email ? `mailto:${user.email}` : '#');
  }
  if (detail.id) detail.id.textContent = user.id;
  if (detail.role) {
    detail.role.textContent = user.role;
    detail.role.className = `badge ${roleStyles[user.role] || 'border border-gray-700 text-gray-300 bg-gray-800/40'}`;
  }
  if (detail.status) {
    detail.status.textContent = user.status;
    detail.status.className = `badge ${statusStyles[user.status] || 'border border-gray-700 text-gray-300 bg-gray-800/40'}`;
  }
  if (detail.vip) {
    detail.vip.textContent = `${user.vipTier}`;
    detail.vip.className = `badge ${vipStyles[user.vipTier] || 'border border-gray-700 text-gray-300 bg-gray-800/40'}`;
  }
  if (detail.balance) detail.balance.textContent = formatCurrency(user.balance);
  if (detail.deposits) detail.deposits.textContent = formatCurrency(user.lifetimeDeposits);
  if (detail.wagered) detail.wagered.textContent = formatCurrency(user.lifetimeWagered);
  if (detail.payouts) detail.payouts.textContent = formatCurrency(user.lifetimePayouts);
  if (detail.lastActive) detail.lastActive.textContent = user.lastActive;
  if (detail.location) detail.location.textContent = user.location || '—';
  if (detail.tags) {
    detail.tags.innerHTML = Array.isArray(user.segments) && user.segments.length
      ? user.segments
          .map(segment => `
              <span class="text-[11px] uppercase tracking-[0.3em] text-gray-500 bg-gray-800/70 border border-gray-700/80 rounded-full px-2 py-0.5">${escapeHtml(
                segment
              )}</span>
            `)
          .join('')
      : '<span class="text-[11px] uppercase tracking-[0.3em] text-gray-600">No tags</span>';
  }
  if (detail.cooldown && detail.cooldownText) {
    if (user.cooldownEnds) {
      detail.cooldown.classList.remove('hidden');
      detail.cooldownText.textContent = user.cooldownEnds;
    } else {
      detail.cooldown.classList.add('hidden');
      detail.cooldownText.textContent = '';
    }
  }

  if (!state.formDirty) {
    applyFormValues(user);
  }
  state.formInitialData = extractFormValues();
}

function applyFormValues(user) {
  const form = elements.userForm;
  if (!form) {
    return;
  }
  form.userName.value = user.name || '';
  form.userEmail.value = user.email || '';
  if (form.userRole) selectOption(form.userRole, user.role || 'Player');
  if (form.userStatus) selectOption(form.userStatus, user.status || 'Active');
  if (form.userVip) selectOption(form.userVip, user.vipTier || 'Bronze');
  if (form.userRisk) selectOption(form.userRisk, user.riskLevel || 'Low');
  if (form.userLocation) form.userLocation.value = user.location || '';
  if (form.userBalance) form.userBalance.value = Number(user.balance || 0).toFixed(2);
  if (form.userDeposits) form.userDeposits.value = Number(user.lifetimeDeposits || 0).toFixed(2);
  if (form.userWagered) form.userWagered.value = Number(user.lifetimeWagered || 0).toFixed(2);
  if (form.userPayouts) form.userPayouts.value = Number(user.lifetimePayouts || 0).toFixed(2);
  if (form.userTwoFactor) form.userTwoFactor.checked = Boolean(user.twoFactor);
  if (form.userEmailVerified) form.userEmailVerified.checked = Boolean(user.emailVerified);
  if (form.userPayoutHold) form.userPayoutHold.checked = Boolean(user.payoutHold);
  if (form.userNotes) form.userNotes.value = user.notes || '';
  state.formDirty = false;
}

function extractFormValues() {
  const form = elements.userForm;
  if (!form) {
    return null;
  }
  return {
    name: form.userName?.value?.trim() || '',
    email: form.userEmail?.value?.trim() || '',
    role: form.userRole?.value || 'Player',
    status: form.userStatus?.value || 'Active',
    vipTier: form.userVip?.value || 'Bronze',
    riskLevel: form.userRisk?.value || 'Low',
    location: form.userLocation?.value?.trim() || '',
    balance: Number.parseFloat(form.userBalance?.value || '0') || 0,
    lifetimeDeposits: Number.parseFloat(form.userDeposits?.value || '0') || 0,
    lifetimeWagered: Number.parseFloat(form.userWagered?.value || '0') || 0,
    lifetimePayouts: Number.parseFloat(form.userPayouts?.value || '0') || 0,
    twoFactor: Boolean(form.userTwoFactor?.checked),
    emailVerified: Boolean(form.userEmailVerified?.checked),
    payoutHold: Boolean(form.userPayoutHold?.checked),
    notes: form.userNotes?.value?.trim() || '',
  };
}

function resetFormToInitial() {
  if (!state.formInitialData) {
    return;
  }
  const form = elements.userForm;
  if (!form) {
    return;
  }
  const values = state.formInitialData;
  form.userName.value = values.name;
  form.userEmail.value = values.email;
  if (form.userRole) selectOption(form.userRole, values.role);
  if (form.userStatus) selectOption(form.userStatus, values.status);
  if (form.userVip) selectOption(form.userVip, values.vipTier);
  if (form.userRisk) selectOption(form.userRisk, values.riskLevel);
  if (form.userLocation) form.userLocation.value = values.location;
  if (form.userBalance) form.userBalance.value = Number(values.balance || 0).toFixed(2);
  if (form.userDeposits) form.userDeposits.value = Number(values.lifetimeDeposits || 0).toFixed(2);
  if (form.userWagered) form.userWagered.value = Number(values.lifetimeWagered || 0).toFixed(2);
  if (form.userPayouts) form.userPayouts.value = Number(values.lifetimePayouts || 0).toFixed(2);
  if (form.userTwoFactor) form.userTwoFactor.checked = Boolean(values.twoFactor);
  if (form.userEmailVerified) form.userEmailVerified.checked = Boolean(values.emailVerified);
  if (form.userPayoutHold) form.userPayoutHold.checked = Boolean(values.payoutHold);
  if (form.userNotes) form.userNotes.value = values.notes;
  state.formDirty = false;
}

async function handleUserFormSubmit(event, auth, db) {
  event.preventDefault();
  if (!state.activeUserId) {
    toast.show('Select a player first.', 'warning');
    return;
  }
  const current = state.users.find(item => item.id === state.activeUserId);
  if (!current) {
    toast.show('Player data unavailable. Wait for synchronization.', 'warning');
    return;
  }
  const values = extractFormValues();
  const previous = state.formInitialData || {};
  const updates = {};
  const changes = [];

  const diffFields = ['name', 'email', 'role', 'status', 'vipTier', 'riskLevel', 'location', 'notes'];
  diffFields.forEach(field => {
    if (values[field] !== previous[field]) {
      switch (field) {
        case 'name':
          updates.displayName = values.name;
          break;
        case 'email':
          updates.email = values.email;
          break;
        case 'role':
          updates.role = values.role;
          break;
        case 'status':
          updates.status = values.status;
          break;
        case 'vipTier':
          updates.vipTier = values.vipTier;
          break;
        case 'riskLevel':
          updates.riskLevel = values.riskLevel;
          break;
        case 'location':
          updates.location = values.location;
          break;
        case 'notes':
          updates.notes = values.notes;
          break;
        default:
          break;
      }
      changes.push({ field, before: previous[field], after: values[field] });
    }
  });

  const numericFields = [
    { key: 'balance', field: 'balance' },
    { key: 'lifetimeDeposits', field: 'lifetimeDeposits' },
    { key: 'lifetimeWagered', field: 'lifetimeWagered' },
    { key: 'lifetimePayouts', field: 'lifetimePayouts' },
  ];

  numericFields.forEach(({ key, field }) => {
    const sanitized = Math.max(0, Number(values[key]) || 0);
    if (sanitized !== Math.max(0, Number(previous[key]) || 0)) {
      updates[field] = sanitized;
      changes.push({ field: key, before: previous[key], after: sanitized });
    }
  });

  if (values.twoFactor !== previous.twoFactor) {
    updates.twoFactor = values.twoFactor;
    changes.push({ field: 'twoFactor', before: previous.twoFactor, after: values.twoFactor });
  }
  if (values.emailVerified !== previous.emailVerified) {
    updates.emailVerified = values.emailVerified;
    changes.push({ field: 'emailVerified', before: previous.emailVerified, after: values.emailVerified });
  }
  if (values.payoutHold !== previous.payoutHold) {
    updates.payoutHold = values.payoutHold;
    changes.push({ field: 'payoutHold', before: previous.payoutHold, after: values.payoutHold });
  }

  if (!changes.length) {
    toast.show('No changes detected.', 'info');
    return;
  }

  const userRef = doc(db, 'users', current.id);

  try {
    if (Object.prototype.hasOwnProperty.call(updates, 'balance')) {
      const sanitizedBalance = updates.balance;
      delete updates.balance;
      await runTransaction(db, async transaction => {
        const snapshot = await transaction.get(userRef);
        if (!snapshot.exists()) {
          transaction.set(userRef, {
            balance: sanitizedBalance,
            displayName: values.name,
            email: values.email,
            updatedAt: serverTimestamp(),
          });
        } else {
          transaction.update(userRef, {
            balance: sanitizedBalance,
            updatedAt: serverTimestamp(),
          });
        }
      });
      updates.balance = sanitizedBalance;
    }
    updates.updatedAt = serverTimestamp();
    await updateDoc(userRef, updates);

    await logAuditEvent(db, {
      userId: current.id,
      userName: current.name,
      userEmail: current.email,
      action: 'Profile updated',
      description: `Updated ${changes.length} field${changes.length === 1 ? '' : 's'} for ${current.name}.`,
      tone: 'emerald',
      metadata: { changes },
    });

    toast.show('Profile saved.', 'success');
    applyLocalUserPatch(current.id, {
      name: values.name,
      email: values.email,
      role: values.role,
      status: values.status,
      vipTier: values.vipTier,
      riskLevel: values.riskLevel,
      location: values.location,
      notes: values.notes,
      balance: values.balance,
      lifetimeDeposits: values.lifetimeDeposits,
      lifetimeWagered: values.lifetimeWagered,
      lifetimePayouts: values.lifetimePayouts,
      twoFactor: values.twoFactor,
      emailVerified: values.emailVerified,
      payoutHold: values.payoutHold,
      updatedAt: new Date(),
      lastLoginAt: current.lastLoginAt,
      lastActiveAt: new Date(),
    });
    state.formDirty = false;
    state.formInitialData = values;
  } catch (error) {
    console.error('Failed to save profile', error);
    toast.show('Unable to save changes. Please try again.', 'danger');
  }
}

function renderActivity() {
  if (!elements.activityList) {
    return;
  }
  if (!state.userActivity.length) {
    elements.activityList.innerHTML = '<li class="text-xs text-gray-500">No recent activity recorded yet.</li>';
    return;
  }
  elements.activityList.innerHTML = state.userActivity
    .map(item => `
      <li class="rounded-2xl border border-gray-800/80 bg-black/30 px-4 py-3">
        <p class="text-sm font-medium text-white">${escapeHtml(item.description)}</p>
        <p class="text-[11px] text-gray-500 mt-1 uppercase tracking-[0.3em]">${escapeHtml(item.timestamp)}</p>
      </li>
    `)
    .join('');
}

function renderAudit() {
  if (!elements.auditList) {
    return;
  }
  if (!state.auditEntries.length) {
    elements.auditList.innerHTML = '<p class="text-sm text-gray-500">No audit events recorded yet.</p>';
    return;
  }
  elements.auditList.innerHTML = state.auditEntries
    .map((entry, index) => {
      const tone = toneStyles[entry.tone] || toneStyles.emerald;
      const isLast = index === state.auditEntries.length - 1;
      const metadataSegments = [];
      if (entry.userName) {
        metadataSegments.push(escapeHtml(entry.userName));
      }
      if (entry.userEmail) {
        metadataSegments.push(escapeHtml(entry.userEmail));
      }
      if (entry.performedBy) {
        metadataSegments.push(`by ${escapeHtml(entry.performedBy)}`);
      }
      metadataSegments.push(entry.timestamp);
      return `
        <div class="flex items-start gap-4">
          <div class="relative flex flex-col items-center">
            <span class="flex h-10 w-10 items-center justify-center rounded-full ${tone} text-base font-semibold">${escapeHtml(
              entry.icon
            )}</span>
            <span class="${isLast ? 'hidden' : 'block'} h-full w-px bg-gray-800/70 mt-2"></span>
          </div>
          <div class="flex-1 space-y-1 border border-gray-800/70 bg-black/30 rounded-2xl px-4 py-3">
            <p class="text-sm font-semibold text-white">${escapeHtml(entry.action)}</p>
            <p class="text-xs text-gray-400">${escapeHtml(entry.description)}</p>
            <div class="flex flex-wrap gap-3 text-[11px] uppercase tracking-[0.25em] text-gray-500">
              ${metadataSegments.map(segment => `<span>${segment}</span>`).join('')}
            </div>
          </div>
        </div>
      `;
    })
    .join('');
}

function updateSummary() {
  const totalUsers = state.users.length;
  const totalBalance = state.users.reduce((sum, user) => sum + (Number(user.balance) || 0), 0);
  const weekAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
  const newSignups = state.users.filter(user => user.createdAt && user.createdAt.getTime() >= weekAgo).length;
  const adminCount = state.users.filter(user => user.role === 'Administrator' || user.isAdmin).length;
  const activeNow = state.users.filter(user => user.lastActiveMinutes <= ACTIVE_WINDOW_MINUTES).length;
  const flagged = state.users.filter(
    user =>
      user.status === 'Under Review' ||
      user.status === 'Suspended' ||
      user.payoutHold ||
      user.riskLevel === 'Critical'
  ).length;

  if (elements.summary.totalUsers) elements.summary.totalUsers.textContent = totalUsers.toLocaleString();
  if (elements.summary.totalBalance) elements.summary.totalBalance.textContent = formatCurrency(totalBalance);
  if (elements.summary.newSignups) elements.summary.newSignups.textContent = newSignups.toLocaleString();
  if (elements.summary.adminCount) elements.summary.adminCount.textContent = adminCount.toLocaleString();
  if (elements.summary.activeNow) elements.summary.activeNow.textContent = activeNow.toLocaleString();
  if (elements.summary.flagged) elements.summary.flagged.textContent = flagged.toLocaleString();
  renderActiveUsers();
}

function updateLastSync() {
  if (!elements.lastSyncTarget) {
    return;
  }
  if (!state.lastSync) {
    elements.lastSyncTarget.textContent = '—';
    return;
  }
  elements.lastSyncTarget.textContent = state.lastSync.toLocaleString();
}

async function logAuditEvent(db, { userId, userName, userEmail, action, description, tone = 'emerald', metadata = {} }) {
  const payload = {
    userId: userId || null,
    userName: userName || null,
    userEmail: userEmail || null,
    action,
    description,
    tone,
    metadata,
    performedBy: state.adminProfile?.displayName || state.adminProfile?.email || null,
    performedByEmail: state.adminProfile?.email || null,
    performedByUid: state.adminProfile?.id || state.authUser?.uid || null,
    icon: selectAuditIcon(tone, action),
    createdAt: serverTimestamp(),
  };
  await addDoc(collection(db, 'adminAudit'), payload);
  if (userId) {
    await addDoc(collection(db, 'users', userId, 'activity'), {
      description,
      action,
      tone,
      metadata,
      performedBy: payload.performedBy,
      performedByEmail: payload.performedByEmail,
      timestamp: serverTimestamp(),
    });
  }
}

function selectAuditIcon(tone, action) {
  if (tone === 'rose' || /suspend/i.test(action)) {
    return '⛔';
  }
  if (tone === 'amber' || /call|wellbeing/i.test(action)) {
    return '📞';
  }
  if (tone === 'sky' || /imperson/i.test(action)) {
    return '🛠️';
  }
  if (tone === 'violet' || /summary/i.test(action)) {
    return '📄';
  }
  return '✅';
}

function normalizeUserDoc(snapshot) {
  const data = snapshot.data() || {};
  const createdAt = resolveTimestamp(data.createdAt);
  const lastLoginAt = resolveTimestamp(data.lastLoginAt);
  const updatedAt = resolveTimestamp(data.updatedAt);
  const presenceUpdatedAt = resolveTimestamp(data.lastSeenAt || data.presenceUpdatedAt);
  const rawLastActive =
    resolveTimestamp(data.lastActiveAt) || presenceUpdatedAt || lastLoginAt || updatedAt || createdAt;
  const declaredOnline =
    data.isOnline === true ||
    data.activeNow === true ||
    (typeof data.presence === 'string' && data.presence.toLowerCase() === 'online');
  const computedMinutes = rawLastActive
    ? Math.max(0, Math.round((Date.now() - rawLastActive.getTime()) / 60000))
    : 999999;
  const effectiveOnline = rawLastActive
    ? declaredOnline && Date.now() - rawLastActive.getTime() <= ONLINE_STALE_MINUTES * 60 * 1000
    : declaredOnline;
  const lastActiveMinutes = effectiveOnline ? 0 : computedMinutes;
  const lastActive = effectiveOnline ? 'Online now' : rawLastActive ? timeAgo(rawLastActive) : '—';

  return {
    id: snapshot.id,
    name: data.displayName || data.name || (data.email ? data.email.split('@')[0] : 'Player'),
    email: data.email || '',
    balance: typeof data.balance === 'number' ? data.balance : 0,
    status: data.status || 'Active',
    role: data.role || (data.isAdmin ? 'Administrator' : 'Player'),
    vipTier: data.vipTier || 'Bronze',
    riskLevel: data.riskLevel || 'Low',
    lifetimeDeposits: typeof data.lifetimeDeposits === 'number' ? data.lifetimeDeposits : 0,
    lifetimeWagered: typeof data.lifetimeWagered === 'number' ? data.lifetimeWagered : 0,
    lifetimePayouts: typeof data.lifetimePayouts === 'number' ? data.lifetimePayouts : 0,
    twoFactor: Boolean(data.twoFactor),
    emailVerified: Boolean(data.emailVerified),
    payoutHold: Boolean(data.payoutHold),
    notes: data.notes || '',
    location: data.location || '',
    segments: Array.isArray(data.segments) ? data.segments : Array.isArray(data.tags) ? data.tags : [],
    cooldownEnds: data.cooldownEnds || null,
    createdAt,
    lastLoginAt,
    updatedAt,
    lastActiveAt: rawLastActive,
    lastActiveMinutes,
    lastActive,
    isOnline: Boolean(effectiveOnline),
    isAdmin: data.isAdmin === true,
  };
}

function normalizeAuditDoc(snapshot) {
  const data = snapshot.data() || {};
  const createdAt = resolveTimestamp(data.createdAt) || new Date();
  return {
    id: snapshot.id,
    userId: data.userId || null,
    userName: data.userName || null,
    userEmail: data.userEmail || null,
    action: data.action || 'Update',
    description: data.description || '—',
    tone: data.tone || 'emerald',
    metadata: data.metadata || {},
    performedBy: data.performedBy || data.performedByEmail || 'System',
    icon: data.icon || selectAuditIcon(data.tone, data.action || ''),
    timestamp: createdAt.toLocaleString(),
  };
}

function normalizeActivityDoc(snapshot) {
  const data = snapshot.data() || {};
  const createdAt = resolveTimestamp(data.timestamp || data.createdAt) || new Date();
  return {
    id: snapshot.id,
    description: data.description || data.action || 'Activity recorded',
    timestamp: timeAgo(createdAt),
  };
}

function createToast() {
  const container = elements.toast;
  const messageEl = elements.toastMessage;
  if (!container || !messageEl) {
    return {
      show() {},
      hide() {},
    };
  }
  let timeoutId = null;
  const toneClasses = {
    success: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200',
    danger: 'border-rose-500/40 bg-rose-500/10 text-rose-200',
    warning: 'border-amber-500/40 bg-amber-500/10 text-amber-200',
    info: 'border-sky-500/40 bg-sky-500/10 text-sky-200',
  };

  function hide() {
    container.classList.add('hidden');
    container.classList.remove(...Object.values(toneClasses));
    messageEl.textContent = '';
    if (timeoutId) {
      clearTimeout(timeoutId);
      timeoutId = null;
    }
  }

  function show(message, tone = 'success') {
    container.classList.remove('hidden');
    container.classList.remove(...Object.values(toneClasses));
    const toneClass = toneClasses[tone] || toneClasses.success;
    container.classList.add(toneClass);
    messageEl.textContent = message;
    if (timeoutId) {
      clearTimeout(timeoutId);
    }
    timeoutId = window.setTimeout(() => hide(), 6000);
  }

  return { show, hide };
}

function createGateController() {
  const root = document.querySelector('[data-admin-gate]');
  if (!root) {
    return {
      showLoading() {},
      showLogin() {},
      showUnauthorized() {},
      showError() {},
      close() {},
      loginForm: null,
      loginEmail: null,
      loginPassword: null,
      loginError: null,
      loginSubmit: null,
      resetButton: null,
      retryButton: null,
    };
  }
  const screens = new Map();
  root.querySelectorAll('[data-gate-screen]').forEach(screen => {
    screens.set(screen.getAttribute('data-gate-screen'), screen);
  });
  const loginForm = root.querySelector('[data-admin-login-form]');
  const loginEmail = root.querySelector('[data-admin-login-email]');
  const loginPassword = root.querySelector('[data-admin-login-password]');
  const loginError = root.querySelector('[data-admin-login-error]');
  const loginSubmit = root.querySelector('[data-admin-login-submit]');
  const resetButton = root.querySelector('[data-admin-login-reset]');
  const retryButton = root.querySelector('[data-admin-retry]');
  const unauthorizedMessage = root.querySelector('[data-admin-unauthorized-message]');
  const errorMessage = root.querySelector('[data-admin-error-message]');

  function setScreen(name) {
    root.classList.remove('hidden');
    screens.forEach((screen, key) => {
      if (key === name) {
        screen.classList.remove('hidden');
      } else {
        screen.classList.add('hidden');
      }
    });
  }

  function close() {
    root.classList.add('hidden');
  }

  return {
    showLoading() {
      setScreen('loading');
    },
    showLogin() {
      if (loginEmail && !loginEmail.value) {
        loginEmail.value = ADMIN_EMAIL;
      }
      if (loginError) {
        loginError.classList.add('hidden');
        loginError.textContent = '';
      }
      setScreen('login');
    },
    showUnauthorized(message) {
      if (unauthorizedMessage) {
        unauthorizedMessage.textContent = message;
      }
      setScreen('unauthorized');
    },
    showError(message) {
      if (errorMessage) {
        errorMessage.textContent = message;
      }
      setScreen('error');
    },
    close,
    loginForm,
    loginEmail,
    loginPassword,
    loginError,
    loginSubmit,
    resetButton,
    retryButton,
  };
}

function initNavigation() {
  const balanceTargets = Array.from(document.querySelectorAll('[data-balance]')).map(element => ({
    element,
    fallback: element.getAttribute('data-default-balance') || element.textContent?.trim() || '0.00',
  }));

  function updateBalanceFromStorage() {
    if (!balanceTargets.length) {
      return;
    }
    let storedBalance = null;
    try {
      storedBalance = window.localStorage.getItem(BALANCE_STORAGE_KEY);
    } catch (error) {
      storedBalance = null;
    }
    if (storedBalance == null) {
      balanceTargets.forEach(({ element, fallback }) => {
        element.textContent = fallback;
      });
      return;
    }
    const numericValue = Number.parseFloat(storedBalance);
    if (Number.isFinite(numericValue)) {
      const formatted = formatCurrency(numericValue);
      balanceTargets.forEach(({ element }) => {
        element.textContent = formatted;
      });
    } else {
      balanceTargets.forEach(({ element, fallback }) => {
        element.textContent = fallback;
      });
    }
  }

  updateBalanceFromStorage();
  window.addEventListener('storage', event => {
    if (event.key === BALANCE_STORAGE_KEY) {
      updateBalanceFromStorage();
    }
  });
  document.addEventListener('neonCasinoBalanceUpdated', updateBalanceFromStorage);

  const toggleButton = document.querySelector('[data-mobile-toggle]');
  const mobileMenu = document.querySelector('[data-mobile-menu]');
  if (toggleButton && mobileMenu) {
    const setMenuState = isOpen => {
      mobileMenu.classList.toggle('hidden', !isOpen);
      toggleButton.setAttribute('aria-expanded', String(isOpen));
      const openIcon = toggleButton.querySelector('[data-icon-open]');
      const closedIcon = toggleButton.querySelector('[data-icon-closed]');
      if (openIcon) openIcon.classList.toggle('hidden', !isOpen);
      if (closedIcon) closedIcon.classList.toggle('hidden', isOpen);
      document.body.classList.toggle('overflow-hidden', isOpen);
    };

    toggleButton.addEventListener('click', () => {
      const currentlyOpen = !mobileMenu.classList.contains('hidden');
      setMenuState(!currentlyOpen);
    });

    mobileMenu.querySelectorAll('a, button').forEach(el => {
      el.addEventListener('click', () => setMenuState(false));
    });

    document.addEventListener('keydown', event => {
      if (event.key === 'Escape') {
        setMenuState(false);
      }
    });

    const mq = window.matchMedia('(min-width: 768px)');
    const handleMediaChange = event => {
      if (event.matches) {
        setMenuState(false);
      }
    };
    if (typeof mq.addEventListener === 'function') {
      mq.addEventListener('change', handleMediaChange);
    } else if (typeof mq.addListener === 'function') {
      mq.addListener(handleMediaChange);
    }

    setMenuState(false);
  }
}

function initAOSAndFeather() {
  if (window.AOS) {
    window.AOS.init({ duration: 800, easing: 'ease-in-out', once: true });
  }
  if (window.feather) {
    window.feather.replace();
  }
}

function setNavSignedIn(profile) {
  elements.nav.signedIn.forEach(el => el.classList.remove('hidden'));
  elements.nav.signedOut.forEach(el => el.classList.add('hidden'));
  const name = profile.displayName || profile.email || 'Administrator';
  elements.nav.identityName.forEach(el => {
    el.textContent = name;
  });
  elements.nav.identityEmail.forEach(el => {
    el.textContent = profile.email || '';
  });
}

function setNavSignedOut() {
  elements.nav.signedOut.forEach(el => el.classList.remove('hidden'));
  elements.nav.signedIn.forEach(el => el.classList.add('hidden'));
}

function readFirebaseConfig() {
  const configEl = document.getElementById('firebase-config');
  if (!configEl) {
    console.warn('Firebase configuration script tag not found.');
    return null;
  }
  try {
    const parsed = JSON.parse(configEl.textContent || '{}');
    return validateFirebaseConfig(parsed);
  } catch (error) {
    console.error('Failed to parse Firebase config', error);
    return null;
  }
}

function validateFirebaseConfig(raw) {
  if (!raw || typeof raw !== 'object') {
    return null;
  }
  const config = {};
  Object.keys(raw).forEach(key => {
    const value = raw[key];
    if (value != null) {
      config[key] = typeof value === 'string' ? value.trim() : value;
    }
  });
  const required = ['apiKey', 'authDomain', 'projectId'];
  const missingKey = required.find(key => !config[key]);
  if (missingKey) {
    console.warn(`Firebase configuration missing required key: ${missingKey}`);
    return null;
  }
  return config;
}

function readLocalUserRegistry() {
  try {
    const raw = window.localStorage.getItem(USER_REGISTRY_KEY);
    if (!raw) {
      return [];
    }
    const parsed = JSON.parse(raw);
    return Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.warn('Unable to read cached admin directory', error);
    return [];
  }
}

function serializeDate(value) {
  if (!value) {
    return null;
  }
  try {
    if (typeof value.toDate === 'function') {
      return value.toDate().toISOString();
    }
  } catch (error) {
    return null;
  }
  if (value instanceof Date) {
    return Number.isNaN(value.getTime()) ? null : value.toISOString();
  }
  if (typeof value === 'string') {
    const parsed = new Date(value);
    return Number.isNaN(parsed.getTime()) ? null : parsed.toISOString();
  }
  return null;
}

function writeLocalUserRegistry(users) {
  if (!Array.isArray(users)) {
    return;
  }
  try {
    const payload = users
      .filter(user => user && user.id)
      .map(user => ({
        id: user.id,
        name: user.name || '',
        email: user.email || '',
        balance: Number(user.balance) || 0,
        status: user.status || 'Active',
        role: user.role || (user.isAdmin ? 'Administrator' : 'Player'),
        vipTier: user.vipTier || 'Bronze',
        riskLevel: user.riskLevel || 'Low',
        lifetimeDeposits: Number(user.lifetimeDeposits) || 0,
        lifetimeWagered: Number(user.lifetimeWagered) || 0,
        lifetimePayouts: Number(user.lifetimePayouts) || 0,
        twoFactor: Boolean(user.twoFactor),
        emailVerified: Boolean(user.emailVerified),
        payoutHold: Boolean(user.payoutHold),
        notes: user.notes || '',
        location: user.location || '',
        segments: Array.isArray(user.segments) ? user.segments : [],
        cooldownEnds: user.cooldownEnds || null,
        createdAt: serializeDate(user.createdAt),
        updatedAt: serializeDate(user.updatedAt),
        lastLoginAt: serializeDate(user.lastLoginAt),
        lastActiveAt: serializeDate(user.lastActiveAt),
        isAdmin: Boolean(user.isAdmin),
      }));
    window.localStorage.setItem(USER_REGISTRY_KEY, JSON.stringify(payload));
  } catch (error) {
    console.warn('Unable to cache admin directory', error);
  }
}

function normalizeLocalRegistryRecord(record) {
  if (!record || !record.id) {
    return null;
  }
  const createdAt = resolveTimestamp(record.createdAt);
  const updatedAt = resolveTimestamp(record.updatedAt);
  const lastLoginAt = resolveTimestamp(record.lastLoginAt);
  const reference =
    resolveTimestamp(record.lastActiveAt) ||
    updatedAt ||
    lastLoginAt ||
    createdAt;
  const minutes = reference ? Math.max(0, Math.round((Date.now() - reference.getTime()) / 60000)) : 999999;
  const isOnline = reference ? minutes <= ONLINE_STALE_MINUTES : Boolean(record.isOnline);
  return {
    id: record.id,
    name: record.name || (record.email ? record.email.split('@')[0] : 'Player'),
    email: record.email || '',
    balance: Number(record.balance) || 0,
    status: record.status || 'Active',
    role: record.role || (record.isAdmin ? 'Administrator' : 'Player'),
    vipTier: record.vipTier || 'Bronze',
    riskLevel: record.riskLevel || 'Low',
    lifetimeDeposits: Number(record.lifetimeDeposits) || 0,
    lifetimeWagered: Number(record.lifetimeWagered) || 0,
    lifetimePayouts: Number(record.lifetimePayouts) || 0,
    twoFactor: Boolean(record.twoFactor),
    emailVerified: Boolean(record.emailVerified),
    payoutHold: Boolean(record.payoutHold),
    notes: record.notes || '',
    location: record.location || '',
    segments: Array.isArray(record.segments) ? record.segments : [],
    cooldownEnds: record.cooldownEnds || null,
    createdAt,
    updatedAt,
    lastLoginAt,
    lastActiveAt: reference || null,
    lastActiveMinutes: isOnline ? 0 : minutes,
    lastActive: reference ? (isOnline ? 'Online now' : timeAgo(reference)) : '—',
    isOnline,
    isAdmin: Boolean(record.isAdmin),
  };
}

function loadUsersFromLocalRegistry({ notify = false } = {}) {
  const entries = readLocalUserRegistry();
  if (!entries.length) {
    return false;
  }
  const normalized = entries.map(normalizeLocalRegistryRecord).filter(Boolean);
  if (!normalized.length) {
    return false;
  }
  state.users = normalized;
  state.usersFallback = true;
  state.usersFromLocal = true;
  updateVisibleUsers();
  updateSummary();
  state.lastSync = new Date();
  updateLastSync();
  if (notify && !state.cacheToastShown) {
    toast.show('Showing cached player registry. Connect to Firebase for live updates.', 'warning');
    state.cacheToastShown = true;
  }
  return true;
}

function syncLocalRegistry() {
  if (!state.users.length) {
    return;
  }
  writeLocalUserRegistry(state.users);
}

function applyLocalUserPatch(userId, patch) {
  if (!userId || !patch) {
    return;
  }
  let changed = false;
  state.users = state.users.map(user => {
    if (user.id !== userId) {
      return user;
    }
    changed = true;
    const updated = { ...user };
    if (Object.prototype.hasOwnProperty.call(patch, 'name')) {
      updated.name = patch.name || '';
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'email')) {
      updated.email = patch.email || '';
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'role')) {
      updated.role = patch.role || updated.role;
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'status')) {
      updated.status = patch.status || updated.status;
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'vipTier')) {
      updated.vipTier = patch.vipTier || updated.vipTier;
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'riskLevel')) {
      updated.riskLevel = patch.riskLevel || updated.riskLevel;
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'location')) {
      updated.location = patch.location || '';
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'notes')) {
      updated.notes = patch.notes || '';
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'segments')) {
      updated.segments = Array.isArray(patch.segments) ? patch.segments : [];
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'twoFactor')) {
      updated.twoFactor = Boolean(patch.twoFactor);
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'emailVerified')) {
      updated.emailVerified = Boolean(patch.emailVerified);
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'payoutHold')) {
      updated.payoutHold = Boolean(patch.payoutHold);
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'balance')) {
      updated.balance = Math.max(0, Number(patch.balance) || 0);
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'lifetimeDeposits')) {
      updated.lifetimeDeposits = Math.max(0, Number(patch.lifetimeDeposits) || 0);
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'lifetimeWagered')) {
      updated.lifetimeWagered = Math.max(0, Number(patch.lifetimeWagered) || 0);
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'lifetimePayouts')) {
      updated.lifetimePayouts = Math.max(0, Number(patch.lifetimePayouts) || 0);
    }
    if (Object.prototype.hasOwnProperty.call(patch, 'isAdmin')) {
      updated.isAdmin = Boolean(patch.isAdmin);
    }

    const updatedAt = resolveTimestamp(patch.updatedAt) || updated.updatedAt || new Date();
    updated.updatedAt = updatedAt;
    if (Object.prototype.hasOwnProperty.call(patch, 'lastLoginAt')) {
      updated.lastLoginAt = resolveTimestamp(patch.lastLoginAt) || updated.lastLoginAt || updatedAt;
    }

    const lastActiveReference =
      resolveTimestamp(patch.lastActiveAt) ||
      updatedAt ||
      updated.lastLoginAt ||
      updated.createdAt;
    if (lastActiveReference) {
      const minutes = Math.max(0, Math.round((Date.now() - lastActiveReference.getTime()) / 60000));
      const isOnline =
        typeof patch.isOnline === 'boolean' ? Boolean(patch.isOnline) : minutes <= ONLINE_STALE_MINUTES;
      updated.lastActiveAt = lastActiveReference;
      updated.lastActiveMinutes = isOnline ? 0 : minutes;
      updated.lastActive = isOnline ? 'Online now' : timeAgo(lastActiveReference);
      updated.isOnline = isOnline;
    }
    return updated;
  });

  if (changed) {
    updateVisibleUsers();
    updateSummary();
    syncLocalRegistry();
  }
}

function startPresenceTicker() {
  if (state.presenceIntervalId) {
    return;
  }
  state.presenceIntervalId = window.setInterval(() => {
    if (!state.users.length) {
      return;
    }
    const now = Date.now();
    let changed = false;
    const updatedUsers = state.users.map(user => {
      const reference = user.lastActiveAt || user.lastLoginAt || user.updatedAt || user.createdAt;
      let nextIsOnline = Boolean(user.isOnline);
      if (reference && nextIsOnline && now - reference.getTime() > ONLINE_STALE_MINUTES * 60 * 1000) {
        nextIsOnline = false;
      }
      const minutes = reference ? Math.max(0, Math.round((now - reference.getTime()) / 60000)) : 999999;
      const nextMinutes = nextIsOnline ? 0 : minutes;
      const nextLabel = nextIsOnline ? 'Online now' : reference ? timeAgo(reference) : '—';
      if (
        user.lastActiveMinutes !== nextMinutes ||
        user.lastActive !== nextLabel ||
        user.isOnline !== nextIsOnline
      ) {
        changed = true;
        return {
          ...user,
          isOnline: nextIsOnline,
          lastActiveMinutes: nextMinutes,
          lastActive: nextLabel,
        };
      }
      return user;
    });
    if (changed) {
      state.users = updatedUsers;
      updateVisibleUsers();
      updateSummary();
      syncLocalRegistry();
    }
  }, 60 * 1000);
}

function selectOption(select, value) {
  if (!select) {
    return;
  }
  const option = Array.from(select.options).find(opt => opt.value === value);
  if (option) {
    select.value = option.value;
  } else if (select.options.length) {
    select.value = select.options[0].value;
  }
}

function formatCurrency(value) {
  const numeric = Number(value) || 0;
  return `$${numeric.toLocaleString('en-US', { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
}

function getInitials(name) {
  if (!name) {
    return 'NC';
  }
  const parts = name.trim().split(/\s+/);
  if (parts.length === 1) {
    return parts[0].slice(0, 2).toUpperCase();
  }
  return `${parts[0][0] || ''}${parts[parts.length - 1][0] || ''}`.toUpperCase();
}

function resolveTimestamp(value) {
  if (!value) {
    return null;
  }
  if (typeof value.toDate === 'function') {
    return value.toDate();
  }
  if (value instanceof Date) {
    return value;
  }
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date;
}

function timeAgo(date) {
  if (!(date instanceof Date)) {
    return '—';
  }
  const seconds = Math.floor((Date.now() - date.getTime()) / 1000);
  if (seconds < 45) {
    return 'Just now';
  }
  if (seconds < 90) {
    return '1 minute ago';
  }
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) {
    return `${minutes} minute${minutes === 1 ? '' : 's'} ago`;
  }
  const hours = Math.floor(minutes / 60);
  if (hours < 24) {
    return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  }
  const days = Math.floor(hours / 24);
  if (days < 7) {
    return `${days} day${days === 1 ? '' : 's'} ago`;
  }
  const weeks = Math.floor(days / 7);
  if (weeks < 4) {
    return `${weeks} week${weeks === 1 ? '' : 's'} ago`;
  }
  const months = Math.floor(days / 30);
  if (months < 12) {
    return `${months} month${months === 1 ? '' : 's'} ago`;
  }
  const years = Math.floor(days / 365);
  return `${years} year${years === 1 ? '' : 's'} ago`;
}

function escapeHtml(value) {
  return String(value || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function exportUsersToCsv() {
  if (!state.visibleUsers.length) {
    toast.show('Nothing to export. Try adjusting your filters first.', 'info');
    return;
  }
  const headers = [
    'User ID',
    'Name',
    'Email',
    'Role',
    'Status',
    'VIP Tier',
    'Risk Level',
    'Balance',
    'Lifetime Deposits',
    'Lifetime Wagered',
    'Lifetime Payouts',
    'Two Factor',
    'Email Verified',
    'Payout Hold',
    'Last Active',
  ];
  const rows = state.visibleUsers.map(user => [
    user.id,
    user.name,
    user.email,
    user.role,
    user.status,
    user.vipTier,
    user.riskLevel,
    user.balance,
    user.lifetimeDeposits,
    user.lifetimeWagered,
    user.lifetimePayouts,
    user.twoFactor ? 'Yes' : 'No',
    user.emailVerified ? 'Yes' : 'No',
    user.payoutHold ? 'Yes' : 'No',
    user.lastActive,
  ]);
  const csvContent = [headers, ...rows]
    .map(row => row.map(value => `"${String(value ?? '').replace(/"/g, '""')}"`).join(','))
    .join('\n');
  const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `neon-casino-users-${Date.now()}.csv`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  toast.show('CSV export generated.', 'success');
}

