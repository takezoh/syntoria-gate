import { createHash } from 'node:crypto';
import { Firestore, Timestamp, type DocumentReference, type Transaction } from '@google-cloud/firestore';
import type { AdapterPayload } from 'oidc-provider';

const key = (value: string) => createHash('sha256').update(value).digest('hex');
export interface IdentitySession { userId: string; csrf: string; expiresAt: Timestamp }
export interface BrowserSession { userId: string; connectionId: string; csrf: string; createdAt: Timestamp; expiresAt: Timestamp }
export interface LoginState { binding: string; interaction?: string }
export interface BrowserLoginAttempt { appId: string; appName: string; redirectUri: string; deviceLabel: string; stateHash: string; bindingHash: string; createdAt: Timestamp; expiresAt: Timestamp }
export interface BrowserApproval { appId: string; appName: string; redirectUri: string; bindingHash: string; userId: string; csrf: string; deviceLabel: string; createdAt: Timestamp; expiresAt: Timestamp }
export interface Connection { id: string; userId: string; clientId: string; clientName?: string; createdAt: string; revoked: boolean; kind?: 'browser' | 'oauth'; subject?: string; approved?: boolean; deviceLabel?: string }
export interface IssuedBrowserSession { redirectUri: string; connectionId: string }
export interface RegistrationLimits { total: number; perMinute: number }

export const DEFAULT_REGISTRATION_LIMITS: Readonly<RegistrationLimits> = Object.freeze({ total: 1_000, perMinute: 20 });

export class RegistrationLimitError extends Error {
  readonly statusCode = 429;
  readonly message = 'temporarily_unavailable';
  readonly expose = true;
  readonly error_description: string;
  constructor(limit: 'capacity' | 'rate') {
    super('Client registration limit reached');
    this.name = 'RegistrationLimitError';
    this.error_description = limit === 'capacity' ? 'Client registration capacity reached' : 'Client registration rate limit reached';
  }
}

class RegistrationUnavailableError extends Error {
  readonly statusCode = 503;
  readonly message = 'server_error';
  readonly expose = false;
  constructor() { super('Client registration storage unavailable'); this.name = 'RegistrationUnavailableError'; }
}

function activeTimestamp(value: unknown, now: number): value is Timestamp {
  return value instanceof Timestamp && value.toMillis() > now;
}

export class Storage {
  constructor(readonly db: Firestore, private namespace = 'gate', private now: () => number = Date.now, private registrationLimits: Readonly<RegistrationLimits> = DEFAULT_REGISTRATION_LIMITS) {
    if (!/^[a-zA-Z0-9_-]+$/.test(namespace)) throw new Error('Invalid collection namespace');
    if (!Number.isSafeInteger(registrationLimits.total) || registrationLimits.total < 1 || !Number.isSafeInteger(registrationLimits.perMinute) || registrationLimits.perMinute < 1) throw new Error('Invalid registration limits');
  }
  async ready() {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      await Promise.race([
        this.db.doc(`${this.namespace}_health/readiness`).get(),
        new Promise<never>((_, reject) => { timer = setTimeout(() => reject(new Error('Storage readiness timeout')), 2000); }),
      ]);
    } finally { clearTimeout(timer); }
  }
  artifacts(model: string) { return this.db.collection(`${this.namespace}_artifacts`).doc(key(model)).collection('entries'); }
  connection(id: string) { return this.db.collection(`${this.namespace}_connections`).doc(key(id)); }
  private browserSessions() { return this.db.collection(`${this.namespace}_browser_sessions`); }
  private browserLoginAttempts() { return this.db.collection(`${this.namespace}_browser_login_attempts`); }
  private browserApprovals() { return this.db.collection(`${this.namespace}_browser_approvals`); }
  private identitySessions() { return this.db.collection(`${this.namespace}_identity_sessions`); }
  private registrationQuota() { return this.db.collection(`${this.namespace}_dcr_state`).doc('quota'); }
  private registrationRate() { return this.db.collection(`${this.namespace}_dcr_state`).doc('rate'); }
  private grantId(model: string, id: string, payload: AdapterPayload) { return model === 'Grant' ? id : payload.grantId; }
  private async active(tx: Transaction, grantId?: string, allowMissing = false) {
    if (!grantId) return true;
    const snapshot = await tx.get(this.connection(grantId));
    if (!snapshot.exists) return allowMissing;
    return snapshot.get('kind') === 'oauth' && snapshot.get('approved') === true && snapshot.get('revoked') !== true;
  }
  private async upsertClient(id: string, payload: AdapterPayload) {
    const ref = this.artifacts('Client').doc(key(id));
    const quotaRef = this.registrationQuota();
    const rateRef = this.registrationRate();
    const now = this.now();
    try {
      await this.db.runTransaction(async tx => {
        const [previous, quota, rate] = await Promise.all([tx.get(ref), tx.get(quotaRef), tx.get(rateRef)]);
        if (previous.exists) {
          if (JSON.stringify(previous.get('payload')) !== JSON.stringify(payload)) throw new Error('Dynamic client metadata is immutable');
          return;
        }
        const total = quota.get('total') ?? 0;
        const currentWindow = Math.floor(this.now() / 60_000);
        const storedWindow: unknown = rate.get('window');
        const storedRequests: unknown = rate.get('requests');
        if (storedWindow !== undefined && (!Number.isSafeInteger(storedWindow) || (storedWindow as number) < 0)) throw new Error('Invalid registration counters');
        if (storedRequests !== undefined && (!Number.isSafeInteger(storedRequests) || (storedRequests as number) < 0)) throw new Error('Invalid registration counters');
        const window = storedWindow === undefined ? currentWindow : Math.max(storedWindow as number, currentWindow);
        const requests = storedWindow === window ? storedRequests ?? 0 : 0;
        if (!Number.isSafeInteger(total) || total < 0 || !Number.isSafeInteger(currentWindow) || currentWindow < 0 || !Number.isSafeInteger(window)) throw new Error('Invalid registration counters');
        if (total >= this.registrationLimits.total) throw new RegistrationLimitError('capacity');
        if ((requests as number) >= this.registrationLimits.perMinute) throw new RegistrationLimitError('rate');
        tx.create(ref, { id, payload, createdAt: Timestamp.fromMillis(now) });
        tx.set(quotaRef, { total: total + 1 });
        tx.set(rateRef, { window, requests: (requests as number) + 1 });
      });
    } catch (error) {
      if (error instanceof RegistrationLimitError) throw error;
      throw new RegistrationUnavailableError();
    }
  }
  async hasActiveOAuthConnection(id: string, userId: string, clientId: string) {
    const connection = await this.connection(id).get();
    return connection.exists && connection.get('kind') === 'oauth' && connection.get('approved') === true && connection.get('revoked') !== true && connection.get('userId') === userId && connection.get('clientId') === clientId;
  }
  async upsert(model: string, id: string, payload: AdapterPayload, expiresIn?: number) {
    if (model === 'Client') {
      await this.upsertClient(id, payload);
      return;
    }
    const ref = this.artifacts(model).doc(key(id));
    await this.db.runTransaction(async tx => {
      const previous = await tx.get(ref);
      if (!await this.active(tx, this.grantId(model, id, payload), model === 'Grant')) throw new Error('Grant missing or revoked');
      const consumed = previous.get('payload.consumed');
      tx.set(ref, { id, payload: { ...payload, ...(consumed === undefined ? {} : { consumed }) }, expiresAt: Timestamp.fromMillis(this.now() + expiresIn! * 1000) });
    });
  }
  private async read(tx: Transaction, ref: DocumentReference) {
    const document = await tx.get(ref);
    if (!document.exists) return undefined;
    const model = document.ref.parent.parent!.id;
    if (model !== key('Client') && !activeTimestamp(document.get('expiresAt'), this.now())) return undefined;
    const payload = document.get('payload') as AdapterPayload;
    const grantId = model === key('Grant') ? document.get('id') as string : payload.grantId;
    return await this.active(tx, grantId) ? payload : undefined;
  }
  async find(model: string, id: string) { return this.db.runTransaction(tx => this.read(tx, this.artifacts(model).doc(key(id)))); }
  async lookup(model: string, field: 'uid' | 'userCode', value: string) {
    return this.db.runTransaction(async tx => {
      const matches = await tx.get(this.artifacts(model).where(`payload.${field}`, '==', value).limit(1));
      return matches.empty ? undefined : this.read(tx, matches.docs[0]!.ref);
    });
  }
  async consume(model: string, id: string) {
    await this.db.runTransaction(async tx => {
      const ref = this.artifacts(model).doc(key(id));
      const payload = await this.read(tx, ref);
      if (!payload || payload.consumed !== undefined) throw new Error('Artifact already consumed');
      tx.update(ref, { 'payload.consumed': Math.floor(this.now() / 1000) });
    });
  }
  async destroy(model: string, id: string) {
    if (model === 'Grant') return this.revoke(id);
    await this.artifacts(model).doc(key(id)).delete();
  }
  async addConnection(id: string, userId: string, clientId: string, clientName?: string) {
    await this.db.runTransaction(async tx => {
      const ref = this.connection(id);
      const previous = await tx.get(ref);
      if (previous.exists) throw new Error('Connection already exists');
      tx.create(ref, { id, userId, clientId, ...(clientName ? { clientName } : {}), subject: userId, kind: 'oauth', approved: true, createdAt: new Date(this.now()).toISOString(), revoked: false });
    });
  }
  async listConnections(userId: string): Promise<Connection[]> {
    const rows = await this.db.collection(`${this.namespace}_connections`).where('userId', '==', userId).get();
    return rows.docs.map(d => d.data() as Connection).filter(c => !c.revoked).sort((a,b) => b.createdAt.localeCompare(a.createdAt));
  }
  async revoke(id: string, userId?: string) {
    await this.db.runTransaction(async tx => {
      const ref = this.connection(id);
      const previous = await tx.get(ref);
      if (userId && previous.get('userId') !== userId) return;
      // Never expire this guard: outstanding token writes must not recreate access.
      tx.set(ref, { revoked: true }, { merge: true });
    });
  }
  async saveIdentity(id: string, session: Omit<IdentitySession, 'expiresAt'>, ttlSeconds = 86400) {
    const ref=this.identitySessions().doc(key(id));
    await ref.set({ ...session, expiresAt: Timestamp.fromMillis(this.now()+ttlSeconds*1000) });
  }
  async identity(id: string): Promise<IdentitySession | undefined> {
    const ref=this.identitySessions().doc(key(id));
    const snapshot=await ref.get();
    if(!snapshot.exists||!activeTimestamp(snapshot.get('expiresAt'),this.now()))return undefined;
    return snapshot.data() as IdentitySession;
  }
  async saveBrowserLogin(id: string, attempt: Omit<BrowserLoginAttempt,'stateHash'|'createdAt'|'expiresAt'>, ttlSeconds = 600) {
    const now=this.now();
    await this.browserLoginAttempts().doc(key(id)).create({ ...attempt, stateHash:key(id), createdAt:Timestamp.fromMillis(now), expiresAt:Timestamp.fromMillis(now+ttlSeconds*1000) });
  }
  async takeBrowserLogin(id: string, binding: string): Promise<BrowserLoginAttempt | undefined> {
    const ref=this.browserLoginAttempts().doc(key(id));
    return this.db.runTransaction(async tx=>{
      const snapshot=await tx.get(ref);
      if(!snapshot.exists)return undefined;
      const data=snapshot.data() as BrowserLoginAttempt;
      if(!activeTimestamp(data.expiresAt,this.now())||data.stateHash!==key(id)||data.bindingHash!==key(binding))return undefined;
      tx.delete(ref);
      return data;
    });
  }
  async saveBrowserApproval(id: string, approval: Omit<BrowserApproval,'createdAt'|'expiresAt'>, ttlSeconds = 600) {
    const now=this.now();
    await this.browserApprovals().doc(key(id)).create({ ...approval, createdAt:Timestamp.fromMillis(now), expiresAt:Timestamp.fromMillis(now+ttlSeconds*1000) });
  }
  private async readBrowserApproval(tx: Transaction, ref: DocumentReference, binding: string, userId: string) {
    const snapshot=await tx.get(ref);
    if(!snapshot.exists)return undefined;
    const data=snapshot.data() as BrowserApproval & {consumedAt?: Timestamp};
    if(data.consumedAt||!activeTimestamp(data.expiresAt,this.now())||data.bindingHash!==key(binding)||data.userId!==userId)return undefined;
    return data;
  }
  async browserApproval(id: string, binding: string, userId: string): Promise<BrowserApproval | undefined> {
    const ref=this.browserApprovals().doc(key(id));
    return this.db.runTransaction(tx=>this.readBrowserApproval(tx,ref,binding,userId));
  }
  async completeBrowserApproval(id: string, binding: string, userId: string, sessionSecret: string, session: Omit<BrowserSession,'createdAt'|'expiresAt'>, ttlSeconds: number): Promise<IssuedBrowserSession | undefined> {
    const approvalRef=this.browserApprovals().doc(key(id));
    const sessionRef=this.browserSessions().doc(key(sessionSecret));
    const connectionRef=this.connection(session.connectionId);
    return this.db.runTransaction(async tx=>{
      const now=this.now();
      const expiresAt=Timestamp.fromMillis(now+ttlSeconds*1000);
      const [approvalSnapshot,sessionSnapshot,connectionSnapshot]=await Promise.all([tx.get(approvalRef),tx.get(sessionRef),tx.get(connectionRef)]);
      if(!approvalSnapshot.exists||sessionSnapshot.exists||connectionSnapshot.exists)return undefined;
      const approval=approvalSnapshot.data() as BrowserApproval & {consumedAt?: Timestamp};
      if(approval.consumedAt||!activeTimestamp(approval.expiresAt,now)||approval.bindingHash!==key(binding)||approval.userId!==userId)return undefined;
      tx.create(connectionRef,{id:session.connectionId,userId,subject:userId,clientId:'browser',kind:'browser',approved:true,deviceLabel:approval.deviceLabel,createdAt:new Date(now).toISOString(),revoked:false});
      tx.create(sessionRef,{...session,createdAt:Timestamp.fromMillis(now),expiresAt});
      tx.update(approvalRef,{consumedAt:Timestamp.fromMillis(now)});
      return {redirectUri:approval.redirectUri,connectionId:session.connectionId};
    });
  }
  async denyBrowserApproval(id: string, binding: string, userId: string): Promise<string | undefined> {
    const ref=this.browserApprovals().doc(key(id));
    return this.db.runTransaction(async tx=>{
      const now=this.now();
      const approval=await this.readBrowserApproval(tx,ref,binding,userId);
      if(!approval)return undefined;
      tx.update(ref,{consumedAt:Timestamp.fromMillis(now)});
      return approval.redirectUri;
    });
  }
  async browser(id: string): Promise<BrowserSession | undefined> {
    const sessionRef=this.browserSessions().doc(key(id));
    return this.db.runTransaction(async tx=>{
      const sessionSnapshot=await tx.get(sessionRef);
      if(!sessionSnapshot.exists)return undefined;
      const session=sessionSnapshot.data() as BrowserSession;
      if(!activeTimestamp(session.expiresAt,this.now()))return undefined;
      const connectionSnapshot=await tx.get(this.connection(session.connectionId));
      const connection=connectionSnapshot.data();
      if(!connectionSnapshot.exists||connection?.revoked===true||connection?.kind!=='browser'||connection?.approved!==true||connection?.userId!==session.userId)return undefined;
      return session;
    });
  }
  async logoutBrowser(id: string, connectionId: string): Promise<boolean> {
    const sessionRef=this.browserSessions().doc(key(id));
    const connectionRef=this.connection(connectionId);
    return this.db.runTransaction(async tx=>{
      const now=this.now();
      const [sessionSnapshot,connectionSnapshot]=await Promise.all([tx.get(sessionRef),tx.get(connectionRef)]);
      if(!sessionSnapshot.exists||!connectionSnapshot.exists)return false;
      const session=sessionSnapshot.data() as BrowserSession;
      const connection=connectionSnapshot.data();
      if(session.connectionId!==connectionId||!activeTimestamp(session.expiresAt,now)||connection?.revoked===true||connection?.kind!=='browser'||connection?.userId!==session.userId)return false;
      tx.set(connectionRef,{revoked:true},{merge:true});
      tx.delete(sessionRef);
      return true;
    });
  }
  async saveLogin(id: string, state: LoginState) { await this.upsert('LoginState', id, {...state}, 600); }
  async takeLogin(id: string, binding: string): Promise<LoginState | undefined> {
    return this.db.runTransaction(async tx => {
      const ref = this.artifacts('LoginState').doc(key(id));
      const payload = await this.read(tx, ref);
      if (!payload || (payload as unknown as LoginState).binding !== binding) return undefined;
      tx.delete(ref);
      return payload as unknown as LoginState;
    });
  }
}

export function adapter(storage: Storage) {
  return class FirestoreAdapter {
    constructor(private model: string) {}
    async upsert(id: string, payload: AdapterPayload, expiresIn: number) { await storage.upsert(this.model, id, payload, expiresIn); }
    async find(id: string) { return storage.find(this.model, id); }
    async findByUid(uid: string) { return storage.lookup(this.model, 'uid', uid); }
    async findByUserCode(code: string) { return storage.lookup(this.model, 'userCode', code); }
    async consume(id: string) { await storage.consume(this.model, id); }
    async destroy(id: string) { await storage.destroy(this.model, id); }
    async revokeByGrantId(id: string) { await storage.revoke(id); }
  };
}
export function firestore(projectId: string, databaseId: string) {
  return new Firestore({ projectId, databaseId, ignoreUndefinedProperties: true });
}
