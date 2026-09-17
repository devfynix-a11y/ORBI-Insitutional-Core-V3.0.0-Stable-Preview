
import { UUID } from '../../services/utils.js';
import { getAdminSupabase, getSupabase } from '../supabaseClient.js';
import { AuditLogEntry, AuditEventType } from '../../types.js';
import { SocketRegistry } from '../infrastructure/SocketRegistry.js';
import { Signatures } from './SignatureService.js';
import { logger } from '../infrastructure/logger.js';
import { withOrbiTransaction } from '../../services/orbiDatabase.js';

export type { AuditEventType };

const auditLogger = logger.child({ component: 'audit_log_service' });
const AUDIT_GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

export const verifyAuditChainLinks = (
    logs: AuditLogEntry[],
    anchorHash = AUDIT_GENESIS_HASH,
): { valid: boolean; report: { failures: string[] } } => {
    let previousHash = anchorHash;
    const failures: string[] = [];
    for (const entry of logs) {
        if (entry.prevHash !== previousHash) failures.push(entry.id);
        previousHash = entry.hash;
    }
    return { valid: failures.length === 0, report: { failures } };
};

/**
 * ORBI IMMUTABLE AUDIT LEDGER (V13.5)
 * Hardened with per-entry verification protocol and direct transaction linkage.
 */
class AuditLogService {
    private logs: AuditLogEntry[] = [];
    private lastHash: string = AUDIT_GENESIS_HASH;
    private integrityAnchorHash: string = AUDIT_GENESIS_HASH;
    private initPromise: Promise<void> | null = null;
    private integrityTimer: any | null = null;
    private logQueue: Promise<void> = Promise.resolve();

    constructor() {
        this.ensureInitialized();
        this.startIntegrityMonitor();
    }

    private startIntegrityMonitor() {
        // Run integrity check every hour
        this.integrityTimer = setInterval(async () => {
            const { valid, report } = await this.verifyIntegrity();
            if (!valid) {
                auditLogger.error('audit.integrity_compromised', { report });
                // In a real system, alert ThreatSentinel or trigger lockdown
                SocketRegistry.broadcast({
                    type: 'SECURITY_ALERT',
                    payload: { level: 'CRITICAL', message: 'Audit chain integrity failure detected.', details: report }
                });
            }
        }, 60 * 60 * 1000);
    }

    private async ensureInitialized() {
        if (!this.initPromise) {
            this.initPromise = this.reconstructChain();
        }
        return this.initPromise;
    }

    private async reconstructChain() {
        const sb = getAdminSupabase() || getSupabase();
        if (!sb) return;

        try {
            // Fetch the last 50 logs from Supabase
            const { data } = await sb.from('audit_trail')
                .select('*')
                .order('timestamp', { ascending: false })
                .order('id', { ascending: false })
                .limit(50);
                
            if (data && data.length > 0) {
                // Reverse to maintain chronological order
                const recentLogs: AuditLogEntry[] = data.reverse().map(d => ({
                    id: d.id, prevHash: d.prev_hash, hash: d.hash, timestamp: d.timestamp,
                    type: d.event_type as AuditEventType, actor_id: d.actor_id || 'system',
                    actor_name: d.metadata?.actor_name || 'ORBI Engine', action: d.action,
                    metadata: d.metadata, signature: d.signature, verificationStatus: 'UNCHECKED',
                    transaction_id: d.transaction_id
                }));
                
                this.logs = recentLogs;
                this.integrityAnchorHash = this.logs[0].prevHash || AUDIT_GENESIS_HASH;
                this.lastHash = this.logs[this.logs.length - 1].hash;
            }
        } catch (e) {
            auditLogger.error('audit.reconstruct_chain_failed', undefined, e);
        }
    }

    private async sha256(message: string): Promise<string> {
        const msgBuffer = new TextEncoder().encode(message);
        const hashBuffer = await crypto.subtle.digest('SHA-256', msgBuffer);
        return Array.from(new Uint8Array(hashBuffer)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    private async signPayload(payload: string): Promise<string> {
        try {
            return await Signatures.sign(payload);
        } catch (e) { 
            auditLogger.error('audit.signing_failed', undefined, e);
            return `signing_fault_${Date.now()}`; 
        }
    }

    public async verifyLogEntry(entry: AuditLogEntry): Promise<boolean> {
        const payload = `${entry.prevHash}|${entry.timestamp}|${entry.type}|${entry.actor_id}|${entry.transaction_id || ''}|${entry.action}|${JSON.stringify(entry.metadata)}`;
        const calculatedHash = await this.sha256(payload);
        if (calculatedHash !== entry.hash) return false;
        await new Promise(r => setTimeout(r, 600)); 
        return true;
    }

    private buildEntry(
        previousHash: string,
        timestamp: string,
        type: AuditEventType,
        actorId: string,
        action: string,
        data: any,
        transactionId?: string | number,
    ): Promise<AuditLogEntry> {
        return (async () => {
            const metadataObj = { ...data, actor_name: data.actor_name || 'ORBI Agent' };
            const id = UUID.generate();
            const payload = `${previousHash}|${timestamp}|${type}|${actorId}|${transactionId || ''}|${action}|${JSON.stringify(metadataObj)}`;
            const hash = await this.sha256(payload);
            const signature = await this.signPayload(payload);
            return {
                id,
                prevHash: previousHash,
                hash,
                timestamp,
                type,
                actor_id: actorId,
                actor_name: metadataObj.actor_name,
                action,
                metadata: metadataObj,
                signature,
                verificationStatus: 'UNCHECKED',
                transaction_id: transactionId,
            };
        })();
    }

    private publishEntry(entry: AuditLogEntry) {
        this.logs.push(entry);
        this.lastHash = entry.hash;
        SocketRegistry.broadcast({ type: 'AUDIT_LOG', payload: entry });
    }

    private async logSerialized(type: AuditEventType, actorId: string, action: string, data: any, transactionId?: string | number) {
        await this.ensureInitialized();
        const sb = getAdminSupabase() || getSupabase();
        const usesLocalPostgres = String(process.env.ORBI_DATA_PROVIDER || '').trim().toLowerCase() === 'local';

        if (usesLocalPostgres && process.env.DATABASE_URL) {
            const entry = await withOrbiTransaction(async (client) => {
                await client.query(`SELECT pg_advisory_xact_lock(hashtext('orbi:audit_trail:chain'))`);
                const head = await client.query<{ hash: string; timestamp: Date }>(
                    'SELECT hash, timestamp FROM public.audit_trail ORDER BY timestamp DESC, id DESC LIMIT 1',
                );
                const previousHash = head.rows[0]?.hash || AUDIT_GENESIS_HASH;
                const previousTimestamp = head.rows[0]?.timestamp
                    ? new Date(head.rows[0].timestamp).getTime()
                    : 0;
                const timestamp = new Date(Math.max(Date.now(), previousTimestamp + 1)).toISOString();
                const candidate = await this.buildEntry(
                    previousHash, timestamp, type, actorId, action, data, transactionId,
                );
                await client.query(
                    `INSERT INTO public.audit_trail
                     (id, prev_hash, hash, timestamp, event_type, actor_id, transaction_id, action, metadata, signature)
                     VALUES ($1::uuid, $2, $3, $4::timestamptz, $5, $6, $7, $8, $9::jsonb, $10)`,
                    [
                        candidate.id, candidate.prevHash, candidate.hash, candidate.timestamp, candidate.type,
                        actorId.length > 30 ? actorId : null, transactionId ? String(transactionId) : null,
                        candidate.action, JSON.stringify(candidate.metadata), candidate.signature,
                    ],
                );
                return candidate;
            });
            this.publishEntry(entry);
            return;
        }

        const entry = await this.buildEntry(
            this.lastHash, new Date().toISOString(), type, actorId, action, data, transactionId,
        );
        if (sb) {
            const { error } = await sb.from('audit_trail').insert({
                id: entry.id, prev_hash: entry.prevHash, hash: entry.hash,
                timestamp: entry.timestamp, event_type: entry.type,
                actor_id: actorId.length > 30 ? actorId : null,
                transaction_id: transactionId ? String(transactionId) : null,
                action: entry.action, metadata: entry.metadata, signature: entry.signature,
            });
            if (error) throw error;
        }
        this.publishEntry(entry);
    }

    public log(type: AuditEventType, actorId: string, action: string, data: any, transactionId?: string | number): Promise<void> {
        const operation = this.logQueue.then(() => this.logSerialized(type, actorId, action, data, transactionId));
        this.logQueue = operation.catch((error) => {
            auditLogger.error('audit.persist_failed', {
                event_type: type,
                action,
                actor_id: actorId,
                transaction_id: transactionId ? String(transactionId) : null,
            }, error);
        });
        return operation;
    }

    public getLogs(): AuditLogEntry[] { return [...this.logs]; }

    public async verifyIntegrity(): Promise<{ valid: boolean, report: { failures: string[] } }> {
        await this.ensureInitialized();
        return verifyAuditChainLinks(this.logs, this.integrityAnchorHash);
    }
}

export const Audit = new AuditLogService();
