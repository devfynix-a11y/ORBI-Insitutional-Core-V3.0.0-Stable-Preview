import { Request, Response, NextFunction } from 'express';
import { FinancialCore } from '../core/FinancialCoreEngine.js';

/**
 * Middleware to authenticate requests using an API Key (x-api-key header)
 */
export const authenticateApiKey = async (req: Request, res: Response, next: NextFunction) => {
    const apiKey = req.headers['x-api-key'] as string;

    if (!apiKey) {
        return res.status(401).json({ success: false, error: "Missing API Key (x-api-key header required)" });
    }

    try {
        const environment = String(req.headers['x-api-environment'] || '').trim();
        const audience = String(req.headers['x-api-audience'] || '').trim();
        if (!environment || !audience) return res.status(400).json({ success: false, error: 'External API environment and audience headers are required' });
        const subjectUserId = String(req.headers['x-orbi-subject'] || '').trim() || undefined;
        const purpose = String(req.headers['x-orbi-purpose'] || '').trim() || undefined;
        const context = await FinancialCore.validateApiKey(apiKey, {
            environment, audience, requiredScopes: ['wallets:read'], subjectUserId, purpose,
        });

        if (!context) {
            return res.status(401).json({ success: false, error: "Invalid or revoked API Key" });
        }

        // Attach tenant context to the request
        (req as any).tenantId = context.tenantId;
        (req as any).externalApiContext = context;
        next();
    } catch (error: any) {
        console.error("API Key Auth Error:", error);
        res.status(500).json({ success: false, error: "Authentication service error" });
    }
};
