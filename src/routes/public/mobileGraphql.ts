import type { RequestHandler, Router } from 'express';
import {
  GraphQLBoolean,
  GraphQLInt,
  GraphQLObjectType,
  GraphQLScalarType,
  GraphQLSchema,
  GraphQLString,
  Kind,
  type ValueNode,
  graphql,
  printSchema,
} from 'graphql';
import { logger } from '../../../backend/infrastructure/logger.js';

type Deps = {
  authenticate: RequestHandler;
  LogicCore: any;
  getSupabase: () => any;
  getAdminSupabase: () => any;
};

const MAX_TRANSACTION_LIMIT = 100;
const MAX_ESCROW_LIMIT = 50;
const mobileGraphqlLogger = logger.child({ component: 'mobile_graphql' });

const clampLimit = (value: unknown, fallback: number, max: number) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(Math.max(Math.trunc(parsed), 1), max);
};

const clampOffset = (value: unknown) => {
  const parsed = Number(value);
  if (!Number.isFinite(parsed)) return 0;
  return Math.max(Math.trunc(parsed), 0);
};

const asNumber = (value: any) => {
  if (typeof value === 'number') return value;
  if (typeof value === 'string') return Number(value.replace(/,/g, '')) || 0;
  return 0;
};

const parseJsonLiteral = (ast: ValueNode): unknown => {
  if (ast.kind === Kind.STRING || ast.kind === Kind.BOOLEAN) return ast.value;
  if (ast.kind === Kind.INT || ast.kind === Kind.FLOAT) return Number(ast.value);
  if (ast.kind === Kind.NULL) return null;
  if (ast.kind === Kind.LIST) return ast.values.map((node) => parseJsonLiteral(node));
  if (ast.kind === Kind.OBJECT) {
    return ast.fields.reduce<Record<string, unknown>>((acc, field) => {
      acc[field.name.value] = parseJsonLiteral(field.value);
      return acc;
    }, {});
  }
  return null;
};

const JsonScalar: GraphQLScalarType = new GraphQLScalarType({
  name: 'JSON',
  description: 'Read-only JSON value returned by ORBI mobile read models.',
  serialize: (value) => value,
  parseValue: (value) => value,
  parseLiteral: parseJsonLiteral,
});

const MobileSnapshotType = new GraphQLObjectType({
  name: 'MobileSnapshot',
  fields: {
    dashboard: { type: JsonScalar },
    transactions: { type: JsonScalar },
    wealthSummary: { type: JsonScalar },
    paySafeEscrows: { type: JsonScalar },
    degraded: { type: JsonScalar },
  },
});

const buildWealthSummary = async (sb: any, userId: string) => {
  if (!sb) throw new Error('DB_OFFLINE');

  const [
    platformVaultsResult,
    walletsResult,
    goalsResult,
    categoriesResult,
    billReservesResult,
    sharedPotsResult,
    userResult,
  ] = await Promise.all([
    sb.from('platform_vaults').select('vault_role,name,balance,currency,metadata,updated_at').eq('user_id', userId),
    sb.from('wallets').select('name,balance,currency,type,management_tier,metadata,updated_at').eq('user_id', userId),
    sb.from('goals').select('current,updated_at').eq('user_id', userId),
    sb.from('categories').select('budget,budget_period,budget_interval,created_at').eq('user_id', userId),
    sb.from('bill_reserves').select('reserve_amount,locked_balance,currency,is_active,status,updated_at').eq('user_id', userId),
    sb.from('shared_pots').select('current_amount,target_amount,currency,status,updated_at').eq('owner_user_id', userId),
    sb.from('users').select('currency').eq('id', userId).maybeSingle(),
  ]);

  const firstError = [
    platformVaultsResult.error,
    walletsResult.error,
    goalsResult.error,
    categoriesResult.error,
    billReservesResult.error,
    sharedPotsResult.error,
    userResult.error,
  ].find(Boolean);
  if (firstError) throw firstError;

  const platformVaults = platformVaultsResult.data || [];
  const wallets = walletsResult.data || [];
  const operatingVault = platformVaults.find(
    (vault: any) => String(vault.vault_role || '').toUpperCase() === 'OPERATING',
  );
  const fallbackOperatingWallet = wallets.find((wallet: any) => {
    const lowType = String(wallet.type || '').toLowerCase();
    const lowTier = String(wallet.management_tier || '').toLowerCase();
    const lowName = String(wallet.name || '').toLowerCase();
    return lowType.includes('internal') || lowTier.includes('sovereign') || lowName.includes('dilpesa');
  });

  const escrowBalance = [
    ...platformVaults.filter((vault: any) => String(vault.vault_role || '').toUpperCase() === 'INTERNAL_TRANSFER'),
    ...wallets.filter((wallet: any) => {
      const lowName = String(wallet.name || '').toLowerCase();
      const lowType = String(wallet.type || '').toLowerCase();
      return lowName.includes('paysafe') ||
        lowName.includes('escrow') ||
        lowType.includes('internal_transfer') ||
        wallet.metadata?.is_secure_escrow === true;
    }),
  ].reduce((sum: number, item: any) => sum + asNumber(item.balance), 0);

  const plannedBudget = (categoriesResult.data || []).reduce(
    (sum: number, category: any) => sum + asNumber(category.budget),
    0,
  );
  const reserveLocked = (billReservesResult.data || [])
    .filter((reserve: any) => reserve.is_active !== false && String(reserve.status || 'ACTIVE').toUpperCase() !== 'ARCHIVED')
    .reduce((sum: number, reserve: any) => sum + asNumber(reserve.locked_balance || reserve.reserve_amount), 0);
  const growingGoals = (goalsResult.data || []).reduce(
    (sum: number, goal: any) => sum + asNumber(goal.current),
    0,
  );
  const sharedPotBalance = (sharedPotsResult.data || [])
    .filter((pot: any) => String(pot.status || 'ACTIVE').toUpperCase() !== 'ARCHIVED')
    .reduce((sum: number, pot: any) => sum + asNumber(pot.current_amount), 0);

  return {
    currency: String(userResult.data?.currency || 'TZS').toUpperCase(),
    operating_balance: asNumber(operatingVault?.balance ?? fallbackOperatingWallet?.balance ?? 0),
    planned_balance: plannedBudget + reserveLocked,
    protected_balance: escrowBalance,
    growing_balance: growingGoals + sharedPotBalance,
    goal_count: (goalsResult.data || []).length,
    budget_count: (categoriesResult.data || []).length,
    linked_wallet_count: wallets.filter((wallet: any) => {
      const lowType = String(wallet.type || '').toLowerCase();
      const lowTier = String(wallet.management_tier || '').toLowerCase();
      return lowType.includes('linked') || lowType.includes('external') || lowTier.includes('linked');
    }).length,
  };
};

const fetchPaySafeEscrows = async (sb: any, userId: string, limit: number, status?: string | null) => {
  if (!sb) throw new Error('DB_OFFLINE');
  let query = sb
    .from('escrow_agreements')
    .select('id,transaction_id,reference_id,sender_id,receiver_id,merchant_id,service_code,amount,currency,status,conditions,metadata,expires_at,created_at,updated_at')
    .or(`sender_id.eq.${userId},receiver_id.eq.${userId}`)
    .order('created_at', { ascending: false })
    .limit(limit);

  if (status && status.trim()) {
    query = query.eq('status', status.trim().toUpperCase());
  }

  const { data, error } = await query;
  if (error) throw error;
  return data || [];
};

export const createMobileGraphqlSchema = (deps: Deps) => new GraphQLSchema({
  query: new GraphQLObjectType({
    name: 'Query',
    fields: {
      mobileSnapshot: {
        type: MobileSnapshotType,
        args: {
          dashboard: { type: GraphQLBoolean, defaultValue: true },
          transactions: { type: GraphQLBoolean, defaultValue: true },
          wealthSummary: { type: GraphQLBoolean, defaultValue: true },
          paySafeEscrows: { type: GraphQLBoolean, defaultValue: true },
          transactionLimit: { type: GraphQLInt, defaultValue: 20 },
          escrowLimit: { type: GraphQLInt, defaultValue: 20 },
        },
        resolve: async (_source, args, context) => {
          const session = context.session;
          const token = context.authToken;
          const sb = deps.getAdminSupabase() || deps.getSupabase();
          const userId = session.sub;
          const include = {
            dashboard: args.dashboard !== false,
            transactions: args.transactions !== false,
            wealthSummary: args.wealthSummary !== false,
            paySafeEscrows: args.paySafeEscrows !== false,
          };

          // Dashboard bootstrap already contains recent transactions. Reuse the
          // same request when both fields are selected so a mobile snapshot does
          // not issue two identical ledger queries under startup load.
          const transactionsPromise = include.transactions
            ? deps.LogicCore.getTransactionsPaginated(
              userId,
              clampLimit(args.transactionLimit, 20, MAX_TRANSACTION_LIMIT),
              0,
            )
            : undefined;

          const bootstrapTransactions = include.transactions
            ? transactionsPromise
            : [];

          const results = await Promise.allSettled([
            include.dashboard
              ? deps.LogicCore.getBootstrapData(token, bootstrapTransactions)
              : Promise.resolve(null),
            transactionsPromise ?? Promise.resolve(null),
            include.wealthSummary ? buildWealthSummary(sb, userId) : Promise.resolve(null),
            include.paySafeEscrows
              ? fetchPaySafeEscrows(sb, userId, clampLimit(args.escrowLimit, 20, MAX_ESCROW_LIMIT))
              : Promise.resolve(null),
          ]);

          const labels = ['dashboard', 'transactions', 'wealthSummary', 'paySafeEscrows'] as const;
          const fallbacks: unknown[] = [{}, [], {}, []];
          const degraded: string[] = [];
          const values = results.map((result, index) => {
            if (result.status === 'fulfilled') return result.value;
            const label = labels[index];
            degraded.push(label);
            mobileGraphqlLogger.warn('mobile_graphql.snapshot_resolver_degraded', {
              resolver: label,
              user_id: userId,
              error: String(result.reason?.message || result.reason || 'UNKNOWN_ERROR'),
            });
            return fallbacks[index];
          });

          return {
            dashboard: values[0],
            transactions: values[1],
            wealthSummary: values[2],
            paySafeEscrows: values[3],
            degraded,
          };
        },
      },
      dashboard: {
        type: JsonScalar,
        resolve: async (_source, _args, context) => deps.LogicCore.getBootstrapData(context.authToken),
      },
      transactions: {
        type: JsonScalar,
        args: {
          limit: { type: GraphQLInt, defaultValue: 50 },
          offset: { type: GraphQLInt, defaultValue: 0 },
        },
        resolve: async (_source, args, context) => deps.LogicCore.getTransactionsPaginated(
          context.session.sub,
          clampLimit(args.limit, 50, MAX_TRANSACTION_LIMIT),
          clampOffset(args.offset),
        ),
      },
      wealthSummary: {
        type: JsonScalar,
        resolve: async (_source, _args, context) => buildWealthSummary(
          deps.getAdminSupabase() || deps.getSupabase(),
          context.session.sub,
        ),
      },
      paySafeEscrows: {
        type: JsonScalar,
        args: {
          limit: { type: GraphQLInt, defaultValue: 20 },
          status: { type: GraphQLString },
        },
        resolve: async (_source, args, context) => fetchPaySafeEscrows(
          deps.getAdminSupabase() || deps.getSupabase(),
          context.session.sub,
          clampLimit(args.limit, 20, MAX_ESCROW_LIMIT),
          args.status,
        ),
      },
    },
  }),
});

export const registerMobileGraphqlRoutes = (v1: Router, deps: Deps) => {
  const schema = createMobileGraphqlSchema(deps);

  v1.get('/graphql/schema', deps.authenticate as any, (_req, res) => {
    res.type('text/plain').send(printSchema(schema));
  });

  v1.post('/graphql', deps.authenticate as any, async (req: any, res) => {
    const query = String(req.body?.query || '').trim();
    if (!query) {
      return res.status(400).json({
        success: false,
        error: 'GRAPHQL_QUERY_REQUIRED',
        message: 'GraphQL query is required.',
      });
    }

    if (/\bmutation\b/i.test(query)) {
      return res.status(405).json({
        success: false,
        error: 'GRAPHQL_MUTATIONS_DISABLED',
        message: 'Mobile GraphQL is read-only. Use audited REST flows for financial actions.',
      });
    }

    try {
      const result = await graphql({
        schema,
        source: query,
        variableValues: req.body?.variables || {},
        operationName: req.body?.operationName,
        contextValue: {
          session: req.session,
          authToken: req.authToken,
        },
      });

      const statusCode = result.errors?.length ? 400 : 200;
      res.status(statusCode).json({
        success: !result.errors?.length,
        ...result,
      });
    } catch (error: any) {
      res.status(500).json({
        success: false,
        error: 'GRAPHQL_EXECUTION_FAILED',
        message: error.message,
      });
    }
  });
};
