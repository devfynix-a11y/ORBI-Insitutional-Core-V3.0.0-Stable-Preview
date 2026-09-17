import assert from 'node:assert/strict';
import { test } from 'node:test';
import { graphql } from 'graphql';

import { createMobileGraphqlSchema } from '../src/routes/public/mobileGraphql.js';

const authenticate = (() => undefined) as any;

test('mobile snapshot remains usable when an optional resolver fails', async () => {
  let transactionFetches = 0;
  const schema = createMobileGraphqlSchema({
    authenticate,
    LogicCore: {
      getBootstrapData: async (_token: string, transactions: Promise<any>) => ({
        startup_status: 'ready',
        transactions: await transactions,
      }),
      getTransactionsPaginated: async () => {
        transactionFetches += 1;
        return [{ id: 'tx-1' }];
      },
    },
    getSupabase: () => null,
    getAdminSupabase: () => null,
  });

  const result = await graphql({
    schema,
    source: `
      query {
        mobileSnapshot {
          dashboard
          transactions
          wealthSummary
          paySafeEscrows
          degraded
        }
      }
    `,
    contextValue: {
      session: { sub: 'user-1' },
      authToken: 'token',
    },
  });

  assert.equal(result.errors, undefined);
  const snapshot = (result.data as any).mobileSnapshot;
  assert.deepEqual(snapshot.dashboard, {
    startup_status: 'ready',
    transactions: [{ id: 'tx-1' }],
  });
  assert.deepEqual(snapshot.transactions, [{ id: 'tx-1' }]);
  assert.equal(transactionFetches, 1);
  assert.deepEqual(snapshot.wealthSummary, {});
  assert.deepEqual(snapshot.paySafeEscrows, []);
  assert.deepEqual(snapshot.degraded, ['wealthSummary', 'paySafeEscrows']);
});
