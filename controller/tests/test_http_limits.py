from concurrent.futures import ThreadPoolExecutor
import unittest

from controller.http_limits import RequestLimits, RateLimited


class HttpLimitTests(unittest.TestCase):
    def test_exact_concurrent_budget_and_replenishment(self):
        clock = [0.0]
        limits = RequestLimits(clock=lambda: clock[0])
        def request(_):
            try:
                limits.check('agent', 'authenticated-uuid')
                return True
            except RateLimited:
                return False
        with ThreadPoolExecutor(max_workers=20) as executor:
            self.assertEqual(sum(executor.map(request, range(100))), 40)
        clock[0] = 1
        self.assertEqual(sum(request(None) for _ in range(20)), 10)

    def test_shared_nat_does_not_share_authenticated_agent_budgets(self):
        limits = RequestLimits(clock=lambda: 0)
        for _ in range(40):
            limits.check('agent', 'server-1')
            limits.check('agent', 'server-2')
        with self.assertRaises(RateLimited):
            limits.check('agent', 'server-1')
        limits.check('agent', 'server-3')

    def test_anonymous_cardinality_is_bounded(self):
        limits = RequestLimits(max_entries=100)
        for index in range(1000):
            limits.check('anonymous', str(index))
        self.assertEqual(len(limits.buckets), 100)

    def test_clock_reversal_does_not_restore_a_budget(self):
        clock = [100.0]
        limits = RequestLimits(clock=lambda: clock[0])
        for _ in range(10):
            limits.check('login', 'peer')
        clock[0] = 90.0
        with self.assertRaises(RateLimited):
            limits.check('login', 'peer')
