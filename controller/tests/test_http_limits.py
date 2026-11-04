from concurrent.futures import ThreadPoolExecutor
from ipaddress import IPv4Address
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

    def test_mapped_ipv4_and_ipv6_privacy_addresses_share_their_peer_budget(self):
        for address, equivalent, other in (
            ("192.0.2.1", "::ffff:c000:201", "192.0.2.2"),
            ("2001:db8:1:2::1", "2001:0db8:0001:0002:ffff::1", "2001:db8:1:3::1"),
        ):
            with self.subTest(address=address):
                limits = RequestLimits(clock=lambda: 0)
                for _ in range(10):
                    limits.check("login", address)
                with self.assertRaises(RateLimited):
                    limits.check("login", equivalent)
                limits.check("login", other)

    def test_concurrent_distributed_attempts_cannot_exceed_ceiling_during_peer_churn(self):
        for category in ("login", "enrollment"):
            with self.subTest(category=category):
                rate, burst = RequestLimits.CEILINGS[category]
                clock = [0.0]
                limits = RequestLimits(max_entries=3, clock=lambda: clock[0])

                def request(index):
                    address = str(IPv4Address("198.18.0.1") + index)
                    try:
                        limits.check(category, address)
                    except RateLimited:
                        return False
                    return True

                with ThreadPoolExecutor(max_workers=20) as executor:
                    self.assertEqual(sum(executor.map(request, range(2 * burst))), burst)
                clock[0] = 1 / rate
                self.assertTrue(request(2 * burst))
                self.assertFalse(request(2 * burst + 1))

    def test_peer_denials_do_not_spend_the_remaining_ceiling(self):
        _, burst = RequestLimits.CEILINGS["login"]
        _, peer_burst = RequestLimits.RATES["login"]
        limits = RequestLimits(clock=lambda: 0)
        for _ in range(peer_burst):
            limits.check("login", "192.0.2.1")
        for _ in range(burst):
            with self.assertRaises(RateLimited):
                limits.check("login", "192.0.2.1")
        for index in range(burst - peer_burst):
            limits.check("login", str(IPv4Address("198.18.0.1") + index))
        with self.assertRaises(RateLimited):
            limits.check("login", "192.0.2.2")
