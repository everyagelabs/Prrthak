import json
import unittest

from controller.review_limits import encoded_size


class ReviewStorageLimits(unittest.TestCase):
    def test_storage_byte_accounting_includes_escaped_unicode_quotes_and_nested_matrices(self):
        value = {"name": "पृथक् 😀 \\\n\"", "targets": [{"sources": ["10.2.3.4/32", "2001:db8::1/128"]}]}
        size = len(json.dumps(value, separators=(",", ":")).encode("utf-8"))
        self.assertEqual(encoded_size(value, size), size)
        with self.assertRaisesRegex(ValueError, "8 MiB bound"):
            encoded_size(value, size - 1)

    def test_bound_is_rejected_before_later_authority_is_serialized(self):
        # Full serialization would reach the unsupported later value. A bounded
        # encoder must stop on the earlier over-budget matrix instead.
        value = {"matrix": "x" * 10000, "later": object()}
        with self.assertRaisesRegex(ValueError, "8 MiB bound"):
            encoded_size(value, 1024)

    def test_empty_record_boundary_is_counted_exactly(self):
        self.assertEqual(encoded_size({}, 2), 2)
        with self.assertRaises(ValueError):
            encoded_size({}, 1)
