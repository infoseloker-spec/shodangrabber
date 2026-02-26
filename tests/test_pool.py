import unittest

from shodan_grabber import ApiKeyPool, KeyState


class ApiKeyPoolTests(unittest.TestCase):
    def test_rotation_uses_all_keys(self):
        pool = ApiKeyPool(
            keys=[KeyState("k1"), KeyState("k2")],
            min_interval=0.0,
            cooldown_seconds=0.1,
        )
        a = pool.get_key().key
        b = pool.get_key().key
        self.assertNotEqual(a, b)

    def test_exhausted_key_skipped(self):
        k1 = KeyState("k1", exhausted=True)
        k2 = KeyState("k2")
        pool = ApiKeyPool(keys=[k1, k2], min_interval=0.0)
        self.assertEqual(pool.get_key().key, "k2")


if __name__ == "__main__":
    unittest.main()
