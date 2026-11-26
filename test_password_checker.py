import unittest

from password_checker import check_password, entropy_bits, has_repeats, has_sequence

COMMON = {"password", "123456", "qwerty"}


class TestPasswordChecker(unittest.TestCase):
    def test_common_password_is_very_weak(self):
        self.assertEqual(check_password("Password", COMMON).score, 0)

    def test_short_password_capped(self):
        self.assertLessEqual(check_password("aB3$", COMMON).score, 1)

    def test_strong_password(self):
        self.assertGreaterEqual(check_password("Tq7#vLm9!rZx2@Wp", COMMON).score, 3)

    def test_sequence_and_repeats(self):
        self.assertTrue(has_sequence("xyabc1"))
        self.assertTrue(has_sequence("x321y"))
        self.assertFalse(has_sequence("a1b2c3"))
        self.assertTrue(has_repeats("heeello"))
        self.assertFalse(has_repeats("hello"))

    def test_entropy_empty(self):
        self.assertEqual(entropy_bits(""), 0.0)


if __name__ == "__main__":
    unittest.main()
