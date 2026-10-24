import unittest

from disposable_postgres import isolated_environment


class DatabaseTests(unittest.TestCase):
    def test_existing_database_and_cookie_are_never_inherited(self):
        parent = dict(
            PGHOST="production",
            PGPASSWORD="secret",
            PGSERVICE="production",
            DATABASE_URL="production",
            RAMA_FP_DATABASE_URL="production",
            RAMA_FP_STORAGE_COOKIE="existing",
            NO_PROXY="elsewhere",
            PATH="/bin",
        )
        child = isolated_environment(parent, "disposable", "owned-container")
        self.assertFalse(any(key.startswith("PG") for key in child))
        self.assertNotIn("RAMA_FP_STORAGE_COOKIE", child)
        for key in (
            "DATABASE_URL",
            "RAMA_FP_DATABASE_URL",
            "RAMA_BROWSER_CAPTURE_DATABASE_URL",
        ):
            self.assertEqual(child[key], "disposable")
        self.assertEqual(child["NO_PROXY"], "127.0.0.1,localhost")
        self.assertEqual(child["PATH"], "/bin")
        self.assertEqual(parent["DATABASE_URL"], "production")


if __name__ == "__main__":
    unittest.main()
