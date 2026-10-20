from pathlib import Path
import re
import unittest
import yaml

ROOT = Path(__file__).resolve().parents[1]

class RecipeTests(unittest.TestCase):
    def test_recipe_is_pinned_private_and_never_dev_mode(self):
        doc = yaml.safe_load((ROOT / 'runtipi/docker-compose.yml').read_text())
        svc = doc['services']['wizard-cloudflare']
        self.assertRegex(svc['image'], r'@sha256:[0-9a-f]{64}$')
        self.assertEqual(svc['user'], '1000:1000'); self.assertTrue(svc['read_only']); self.assertEqual(svc['cap_drop'], ['ALL'])
        env = svc['environment']
        self.assertNotIn('CF_DEVELOPMENT_MODE', env)
        self.assertEqual(env['DATA_DIR'], '/data/private'); self.assertEqual(env['PORT'], '18805')
        self.assertEqual(env['CF_ALLOW_WRITES'], 'false')
        self.assertEqual(svc['volumes'], ['cloudflare-private-data:/data'])
        self.assertEqual(doc['volumes']['cloudflare-private-data']['name'], 'wizard-cloudflare-private-data')
        self.assertEqual(svc['x-runtipi']['internal_port'], 18805)

    def test_dockerfile_matches_port_and_owns_data(self):
        text = (ROOT / 'app/Dockerfile').read_text()
        self.assertIn('PORT=18805', text); self.assertIn('chown 1000:1000 /data', text); self.assertIn('USER 1000:1000', text)

if __name__ == '__main__':
    unittest.main()
