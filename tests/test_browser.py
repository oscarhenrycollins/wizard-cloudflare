import os, subprocess, tempfile, threading, unittest
from pathlib import Path
from http.server import ThreadingHTTPServer
from unittest import mock
from test_service import server, FakeTransport

class BrowserSmoke(unittest.TestCase):
 def test_disconnected_browser_fixture(self):
  with tempfile.TemporaryDirectory() as temporary,mock.patch.dict(os.environ,{'CF_DEVELOPMENT_MODE':'loopback-single-owner','WIZARD_OWNER_TOKEN':'','WIZARD_ADMIN_TOKEN':'','CF_OAUTH_CLIENT_ID':'c','CF_OAUTH_SCOPE':'s','CF_OAUTH_REDIRECT_URI':'http://127.0.0.1/oauth/callback'}):
   server.DATA=Path(temporary); server.SERVICE=server.Service(FakeTransport(),server.SecretStore()); httpd=ThreadingHTTPServer(('127.0.0.1',0),server.Handler); port=httpd.server_address[1]; host=f'127.0.0.1:{port}'; origin=f'http://{host}'; server.TRUSTED_HOSTS.add(host); server.TRUSTED_ORIGINS.add(origin); server.LOCAL_HOSTS.add(host); thread=threading.Thread(target=httpd.serve_forever,daemon=True); thread.start()
   try:
    result=subprocess.run(['node',str(Path(__file__).with_name('browser-smoke.mjs')),origin],text=True,capture_output=True,timeout=30)
    self.assertEqual(result.returncode,0,result.stdout+'\n'+result.stderr); self.assertIn('browser smoke ok',result.stdout)
   finally:httpd.shutdown(); httpd.server_close(); thread.join()

if __name__=='__main__':unittest.main()
