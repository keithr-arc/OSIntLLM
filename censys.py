import requests

headers = {"Authorization": "bearer CENSYS_API_KEY", "Accept": "application/vnd.censys.api.v3.host.v1+json"}
print(requests.get("https://api.platform.censys.io/v3/global/asset/host/47.33.210.14", headers=headers).json())
