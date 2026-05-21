import requests
host = requests.get("https://internetdb.shodan.io/34.60.61.146").json()
print(host)
