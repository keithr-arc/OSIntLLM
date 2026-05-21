import requests

url = 'https://api.abuseipdb.com/api/v2/report'

headers = {
    'Key': 'ABUSEIP_API_KEY',
    'Accept': 'application/json'
}

# Payload structured as a form dictionary
payload = {
    'ip': '135.233.112.102',
    'categories': '14,18',
    'comment': 'Automated block: Repeated port scanning and invalid credential submission.'
}

response = requests.post(url, headers=headers, data=payload)

if response.status_code == 200:
    print("Report successful:", response.json())
else:
    print(f"Error {response.status_code}:", response.text)
