import requests

url = "https://api.greynoise.io/v3/community/54.245.56.55"

headers = {
  'key': '{{GREYNOISE_API_KEY}}'
}

response = requests.request("GET", url, headers=headers)

print(response.text)
