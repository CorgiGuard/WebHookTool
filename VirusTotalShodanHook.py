import requests
import json

# Ask for an IP address to provide
ip_address = input("Please enter an IP address: ")

# Check this IP against VirusTotal to see if it comes back with any malicious indicators
# Set the base URL for the VirusTotal API
vt_base_url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
vt_params = {"ip": ip_address, "apikey": ""}
# Make the VirusTotal API request and store the response
vt_response = requests.get(vt_base_url, params=vt_params)
if vt_response.status_code == 200:
    vt_data = json.loads(vt_response.text)
    # Check if the IP has any malicious indicators
    if vt_data.get("detected_urls"):
        message = f"This IP has been flagged as malicious by VirusTotal.\n"
    else:
        message = f"This IP has not been flagged as malicious by VirusTotal.\n"
else:
    message = f"Error in getting the data from VirusTotal, status code : {vt_response.status_code}\n"

#Run the IP through Shodan to grab ports open and any other relevant information
shodan_base_url = f"https://api.shodan.io/shodan/host/{ip_address}?key={''}"

#Make the Shodan API request and store the response
shodan_response = requests.get(shodan_base_url)
if shodan_response.status_code == 200:
    shodan_data = json.loads(shodan_response.text)
# Extract the relevant information from the response
    ports = shodan_data.get("ports")
    message += f"Ports open on {ip_address}: {ports}"
else:
    message += f"Error in getting the data from Shodan, status code : {shodan_response.status_code} \n"

#Format the message as a card to be sent to the Teams channel
teams_message = {
"@type": "MessageCard",
"@context": "http://schema.org/extensions",
"themeColor": "0072C6",
"title": "IP Address Information",
"text": message
}

#Send the message to the Teams channel using the webhook URL
webhook_url = ""
teams_response = requests.post(webhook_url, json=teams_message)

print(teams_response.status_code)