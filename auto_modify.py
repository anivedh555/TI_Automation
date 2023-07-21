import argparse
import csv
import requests
import json
import base64
import sys

def ibm_xforce_ip_reputation(ip_address, api_key,api_password):
    #url = "https://api.xforce.ibmcloud.com/ipr/" + ip_address
    #data=str({api_key+ ":"+ api_password})
    #data_bytes = data.encode("utf-8")
    #token = base64.b64encode(data_bytes)
    #headers = {'Authorization': "Basic " + token, 'Accept': 'application/json'}
    #headers = {"Authorization": f"Basic {api_key}"}
    auth_string = f"{api_key}:{api_password}"
    encoded_auth_string = base64.b64encode(auth_string.encode()).decode()
    headers = {"Authorization": f"Basic {encoded_auth_string}"}
    url = f"https://api.xforce.ibmcloud.com/ipr/{ip_address}"
    response = requests.get(url, headers=headers)
    data = response.json()
    #print(data.get("geo").get("country"))
    return [data.get("score"), data.get("cats"), data.get("geo").get("country")]

def virustotal_ip_reputation(ip_address, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    response = requests.get(url, headers=headers)
    data = response.json()
    x=data.get("data", {}).get("attributes", {}).get("as_owner")
    return [x,data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {}).get("malicious")]


def ipvoid_ip_reputation(ip_address):
    url = f"http://www.ipvoid.com/ip-blacklist-check/{ip_address}/"
    response = requests.get(url)
    


def main():
    parser = argparse.ArgumentParser(description="IP Reputation Checker")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-ip", metavar="IP", help="Enter Comma seperated IP addresses to check")
    #group.add_argument("-ips", metavar= "IPS" help="Multiple IP addresses to check")
    group.add_argument("-file", metavar="FILE", help="Path to the input CSV file")
    args = parser.parse_args()
    vt_api_key = "a3a51c954f3510216b07430af840e88b3732564786dec3ff3baad2033dfd1b06"
    xforce_api_key = 'e8a1d629-02b0-4214-b4c3-78881c9523ad'
    xforce_api_password= "9bb8cba9-f797-46d0-9ca4-5da6b419233f"


    if args.ip:
        # Comma Seperated IP addresses
        ip_addresses=[]
        ip_addresses=args.ip.split(",")
    elif args.file:
        # Read input from CSV file
        ip_addresses = []
        with open(args.file, "r") as file:
            reader = csv.reader(file)
            next(reader)  # Skip header row
            for row in reader:
                ip_addresses.append(row[0])


    results = []
    for ip_address in ip_addresses:
        vt_score = virustotal_ip_reputation(ip_address, vt_api_key)
        xforce_score = ibm_xforce_ip_reputation(ip_address, xforce_api_key,xforce_api_password)
        results.append({
                "IP Address": ip_address,
                "VirusTotal Score": vt_score[1],
                "IBM X-Force Score": xforce_score[0],
                "Category": xforce_score[1],
                "Country": xforce_score[2],
                "ISP":vt_score[0]
                
                
            })
        #if(int(xforce_score)+ int(vt_score)
        print(f"VirusTotal Score: {vt_score[1]}")
        print(f"IBM X-Force Score: {xforce_score[0]}")
        print(f"Category: {xforce_score[1]}")
        print(f"Country: {xforce_score[2]}")
        print(f"ISP: {vt_score[0]}")
        print()

    # Write results to CSV file
    #output_file = "ip_reputation_scores.csv"
    #with open(output_file, "w", newline="") as file:
    #    writer = csv.writer(file)
    #    writer.writerow(["IP Address", "VirusTotal Score", "IBM X-Force Score", "Category", "Country"])
    #   writer.writerows(results)
    output_file = "ip_reputation_scores.csv"
    with open(output_file, "w", newline="") as file:
        writer = csv.DictWriter(file, fieldnames=["IP Address", "VirusTotal Score", "IBM X-Force Score", "Category", "Country","ISP"])
        writer.writeheader()
        writer.writerows(results)

    #print(f"\nOutput saved to '{output_file}'")

    print(f"Results saved to '{output_file}'")

if __name__ == "__main__":
    main()

