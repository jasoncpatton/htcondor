#!/usr/bin/python3

import requests

def fetch_token():
    response = requests.put(
        "http://169.254.169.254/latest/api/token",
        headers={"X-aws-ec2-metadata-token-ttl-seconds": "21600"},
    )
    response.raise_for_status()
    return response.text

def fetch_value(token, attribute):
    response = requests.get(
        f"http://169.254.169.254/latest/meta-data/{attribute}",
        headers={"X-aws-ec2-metadata-token": token},
    )
    response.raise_for_status()
    return response.text

def main():
    classad = {
        "Provider": '"AWS"',
        "Platform": '"EC2"',
    }

    token = fetch_token()
    aws_by_common_map = {
        "Image":        "ami-id",
        "Type":         "instance-type",
        "Zone":         "placement/availability-zone",
        "Region":       "placement/region",
        "InstanceID":   "instance-id"
    }
    for common,aws in aws_by_common_map.items():
        value = fetch_value(token, aws)
        classad[common] = f'"{value}"'

    # Interruptable requires a little more translation.
    classad["Interruptable"] = "False"
    interruptable = fetch_value(token, "instance-life-cycle")
    if interruptable == "spot":
        classad["Interruptable"] = "True"

    for k,v in classad.items():
        print(f"{k}={v}")

    print("- update:true")

if __name__ == "__main__":
    main()
