#!/usr/bin/env python3
from boto3 import client
from botocore.config import Config
from shodan import Shodan, APIError
from time import sleep


config = Config(region_name='us-east-1')
api = Shodan('topsycrets')

ec2 = client('ec2', config=config)
filters = [{'Name': 'public-ip', 'Values': ['*']}
response = ec2.describe_addresses(Filters=filters)
addresses = response['Addresses']
for addr in addresses:
    a = dict(addr)
    try:
        results = api.host(a["PublicIp"])
        print(a["PublicIp"], results['ports'])
    except APIError as e:
        print(a["PublicIp"], f'Error: {e}')
    sleep(2)
