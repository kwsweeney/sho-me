#!/usr/bin/env python3
from boto3 import client
from botocore.config import Config
import click
from shodan import Shodan, APIError
from time import sleep


def get_ip_addrs(region):
    """Gets Elastic IP addresses from an AWS region for an account"""

    # Sets the region and creates the configuration
    # Authentication pieces are inherited from AWS credentials
    config = Config(region_name=region)
    ec2 = client('ec2', config=config)
    filters = [{'Name': 'public-ip', 'Values': ['*']}]

    # Get the Elastic IPs from AWS
    response = ec2.describe_addresses(Filters=filters)
    hosts = response.get('Addresses')

    # Loop through the hosts and strip only the IP addresses
    ip_addrs = []
    for host in hosts:
        addr = host.get('PublicIp')
        ip_addrs.append(addr)
    return ip_addrs


def check_shodan(addrs, key, quiet):
    """Checks if IP address exists in Shodan's index and lists ports it found for the IP."""

    # Build the API connection with the API key
    api = Shodan(key)

    # Loop through the IPs and check Shodan
    for addr in addrs:
        try:
            result = api.host(addr)
            ports = result.get('ports')
            print(f"{addr} Found: {ports}")
        except APIError as e:
            if not quiet:
                print(f"{addr} Error: {e}")
        sleep(1)


@click.command()
@click.option('-k', '--key', required=True, help='API key for Shodan')
@click.option('-q', '--quiet', is_flag=True, default=False, help='Only prints IPs that are found in Shodan')
@click.option('-r', '--region', default='us-east-1', help='AWS region.')
def cli(key, quiet, region):
    """Compiles a list of Elastic IP addresses and checks to see if they're indexed by Shodan"""

    # Get Elastic IPs from the specified region
    if region == 'all':
        regions = ['us-east-1', 'us-east-2', 'us-west-1', 'us-west-2']
        elastic_ip_addrs = []
        for region in regions:
            ips = get_ip_addrs(region)
            for ip in ips:
                elastic_ip_addrs.append(ip)
    else:
        elastic_ip_addrs = get_ip_addrs(region)

    # Check the IP addresses against Shodan
    check_shodan(elastic_ip_addrs, key, quiet)


if __name__ == '__main__':
    cli()