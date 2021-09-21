#!/usr/bin/env python3
from boto3 import client
from botocore.config import Config
from botocore.exceptions import ClientError, NoCredentialsError
from click import command, option
from shodan import APIError, Shodan
from time import sleep


def build_region_list():
    """
    Builds a list of all AWS regions

    Args:
        NONE

    Returns:
        regions:
            TYPE: LIST
            INFO: All regions available to an AWS account
    """

    # Sets the region and creates the configuration
    config = Config(region_name="us-east-1")
    ec2 = client("ec2", config=config)

    # Get the region data from AWS
    regions = []
    try:
        response = ec2.describe_regions()

        # Loop through responses and grab the list of regions
        for r in response.get("Regions"):
            region = r.get("RegionName")
            regions.append(region)
    except ClientError as cerr:
        print(f"Error: {cerr}")
    except NoCredentialsError as crderr:
        print(f"Error: {crderr}, ensure you have AWS credentials")

    return regions


def get_ip_addrs(region):
    """
    Gets Elastic IP addresses from an AWS region for an account

    Args:
        region:
            TYPE: String
            INFO: A single AWS region

    Returns:
        ip_addrs:
            TYPE: List
            INFO: Elastic IP addresses found in the region
    """

    # Sets the region and creates the configuration
    # Authentication pieces are inherited from AWS credentials
    config = Config(region_name=region)
    ec2 = client("ec2", config=config)
    filters = [{"Name": "public-ip", "Values": ["*"]}]

    # Get the Elastic IPs from AWS
    try:
        response = ec2.describe_addresses(Filters=filters)
        hosts = response.get("Addresses")
    except ClientError as cerr:
        print(f"Error: {cerr}")
    except NoCredentialsError as crderr:
        print(f"Error: {crderr}, ensure you have AWS credentials")

    # Loop through the hosts and strip only the IP addresses
    ip_addrs = []
    try:
        for host in hosts:
            addr = host.get("PublicIp")
            ip_addrs.append(addr)
    except UnboundLocalError:
        print("Error: No hosts provided.")
    return ip_addrs


def check_shodan(addrs, key, quiet):
    """
    Checks if IP address exists in Shodan's index and lists ports it found for the IP.

    Args:
        addrs:
            TYPE: List
            INFO: IP addresses as strings
        key:
            TYPE: String
            INFO: Shodan API key
        quiet:
            TYPE: Bool
            INFO: Flag to only print relevant entries

    Returns:
        NONE
    """

    # Build the API connection with the API key
    api = Shodan(key)

    # Loop through the IPs and check Shodan
    for addr in addrs:
        try:
            result = api.host(addr)
            ports = result.get("ports")
            print(f"{addr} Found: {ports}")
        except APIError as e:
            if not quiet:
                print(f"{addr} Error: {e}")
        sleep(1)


@command()
@option("-k", "--key", required=True, help="API key for Shodan")
@option(
    "-q",
    "--quiet",
    is_flag=True,
    default=False,
    help="Only prints IPs that are found in Shodan",
)
@option("-r", "--region", default="us-east-1", help="AWS region.")
def cli(key, quiet, region):
    """Compiles a list of Elastic IP addresses and checks to see if they're indexed by Shodan"""

    # Initial empty list of Elastic IPs
    elastic_ip_addrs = []

    # Get Elastic IPs from the specified region
    if region == "all":
        regions = build_region_list()

        # Grab the addresses for each region, add them to list of Elastic IPs
        for r in regions:
            addrs = get_ip_addrs(r)
            elastic_ip_addrs.extend(addrs)

    # Only check a single defined region
    else:
        elastic_ip_addrs = get_ip_addrs(region)

    # Check the IP addresses against Shodan
    check_shodan(elastic_ip_addrs, key, quiet)


if __name__ == "__main__":
    cli()
