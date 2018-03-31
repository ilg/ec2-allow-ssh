#!/usr/bin/env python3

import ipaddress
from socket import gethostbyname

import boto3
import click
import ipgetter

ec2 = boto3.resource('ec2')


@click.command()
@click.option(
        '--host', prompt='Host', help='Hostname to which to allow access')
@click.option('-v', '--verbose', count=True)
def allow_access(host, verbose):
    myip = ipaddress.ip_address(ipgetter.myip())
    if verbose:
        click.echo('My IP: {}'.format(myip))

    host_ip = gethostbyname(host)
    if verbose:
        click.echo('Host IP: {}'.format(host_ip))

    instances = list(ec2.instances.filter(
        Filters=[
            dict(
                Name='ip-address',
                Values=[host_ip],
                ),
            ],
        ))
    if not instances:
        click.echo('No instances found.')
        click.get_current_context().exit(1)
    if verbose:
        click.echo('{} instance(s) found.'.format(len(instances)))
    if len(instances) > 1:
        click.echo('More than one instance found.')
        click.get_current_context().exit(1)

    instance = instances[0]
    security_groups = list(ec2.security_groups.filter(
        Filters=[
            dict(
                Name='group-id',
                Values=[
                    g['GroupId']
                    for g in instance.security_groups
                    ]
                ),
            ],
        ))

    if verbose:
        click.echo('Security group(s): {}'.format(security_groups))
    if not security_groups:
        click.echo('No security groups found.')
        click.get_current_context().exit(1)

    existing_ssh_allows = [
            ipaddress.ip_network(ip_range['CidrIp'])
            for security_group in security_groups
            for perm in security_group.ip_permissions
            for ip_range in perm['IpRanges']
            if 22 in range(perm['FromPort'], perm['ToPort'] + 1)
            and perm['IpProtocol'] == 'tcp'
            ]
    if verbose:
        click.echo(
                'Existing allowed IP ranges: {}'.format(existing_ssh_allows))

    if any(myip in net for net in existing_ssh_allows):
        click.echo(
                'Your IP address is already allowed to ssh to {}.'.format(
                    host
                    )
                )
        click.get_current_context().exit(0)

    target_sg = security_groups[0]
    if verbose:
        click.echo('Adding allow-ingress rule to {}...'.format(target_sg.id))

    ingress_rule = dict(
            CidrIp='{}/32'.format(myip),
            FromPort=22,
            ToPort=22,
            IpProtocol='tcp',
            )
    target_sg.authorize_ingress(**ingress_rule)
    click.echo('ssh allowed.')
    click.pause(info='Press any key to remove access.')
    if verbose:
        click.echo('Removing allow-ingress rule...')
    target_sg.revoke_ingress(**ingress_rule)
    click.echo('Done.')


if __name__ == '__main__':
    allow_access()
