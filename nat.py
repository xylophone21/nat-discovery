import argparse
import logging
from termcolor import colored

import discovery

def make_argument_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument(
        '-d', '--debug', action='store_true',
        help='enable debug logging'
    )
    parser.add_argument(
        '-H', '--stun-host',
        help='STUN host to use'
    )
    parser.add_argument(
        '-P', '--stun-port', type=int,
        default=discovery.DEFAULTS['stun_port'],
        help='STUN host port to use'
    )
    parser.add_argument(
        '-i', '--source-ip',
        default=discovery.DEFAULTS['source_ip'],
        help='network interface for client'
    )
    parser.add_argument(
        '-p', '--source-port', type=int,
        default=discovery.DEFAULTS['source_port'],
        help='port to listen on for client'
    )
    parser.add_argument(
        '--version', action='version', version=discovery.__version__
    )
    return parser


def main():
    try:
        options = make_argument_parser().parse_args()

        logging.basicConfig(format='- %(asctime)-15s %(message)s')
        discovery.log.setLevel(logging.DEBUG if options.debug else logging.INFO)

        print(colored('- Discovering NAT type (it may take 5 to 60 seconds) ...','cyan'))
        nat_type_classic, external_ip, external_port = discovery.get_ip_info(
            source_ip=options.source_ip,
            source_port=options.source_port,
            stun_host=options.stun_host,
            stun_port=options.stun_port,
            typ=discovery.DiscoveryType.classic
        )

        nat_type_mapping, _, _ = discovery.get_ip_info(
            source_ip=options.source_ip,
            source_port=options.source_port,
            stun_host=options.stun_host,
            stun_port=options.stun_port,
            typ=discovery.DiscoveryType.mapping
        )

        nat_type_filter, _, _ = discovery.get_ip_info(
            source_ip=options.source_ip,
            source_port=options.source_port,
            stun_host=options.stun_host,
            stun_port=options.stun_port,
            typ=discovery.DiscoveryType.filter
        )
        print('{}\n'.format('-' * 60))
        print(colored('\tNAT Type classic: {}'.format(nat_type_classic), 'magenta'))
        print(colored('\tNAT Type mapping: {}'.format(nat_type_mapping), 'magenta'))
        print(colored('\tNAT Type filter: {}'.format(nat_type_filter), 'magenta'))
        print('\tExternal IP: {}'.format(external_ip))
        print('\tExternal Port: {}'.format(external_port))
        print('\n{}'.format(('-' * 60)))

    except KeyboardInterrupt:
        pass

if __name__ == '__main__':
    main()
