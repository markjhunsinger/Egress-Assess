#!/usr/bin/python3

# This tool is designed to be an easy way to test exfiltrating data
# from the network you are currently plugged into.  Used for red or
# blue teams that want to test network boundary egress detection
# capabilities.


import logging
import sys
import threading
import time
from common import helpers
from common import orchestra

def _run_server(server):
    try:
        server.serve()
    except SystemExit:
        pass
    except Exception as e:
        print(f'[!] {server.protocol} server error: {e}')


if __name__ == "__main__":

    logging.getLogger('scapy.runtime').setLevel(logging.ERROR)
    logging.getLogger('pyftpdlib').setLevel(logging.WARNING)
    logging.getLogger('mail.log').setLevel(logging.WARNING)
    logging.getLogger('aiosmtpd.smtp').setLevel(logging.WARNING)
    logging.getLogger('asyncio').setLevel(logging.WARNING)

    helpers.title_screen()

    cli_parsed = helpers.cli_parser()

    the_conductor = orchestra.Conductor()

    # Check if only listing supported server/client protocols or datatypes
    if cli_parsed.list_servers:
        print('[*] Supported server protocols: \n')
        the_conductor.load_server_protocols(cli_parsed)
        for name, server_module in sorted(the_conductor.server_protocols.items()):
            print(f'[+] {server_module.protocol}')
        sys.exit()

    elif cli_parsed.list_clients:
        print('[*] Supported client protocols: \n')
        the_conductor.load_client_protocols(cli_parsed)
        for name, client_module in sorted(the_conductor.client_protocols.items()):
            print(f'[+] {client_module.protocol}')
        sys.exit()

    elif cli_parsed.list_datatypes:
        print('[*] Supported data types: \n')
        the_conductor.load_datatypes(cli_parsed)
        for name, datatype_module in sorted(the_conductor.datatypes.items()):
            print(f'[+] {datatype_module.cli}' + " - (" +
                  datatype_module.description + ")")
        sys.exit()

    elif cli_parsed.list_actors:
        print('[*] Supported malware/APT groups: \n')
        the_conductor.load_actors(cli_parsed)
        for name, datatype_module in sorted(the_conductor.actor_modules.items()):
            print(f'[+] {datatype_module.cli}' + " - (" +
                  datatype_module.description + ")")
        sys.exit()

    if cli_parsed.sweep and cli_parsed.server is not None:
        the_conductor.load_server_protocols(cli_parsed)
        servers = list(the_conductor.server_protocols.values())

        if cli_parsed.sftp_port:
            for s in servers:
                if s.protocol == 'sftp':
                    s.port = cli_parsed.sftp_port

        if cli_parsed.smb_port:
            for s in servers:
                if s.protocol == 'smb':
                    s.port = cli_parsed.smb_port

        errors = helpers.preflight_server_sweep(servers)
        if errors:
            print('[!] Pre-flight checks failed:')
            for err in errors:
                print(f'    [-] {err}')
            sys.exit(1)

        print('[*] Pre-flight checks passed. Starting all servers...\n')
        for server in servers:
            t = threading.Thread(target=_run_server, args=[server], daemon=True)
            t.start()
            port_str = f'on port {server.port}' if hasattr(server, 'port') else '(raw socket)'
            print(f'[+] {server.protocol} server started {port_str}')

        print('\n[*] All servers running. Press Ctrl+C to stop.')
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print('\n[*] Shutting down all servers.')
            sys.exit()

    elif cli_parsed.sweep and cli_parsed.client is not None:
        the_conductor.load_client_protocols(cli_parsed)
        the_conductor.load_datatypes(cli_parsed)

        protocols = list(the_conductor.client_protocols.values())

        if cli_parsed.sftp_port:
            for p in protocols:
                if p.protocol == 'sftp':
                    p.port = cli_parsed.sftp_port

        if cli_parsed.smb_port:
            for p in protocols:
                if p.protocol == 'smb':
                    p.port = cli_parsed.smb_port

        datatypes = list(the_conductor.datatypes.values())
        results = []

        interrupted = False
        try:
            for dtype in datatypes:
                print(f'[*] Generating {dtype.description} data...')
                try:
                    generated_data = dtype.generate_data()
                except Exception as e:
                    for proto in protocols:
                        results.append((proto.protocol, dtype.cli, False, f'Data generation failed: {e}'))
                    continue

                # Truncate to 10KB in sweep — goal is connectivity, not throughput.
                # DNS gets a tighter cap (5KB) because it's packet-per-chunk.
                for proto in protocols:
                    print(f'[*] Transmitting {dtype.cli} via {proto.protocol}...')
                    try:
                        cap = 5000 if proto.protocol in ('dns', 'dns_resolved') else 10000
                        chunk = generated_data[:cap]
                        if proto.protocol in ('http', 'https', 'dns', 'dns_resolved'):
                            data = str.encode(chunk)
                        else:
                            data = chunk
                        proto.transmit(data)
                        results.append((proto.protocol, dtype.cli, True, ''))
                    except SystemExit:
                        results.append((proto.protocol, dtype.cli, False, 'sys.exit() called'))
                    except Exception as e:
                        results.append((proto.protocol, dtype.cli, False, str(e)))
        except KeyboardInterrupt:
            print('\n[!] Sweep interrupted by user.')

        print('\n' + '=' * 60)
        print('[*] Sweep complete.\n')
        col1, col2 = 10, 12
        print(f'{"Protocol":<{col1}} {"Datatype":<{col2}} {"Result"}')
        print(f'{"-"*col1} {"-"*col2} {"-"*8}')
        succeeded = 0
        for proto_name, dtype_cli, success, err in sorted(results):
            status = 'SUCCESS' if success else f'FAILED: {err}'
            marker = '[+]' if success else '[-]'
            print(f'{marker} {proto_name:<{col1}} {dtype_cli:<{col2}} {status}')
            if success:
                succeeded += 1
        print(f'\n[*] {succeeded}/{len(results)} combos succeeded.')
        sys.exit()

    elif cli_parsed.server is not None:
        the_conductor.load_server_protocols(cli_parsed)
        the_conductor.load_actors(cli_parsed)

        # Check if server module is given threat actor vs. normal server
        for actor_path, actor_mod in the_conductor.actor_modules.items():

            # If actor module is what is used, search for the server requirement
            # and load that
            if actor_mod.cli == cli_parsed.server.lower():

                for full_path, server_actor in the_conductor.server_protocols.items():

                    if server_actor.protocol.lower() == actor_mod.server_requirement:
                        server_actor.serve()

        for full_path, server in the_conductor.server_protocols.items():

            if server.protocol == cli_parsed.server.lower():
                server.serve()

    elif cli_parsed.client is not None:
        # load up all supported client protocols and datatypes
        the_conductor.load_client_protocols(cli_parsed)
        the_conductor.load_datatypes(cli_parsed)

        if cli_parsed.file is None:
            # Loop through and find the requested datatype
            for name, datatype_module in the_conductor.datatypes.items():
                if datatype_module.cli == cli_parsed.datatype.lower():
                    generated_data = datatype_module.generate_data()

                    # Once data has been generated, transmit it using the
                    # protocol requested by the user
                    for proto_name, proto_module in the_conductor.client_protocols.items():
                        if proto_module.protocol == cli_parsed.client.lower():
                            # If HTTP or HTTPS protocols, 
                            # encode generated data to utf-8 for POST request
                            if cli_parsed.client == "http" or cli_parsed.client == "https":
                                generated_data = str.encode(generated_data)
                            proto_module.transmit(generated_data)
                            sys.exit()

        else:
            with open(cli_parsed.file, 'rb') as file_data_handle:
                file_data = file_data_handle.read()

            for proto_name, proto_module in the_conductor.client_protocols.items():
                if proto_module.protocol == cli_parsed.client.lower():
                    proto_module.transmit(file_data)
                    sys.exit()

        print("[*] Error: You either didn't provide a valid datatype or client protocol to use.")
        print('[*] Error: Re-run and use --list-datatypes or --list-clients to see possible options.')
        sys.exit()

    elif cli_parsed.actor is not None:
        # Load different threat actors/malware
        the_conductor.load_actors(cli_parsed)

        # Identify the actor to emulate
        for full_path, actor_variant in the_conductor.actor_modules.items():
            if actor_variant.cli == cli_parsed.actor.lower():

                # Check if generating data or using data within the actor module
                if cli_parsed.datatype is not None:
                    the_conductor.load_datatypes(cli_parsed)

                    # Generate the data for the actor to exfil
                    for name, datatype_module in the_conductor.datatypes.items():
                        if datatype_module.cli == cli_parsed.datatype.lower():
                            generated_data = datatype_module.generate_data()

                    actor_variant.emulate(data_to_exfil=generated_data)

                # Instead, use the exfil data within the module
                else:
                    actor_variant.emulate()
