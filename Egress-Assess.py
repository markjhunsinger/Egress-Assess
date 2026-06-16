#!/usr/bin/python3

# This tool is designed to be an easy way to test exfiltrating data
# from the network you are currently plugged into.  Used for red or
# blue teams that want to test network boundary egress detection
# capabilities.


import json
import logging
import os
import sys
import threading
import time
from common import helpers
from common import orchestra

os.umask(0o022)

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
    logging.getLogger('paramiko').setLevel(logging.WARNING)

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

        if cli_parsed.smtp_port:
            for s in servers:
                if s.protocol == 'smtp':
                    s.port = cli_parsed.smtp_port

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

        time.sleep(1)
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

        if cli_parsed.smtp_port:
            for p in protocols:
                if p.protocol == 'smtp':
                    p.port = cli_parsed.smtp_port

        datatypes = list(the_conductor.datatypes.values())
        results = []
        total_combos = len(protocols) * len(datatypes)
        combo_num = 0

        interrupted = False
        try:
            for dtype in datatypes:
                print(f'\n[*] Generating {dtype.description or dtype.cli} data...')
                try:
                    generated_data = dtype.generate_data()
                except Exception as e:
                    for proto in protocols:
                        combo_num += 1
                        results.append((proto.protocol, dtype.cli, 'blocked', f'Data generation failed: {e}'))
                    continue

                # Protocols that verify data integrity end-to-end
                _verified_protos = {'http', 'https', 'ftp', 'sftp', 'smtp', 'smb'}

                # Truncate to 10KB in sweep — goal is connectivity, not throughput.
                # DNS gets a tighter cap (5KB) because it's packet-per-chunk.
                for proto in protocols:
                    combo_num += 1
                    print(f'[{combo_num}/{total_combos}] {dtype.cli.upper()} via {proto.protocol.upper()}...')
                    try:
                        cap = 5000 if proto.protocol in ('dns', 'dns_resolved') else 10000
                        chunk = generated_data[:cap]
                        if proto.protocol in ('http', 'https', 'dns', 'dns_resolved'):
                            data = str.encode(chunk)
                        else:
                            data = chunk
                        proto.transmit(data)
                        status = 'verified' if proto.protocol in _verified_protos else 'unverified'
                        results.append((proto.protocol, dtype.cli, status, ''))
                    except SystemExit:
                        results.append((proto.protocol, dtype.cli, 'blocked', 'sys.exit() called'))
                    except Exception as e:
                        err = str(e)
                        status = 'tampered' if err.startswith('Integrity check failed') else 'blocked'
                        results.append((proto.protocol, dtype.cli, status, err))
        except KeyboardInterrupt:
            print('\n[!] Sweep interrupted by user.')

        # ANSI colors
        G = '\033[92m'   # green
        Y = '\033[93m'   # yellow
        R = '\033[91m'   # red
        B = '\033[1m'    # bold
        C = '\033[96m'   # cyan
        DIM = '\033[2m'  # dim
        X = '\033[0m'    # reset

        # Build result lookup and collect unique protocols/datatypes
        result_map = {}
        for proto_name, dtype_cli, status, err in results:
            result_map.setdefault(proto_name, {})[dtype_cli] = (status, err)

        _display = {
            'dns': 'DNS (TXT)', 'dns_resolved': 'DNS (A)',
            'ftp': 'FTP', 'http': 'HTTP', 'https': 'HTTPS',
            'icmp': 'ICMP', 'sftp': 'SFTP', 'smb': 'SMB', 'smtp': 'SMTP',
        }
        def pname(p): return _display.get(p, p.upper())

        protocols = sorted(result_map.keys())
        dtypes = sorted({d for p in result_map.values() for d in p})

        # Column widths — cells show up to "Unverified" (10 chars)
        p_col = max(len(pname(p)) for p in protocols) + 2
        d_col = max(max(len(d) for d in dtypes), 10) + 2

        width = p_col + (d_col + 1) * len(dtypes) + 2
        bar = '═' * width

        print(f'\n{C}{B}{bar}{X}')
        title = 'EGRESS-ASSESS SWEEP RESULTS'
        print(f'{C}{B}{"  " + title:<{width}}{X}')
        print(f'{C}{B}{bar}{X}\n')

        # Header row
        header = f'{B}{"Protocol":<{p_col}}{X}'
        for d in dtypes:
            header += f' {C}{B}{d.upper():<{d_col}}{X}'
        print(header)
        print(DIM + '─' * p_col + ('─' * (d_col + 1)) * len(dtypes) + X)

        # Data rows
        succeeded = 0
        for proto in protocols:
            row = f'{B}{pname(proto):<{p_col}}{X}'
            for d in dtypes:
                if d in result_map[proto]:
                    st, _ = result_map[proto][d]
                    if st == 'verified':
                        row += f' {G}{"Allowed ✓":<{d_col}}{X}'
                        succeeded += 1
                    elif st == 'unverified':
                        row += f' {Y}{"Allowed ~":<{d_col}}{X}'
                        succeeded += 1
                    elif st == 'tampered':
                        row += f' {Y}{"Tampered":<{d_col}}{X}'
                    else:
                        row += f' {R}{"Blocked":<{d_col}}{X}'
                else:
                    row += f' {DIM}{"N/A":<{d_col}}{X}'
            print(row)

        print(f'\n{DIM}  ✓ = verified intact   ~ = allowed, no verification   Tampered = modified in transit{X}')

        # Failures / tampered detail
        issues = [(p, d, st, e) for p, d, st, e in
                  [(p, d, *result_map[p][d]) for p in protocols for d in dtypes if d in result_map[p]]
                  if st in ('blocked', 'tampered')]
        if issues:
            print(f'\n{B}Issues{X}')
            print(DIM + '─' * 50 + X)
            for p, d, st, e in issues:
                label = f'{R}Blocked{X}' if st == 'blocked' else f'{Y}Tampered{X}'
                truncated = e[:80] + '…' if len(e) > 80 else e
                print(f'  {label}  {pname(p)} / {d.upper()}  {DIM}→{X}  {truncated}')

        total = len(results)
        pct = int(succeeded / total * 100) if total else 0
        print(f'\n{B}{succeeded}/{total}{X} combinations allowed {DIM}({pct}%){X}\n')

        if cli_parsed.json_out:
            import datetime
            payload = {
                'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
                'summary': {'allowed': succeeded, 'total': total, 'pct': pct},
                'results': [
                    {'protocol': p, 'datatype': d, 'status': s, 'error': e}
                    for p, d, s, e in results
                ],
            }
            with open(cli_parsed.json_out, 'w') as jf:
                json.dump(payload, jf, indent=2)
            print(f'[*] Results written to {cli_parsed.json_out}')

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
