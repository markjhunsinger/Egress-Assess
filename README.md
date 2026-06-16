# Egress-Assess

A tool for testing egress data detection capabilities. Run a server on one host and a client on another to verify which protocols and data types can exfiltrate data through your network controls.

## Requirements

- Python 3.12+
- Root / Administrator privileges (required for ICMP and DNS raw socket clients)

## Setup

### 1. Create a virtual environment

```bash
python3 -m venv egress-venv
source egress-venv/bin/activate   # Windows: egress-venv\Scripts\activate
pip install -r requirements.txt
```

### 2. Generate an SSL certificate (required for HTTPS)

```bash
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
```

Place `server.pem` in the same directory as `Egress-Assess.py`.

---

## Usage

### Sweep Mode (recommended)

Sweep mode tests all protocols and data types automatically and produces a summary report.

**Server** — start all servers at once:

```bash
sudo python3 Egress-Assess.py --server --sweep --username testuser --password pass123 \
    --sftp-port 2222 --smb-port 8445
```

**Client** — transmit all data types over all protocols:

```bash
sudo python3 Egress-Assess.py --client --sweep --ip <server-ip> \
    --username testuser --password pass123 \
    --sftp-port 2222 --smb-port 8445
```

The client prints a colour-coded matrix showing **Allowed** / **Blocked** per protocol × data type, with a failures section listing error details.

#### Sweep flags

| Flag | Default | Description |
|------|---------|-------------|
| `--sftp-port` | 22 | Override SFTP port (port 22 conflicts with SSH) |
| `--smb-port` | 445 | Override SMB port (port 445 is blocked by AWS and some ISPs) |

---

### Single Protocol Mode

**Server:**

```bash
sudo python3 Egress-Assess.py --server <protocol> --username testuser --password pass123
```

**Client:**

```bash
sudo python3 Egress-Assess.py --client <protocol> --ip <server-ip> \
    --username testuser --password pass123 --datatype <datatype>
```

**Examples:**

```bash
# FTP
sudo python3 Egress-Assess.py --server ftp --username testuser --password pass123
sudo python3 Egress-Assess.py --client ftp --ip 10.0.0.1 --username testuser --password pass123 --datatype creditcard

# HTTPS
sudo python3 Egress-Assess.py --server https
sudo python3 Egress-Assess.py --client https --ip 10.0.0.1 --datatype ssn

# DNS (requires root)
sudo python3 Egress-Assess.py --server dns
sudo python3 Egress-Assess.py --client dns --ip 10.0.0.1 --datatype creditcard

# SFTP on alternate port
sudo python3 Egress-Assess.py --server sftp --username testuser --password pass123 --server-port 2222
sudo python3 Egress-Assess.py --client sftp --ip 10.0.0.1 --username testuser --password pass123 --client-port 2222 --datatype creditcard
```

---

## Supported Protocols

| Protocol | Default Port | Notes |
|----------|-------------|-------|
| ftp | 21 | Username/password required |
| http | 80 | |
| https | 443 | Requires `server.pem` on server |
| smtp | 25 | |
| sftp | 22 | Username/password required; use `--sftp-port 2222` to avoid SSH conflict |
| smb | 445 | Use `--smb-port 8445` on AWS (port 445 blocked at hypervisor) |
| dns | 53 | Requires root; data sent in DNS TXT queries |
| dns_resolved | 53 | Requires root; data sent as DNS A record subdomains |
| icmp | — | Requires root; raw socket |

List all: `python3 Egress-Assess.py --list-clients` / `--list-servers`

## Supported Data Types

| Type | Description |
|------|-------------|
| `creditcard` | Credit card numbers |
| `ssn` | US Social Security Numbers |
| `ni` | UK National Insurance Numbers |
| `identity` | Combination identity data |

List all: `python3 Egress-Assess.py --list-datatypes`

---

## Integrity Verification

The following protocols verify that data arrived on the server intact (detects DLP/SSL-inspection proxies that modify content):

| Protocol | Method |
|----------|--------|
| HTTP/HTTPS | Server returns SHA256 of received data; client compares |
| FTP | Client checks remote file size after upload |
| SFTP | Client checks remote file size after upload |
| SMTP | Server returns SHA256 in 250 response; client compares |
| SMB | Exit code verification only |
| DNS / dns_resolved / ICMP | No verification (fire-and-forget) |

---

## How the Protocols Work

- **FTP** — Data uploaded to the server's `/transfer` share with username/password auth.
- **HTTP/HTTPS** — Data POSTed to `/post_data.php`. HTTPS uses a self-signed certificate.
- **SMTP** — Data placed in email body (or attachment for files) and sent to the server's SMTP listener on port 25. Does not route through your mail server.
- **SFTP** — Data uploaded over SSH file transfer protocol with password auth.
- **SMB** — Data written to a `/TRANSFER` share created by Impacket's SimpleSMBServer.
- **DNS (TXT)** — Data base64-encoded and chunked into DNS TXT queries sent directly to the server IP.
- **DNS (Resolved)** — Data base64-encoded and sent as subdomain lookups (`<data>.yourdomain.com`). Requires an NS record pointing to the server.
- **ICMP** — Data base64-encoded and sent in ICMP Echo Request payloads.

---

## Known Limitations

- **AWS blocks port 445** at the hypervisor level regardless of security group rules. Use `--smb-port 8445` (or any non-445 port) as a workaround.
- **ICMP, DNS, dns_resolved** have no return channel so data integrity cannot be verified.
- **SMTP** verification may produce false negatives if an intermediate relay rewrites message headers significantly.
- DNS and ICMP clients require root for raw socket access.
