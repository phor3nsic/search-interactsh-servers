# search-interactsh-servers

Scanner for public, **token-less** [Interactsh](https://github.com/projectdiscovery/interactsh)
servers. It queries Shodan, Censys or LeakIX for hosts serving
`<h1>Interactsh Server</h1>`, extracts the associated domains (hostnames /
certificate SAN / CN) and tries to register a client against `/register`
without providing a token. Servers that accept the request are exposing
out-of-band (OOB) subdomains publicly and are listed in the output.

> **Authorized use only.** This tool is intended for security research,
> red/blue-team engagements you are authorized to perform, and CTF / lab
> environments. Do not use it against systems you do not own or have explicit
> permission to test.

## Features

- Multiple discovery sources: **Shodan**, **Censys**, **LeakIX**, or a static
  host list
- RSA 2048 keypair generation for realistic `/register` payloads
- Automatic HTTPS → HTTP fallback per candidate
- Derives base domains from hostnames and TLS certificate CN
- Optional plain-text and JSON output

## Requirements

- Python 3.9+
- Packages listed in [`requirements.txt`](requirements.txt):
  `requests`, `cryptography`, `urllib3`

## Installation

```bash
git clone https://github.com/phor3nsic/search-interactsh-servers.git
cd search-interactsh-servers

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Usage

```text
usage: search_interactsh.py [-h] --source {shodan,censys,leakix,file}
                            [--hosts-file HOSTS_FILE] [--limit LIMIT]
                            [--pages PAGES] [--timeout TIMEOUT]
                            [--output OUTPUT] [--json JSON_OUT]
```

### Environment variables

| Source  | Variables                                    |
| ------- | -------------------------------------------- |
| shodan  | `SHODAN_API_KEY`                             |
| censys  | `CENSYS_API_ID`, `CENSYS_API_SECRET`         |
| leakix  | `LEAKIX_API_KEY` (free at <https://leakix.net/auth>) |
| file    | _none_                                       |

### Examples

Shodan:

```bash
export SHODAN_API_KEY=xxxx
python search_interactsh.py --source shodan --limit 200 \
    --output valid.txt --json details.json
```

LeakIX:

```bash
export LEAKIX_API_KEY=xxxx
python search_interactsh.py --source leakix --pages 5
```

Static list (one host/IP/domain per line):

```bash
python search_interactsh.py --source file --hosts-file candidates.txt
```

### Output legend

- `[OK ]` — `/register` accepted without a token
- `[--]` — request was rejected, errored out, or timed out
- Final summary prints the list of open Interactsh servers

## Project layout

```
.
├── .gitignore
├── LICENSE
├── README.md
├── requirements.txt
└── search_interactsh.py
```

## Disclaimer

This software is provided for educational and authorized security testing
purposes only. The authors are not responsible for any misuse or damage caused
by this program. See [LICENSE](LICENSE) for the full terms.

## License

Released under the [MIT License](LICENSE).
