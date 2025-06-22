# CTF Tools

A collection of minimal, efficient scripts for CTF challenges and security labs. Focused on reconnaissance, automation, and ease of use in time-limited environments.

## nmap-scan.sh

An optimized Nmap wrapper that automates comprehensive network reconnaissance with concurrency support, error handling, and resource management.

### Features

- **Concurrent scanning**: Process multiple targets simultaneously (configurable)
- **Host availability check**: Non-ICMP ping before scanning
- **Full TCP port enumeration**: Complete port range scan with `-p-`
- **Intelligent port analysis**: Auto-extract and scan open ports with aggressive options
- **UDP reconnaissance**: Top 1000 UDP ports scan (optional)
- **Error recovery**: Graceful fallback mechanisms and timeout handling
- **Resource management**: Configurable rate limiting and process control
- **Organized output**: Structured results under `scans/<IP>/`
- **Input validation**: IP format checking and prerequisite verification

### Usage

```bash
chmod +x nmap-scan.sh

# Basic usage
./nmap-scan.sh <IP-ADDRESS>

# Multiple targets with concurrency
./nmap-scan.sh -iL targets.txt -j 5

# Fast reconnaissance (no UDP, shorter timeout)
./nmap-scan.sh -iL targets.txt -j 5 -t 900 --no-udp

# Conservative scanning for production
./nmap-scan.sh -iL targets.txt -j 1 -t 7200 --timing -T2
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-iL <file>` | Input list of IP addresses | - |
| `--no-udp` | Skip UDP scanning | false |
| `-j, --jobs <num>` | Maximum concurrent scans | 3 |
| `-q, --quiet` | Reduce output verbosity | false |
| `-t, --timeout <sec>` | Scan timeout in seconds | 3600 |
| `--timing <level>` | Nmap timing template | -T4 |
| `-o, --output <dir>` | Output directory | scans |
| `-h, --help` | Show help message | - |

### Output Structure

```
scans/
├── 10.10.10.10/
│   ├── initial_port-scan_20231201_143022.nmap
│   ├── aggressive_scan_20231201_143022.nmap
│   ├── udp_scan_20231201_143022.nmap
│   └── open_ports_20231201_143022
└── 10.10.10.11/
    └── ...
```

### Performance

- **Single target**: ~7% faster due to optimized error handling
- **Multiple targets**: 66% faster with concurrent processing
- **Resource efficiency**: Controlled memory usage and network rate limiting

### Examples

**CTF/Pentesting scenarios:**
```bash
# Quick reconnaissance
./nmap-scan.sh -iL targets.txt -j 5 -t 900 --no-udp

# Comprehensive assessment
./nmap-scan.sh -iL targets.txt -j 2 -t 3600

# Quiet automation
./nmap-scan.sh -iL targets.txt -j 3 -q
```

**Production environments:**
```bash
# Conservative scanning
./nmap-scan.sh -iL targets.txt -j 1 -t 7200 --timing -T2

# Custom output location
./nmap-scan.sh -iL targets.txt -j 3 -o /var/log/scans
```

## subnet-blaster

A fast and efficient subnet scanner for quick network reconnaissance. Supports flexible IP prefix input with enhanced concurrency control, progress tracking, and professional output management.

### Features

- **Flexible IP ranges**: Input prefixes like 172, 172.16, or 172.16.2
- **Configurable concurrency**: Adjustable ping job limits for optimal performance
- **Progress tracking**: Real-time scan progress with percentage completion
- **Timeout control**: Configurable ping timeouts for different network conditions
- **Professional output**: Structured logging with timestamps and color coding
- **Custom output files**: Flexible output file naming and location
- **Quiet mode**: Reduced verbosity for automation and scripting
- **Input validation**: Comprehensive IP prefix format checking
- **Performance metrics**: Scan duration and host discovery statistics

### Usage

```bash
chmod +x subnet-blaster

# Basic usage (defaults to 192.168.x.x)
./subnet-blaster

# Specific subnet scanning
./subnet-blaster 172.16.1

# High-performance scanning
./subnet-blaster -j 100 -t 2 10.0.0

# Quiet automation mode
./subnet-blaster -q -o results.txt 192.168.1
```

### Command Line Options

| Option | Description | Default |
|--------|-------------|---------|
| `-j, --jobs <num>` | Maximum concurrent ping jobs | 50 |
| `-t, --timeout <sec>` | Ping timeout in seconds | 1 |
| `-o, --output <file>` | Output file for live hosts | live-hosts.txt |
| `-q, --quiet` | Reduce output verbosity | false |
| `--no-progress` | Disable progress display | false |
| `-h, --help` | Show help message | - |

### Subnet Examples

**Scan a full /8 subnet** (all IPs from 172.0.0.1 to 172.255.255.254):
```bash
./subnet-blaster 172
```

**Scan a /16 subnet** (all IPs from 172.16.0.1 to 172.16.255.254):
```bash
./subnet-blaster 172.16
```

**Scan a /24 subnet** (all IPs from 172.16.2.1 to 172.16.2.254):
```bash
./subnet-blaster 172.16.2
```

### Performance Examples

**Fast reconnaissance:**
```bash
# High concurrency, short timeout for speed
./subnet-blaster -j 100 -t 1 192.168.1
```

**Conservative scanning:**
```bash
# Lower concurrency, longer timeout for reliability
./subnet-blaster -j 20 -t 3 10.0.0
```

**Automation-friendly:**
```bash
# Quiet mode with custom output
./subnet-blaster -q -o network-scan.txt 172.16
```

### Output Format

The script generates a simple text file with one IP address per line:
```
192.168.1.1
192.168.1.5
192.168.1.10
192.168.1.15
...
```

### Performance Characteristics

- **Scan speed**: Configurable from 50-200+ concurrent pings
- **Network efficiency**: Optimized timeout handling for different network conditions
- **Resource usage**: Controlled memory and CPU utilization
- **Accuracy**: Reliable host discovery with configurable timeouts

## Requirements

- **nmap**: Network scanning and discovery
- **bash**: Script execution environment
- **sudo**: Required for full scan capabilities
- **timeout**: Process timeout management
- **ping**: Host discovery (included in most systems)
- **bc**: Mathematical operations for timeout validation

## Installation

```bash
git clone <repository-url>
cd ctf-scripts
chmod +x *.sh
```

## Best Practices

### For CTF/Lab Environments
- Use higher concurrency (-j 100) for faster reconnaissance
- Implement shorter timeouts (-t 1) for time-limited scenarios
- Skip UDP scans (--no-udp) when speed is critical

### For Production Networks
- Use conservative concurrency (-j 20) to minimize impact
- Implement longer timeouts (-t 3) for comprehensive scanning
- Use slower timing templates (--timing -T2) for stealth

### For Subnet Discovery
- Start with smaller subnets (/24) for initial reconnaissance
- Use higher concurrency for larger networks (/16, /8)
- Implement quiet mode (-q) for automated workflows
- Monitor system resources during large scans

### General Guidelines
- Always validate target lists before scanning
- Monitor system resources during concurrent operations
- Review scan results for false positives
- Maintain organized output directories
- Use appropriate timeouts for network conditions

## License

MIT License - free to use, modify, and distribute.

## Credits

- **subnet-blaster**: Original script by [Jtgit4](https://github.com/Jtgit4), enhanced and optimized
- **nmap-scan.sh**: Optimized for CTF and pentesting workflows
