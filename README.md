# Analyzer CLI

A command-line interface for [Exein Analyzer](https://analyzer.exein.io) -- firmware & container security scanning.

Scan firmware images for CVEs, generate SBOMs, check CRA compliance, and more. All from your terminal.

## Install

### Homebrew (macOS & Linux)

```bash
brew install exein-io/tap/analyzer
```

### Shell installer

```bash
curl -fsSL https://raw.githubusercontent.com/exein-io/analyzer-cli/main/dist/install.sh | bash
```

### Cargo

```bash
cargo install analyzer-cli
```

### From source

```bash
git clone https://github.com/exein-io/analyzer-cli.git
cd analyzer-cli
cargo install --path .
```

## Quick start

```bash
# 1. Authenticate
analyzer login
#    Enter your API key: ********
#    OK Saved to ~/.config/analyzer/config.toml

# 2. Create an object (device / product)
analyzer object new "my-router"
#    OK Created object 'my-router' (a1b2c3d4-...)

# 3. Upload and scan a firmware image
analyzer scan new \
  --object a1b2c3d4-... \
  --file firmware.bin \
  --type linux \
  --analysis info cve software-bom malware \
  --wait
#    Uploading firmware.bin  [=====================>] 100% (42 MB)
#    OK Scan completed successfully!

# 4. Download the report
analyzer scan report --scan e5f6g7h8-... --output report.pdf
#    OK Report saved to report.pdf

# 5. Download the SBOM
analyzer scan sbom --scan e5f6g7h8-... --output sbom.json
#    OK SBOM saved to sbom.json
```

## Usage

### Authentication

```bash
# Interactive login (prompts for API key, validates, saves)
analyzer login

# Use a specific server URL
analyzer login --url https://my-analyzer.example.com/api/

# Login to a named profile
analyzer login --profile staging

# Check your current identity
analyzer whoami
```

### Objects

```bash
# List all objects
analyzer object list

# Create a new object
analyzer object new "my-device" --description "Router firmware" --tags iot,router

# Delete an object
analyzer object delete <UUID>
```

### Scans

```bash
# Create a scan (returns immediately)
analyzer scan new -o <OBJECT_ID> -f firmware.bin -t linux -a info cve software-bom

# Create a scan and wait for completion
analyzer scan new -o <OBJECT_ID> -f image.tar -t docker -a info cve malware --wait

# Check scan status
analyzer scan status --scan <SCAN_ID>

# View the security score
analyzer scan score --scan <SCAN_ID>

# Download PDF report (waits for completion)
analyzer scan report --scan <SCAN_ID> --output report.pdf --wait

# Download SBOM
analyzer scan sbom --scan <SCAN_ID> --output sbom.json

# Download CRA compliance report
analyzer scan cra-report --scan <SCAN_ID> --output cra.pdf --wait

# List available scan types and analyses
analyzer scan types

# Cancel a running scan
analyzer scan cancel <SCAN_ID>

# Delete a scan
analyzer scan delete <SCAN_ID>
```

### Configuration

```bash
# Show all config
analyzer config show

# Set a value
analyzer config set url https://my-instance.example.com/api/
analyzer config set api-key <KEY>
analyzer config set default-profile staging

# Get a value
analyzer config get url
```

### Output formats

Every command supports `--format`:

```bash
# Human-readable (default) -- colored, tables
analyzer object list

# JSON -- for scripting and piping
analyzer object list --format json

# Pipe into jq
analyzer scan status --scan <ID> --format json | jq '.status'
```

### Shell completions

```bash
# Bash
analyzer completions bash > /etc/bash_completion.d/analyzer

# Zsh
analyzer completions zsh > ~/.zfunc/_analyzer

# Fish
analyzer completions fish > ~/.config/fish/completions/analyzer.fish
```

## Configuration

The CLI stores configuration at `~/.config/analyzer/config.toml`:

```toml
default_profile = "default"

[profiles.default]
api_key = "your-api-key"
url = "https://analyzer.exein.io/api/"

[profiles.staging]
api_key = "staging-key"
url = "https://staging.analyzer.exein.io/api/"
```

### Precedence

Settings are resolved in this order (highest priority first):

1. CLI flags (`--api-key`, `--url`, `--profile`)
2. Environment variables (`ANALYZER_API_KEY`, `ANALYZER_URL`, `ANALYZER_PROFILE`)
3. Config file (`~/.config/analyzer/config.toml`)
4. Defaults (URL: `https://analyzer.exein.io/api/`)

## Supported scan types

| Type | Analyses |
|------|----------|
| `linux` | info, kernel, cve, password-hash, crypto, software-bom, malware, hardening, capabilities |
| `docker` | info, cve, password-hash, crypto, software-bom, malware, hardening, capabilities |
| `idf` | info, cve, software-bom, symbols, tasks, stack-overflow |

## License

Apache-2.0
