# Home Network Agent

AI-powered network security agent that analyzes DNS queries from AdGuard Home and automatically blocks suspicious domains using LLM reasoning.

## Features

- Parallel data fetching from AdGuard for faster analysis
- LLM-powered threat analysis with learning from past decisions
- Interactive and automatic blocking modes
- Domain revert capability with reason tracking
- Configurable auto-block threshold based on confidence
- Comprehensive logging and decision history

## Setup

1. Copy `config.yaml.example` to `config.yaml`:
   ```bash
   cp config.yaml.example config.yaml
   ```

2. Edit `config.yaml` with your settings:
   - AdGuard URL and credentials
   - OpenAI API key
   - Model configuration
   - Trusted domains
   - Auto-block threshold

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Interactive Mode (default)
Run the agent and manually select domains to block:
```bash
python agent.py
```

### Automatic Mode
Automatically block domains from the BLOCK list with confidence >= threshold (default 0.9):
```bash
python agent.py --auto
```

### Aggressive Automatic Mode
Automatically block ALL domains (block + watch) with confidence >= threshold:
```bash
python agent.py --auto-all
```

### Revert a Block
Unblock a domain and record the reason for learning:
```bash
python agent.py revert example.com "broke my service"
```

### Help
View all available options:
```bash
python agent.py --help
```

## How It Works

1. **Fetch Data**: Retrieves DNS query logs and blocked domains from AdGuard Home in parallel
2. **Analyze**: Summarizes network activity and identifies new/suspicious domains
3. **LLM Reasoning**: Uses OpenAI to analyze patterns and recommend actions with confidence scores
4. **Decision**: Either auto-blocks high-confidence threats or presents recommendations for manual review
5. **Learn**: Records decisions and reverts to improve future analysis



