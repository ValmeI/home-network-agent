# Home Network Agent

AI agent for home network intervention that analyzes DNS queries from AdGuard Home and recommends blocking suspicious domains.

## Setup

1. Copy `.env.example` to `.env` and configure:
   ```bash
   cp .env.example .env
   ```

2. Edit `.env` with your settings:
   - AdGuard URL and credentials
   - OpenAI API key

3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

Run the agent:
```bash
python agent.py
```

The agent will:
- Fetch DNS query logs from AdGuard
- Analyze domains for suspicious patterns
- Recommend domains to block
- Log decisions to `decisions.jsonl`

## Configuration

Edit `.env` to customize:
- `LOG_LEVEL` - Logging verbosity (INFO, DEBUG, WARNING)
- `MODEL` - OpenAI model to use
- `HISTORY_LIMIT` - Number of previous decisions to consider

