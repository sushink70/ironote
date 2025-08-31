# Immutable Database (IMDB) Tool

A powerful, secure immutable database system that creates cryptographically signed files that cannot be modified once created. Perfect for audit logs, compliance records, evidence storage, and any data that requires tamper-proof integrity.

## Features

### Core Functionality
- **Immutable Storage**: Files cannot be modified after creation
- **Cryptographic Integrity**: Ed25519 signatures ensure authenticity
- **Content Verification**: SHA-256 hashing prevents corruption
- **File Permissions**: Automatic read-only permissions and immutable flags

### Enhanced Features
- **Interactive Mode**: User-friendly guided operations
- **Multiple Content Types**: Support for text, JSON, CSV, logs, markdown, etc.
- **Tagging System**: Organize entries with searchable tags
- **Expiration Dates**: Set automatic expiration for time-sensitive data
- **Priority Levels**: Organize content by importance (1-5 scale)
- **Full-Text Search**: Search across all content and metadata
- **Export/Import**: Backup and restore entire workspaces
- **Batch Operations**: Verify multiple files at once
- **Detailed Statistics**: Comprehensive workspace analytics
- **Watch Mode**: Continuous integrity monitoring

## Installation

### Prerequisites
- Rust 1.70 or later
- Git

### Build from Source
```bash
git clone <repository-url>
cd immutable_deb_db
cargo build --release
sudo cp target/release/immutable_deb_db /usr/local/bin/imdb
```

## Quick Start

### 1. Initialize a Workspace
```bash
# Initialize in current directory
imdb init

# Initialize in specific directory
imdb init --path /path/to/workspace
```

### 2. Create Your First Entry
```bash
# Interactive mode (recommended for beginners)
imdb interactive

# Direct creation
imdb create entry1 --description "My first immutable entry"
```

### 3. Read Content
```bash
# Read an entry
imdb read entry1

# Read with different formats
imdb read entry1 --format table
imdb read entry1 --format compact
```

## Commands Reference

### Workspace Management
```bash
# Initialize workspace
imdb init [--path <directory>] [--force]

# Show workspace information
imdb info

# Generate new keypair (WARNING: invalidates existing files)
imdb generate-key [--force] [--backup]
```

### Creating Content
```bash
# Basic creation
imdb create <name> [OPTIONS]

# With metadata
imdb create "meeting-notes" \
    --description "Team meeting notes" \
    --tags "meetings,2024,team-alpha" \
    --content-type "markdown" \
    --priority 2 \
    --expires "30d"

# From file
imdb create "config-backup" --file /etc/nginx/nginx.conf

# Interactive creation
imdb interactive
```

### Reading and Verification
```bash
# Read content
imdb read <name> [--raw] [--meta-only] [--format <format>]

# Export content to file
imdb read <name> --export /path/to/output.txt

# Verify single file
imdb verify <name> [--verbose] [--report]

# Verify all
imdb verify --all [--verbose] [--report]
