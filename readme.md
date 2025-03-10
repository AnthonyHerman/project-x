# Project-X: Runtime SCA with eBPF and Vulnerability Analysis

Project-X is a comprehensive runtime Software Composition Analysis (SCA) tool powered by eBPF technology. It combines real-time application monitoring with advanced vulnerability analysis capabilities, tracking Open Source Vulnerabilities (OSV) and identifying vulnerable functions in codebases through LLM-based code analysis.

## Features

- **Runtime SCA with eBPF**: Monitors running applications in real-time using eBPF technology to detect potential vulnerabilities as they're executed
- **Function-Level Tracking**: Identifies specific vulnerable functions being called during runtime
- **Zero Instrumentation**: Monitors applications without requiring code changes or recompilation
- **OSV Data Integration**: Automatically downloads and processes vulnerability data from the OSV database for multiple ecosystems
- **Repository Analysis**: Clones relevant repositories associated with vulnerabilities for local analysis
- **LLM-Powered Function Identification**: Uses Large Language Models to identify specific functions responsible for vulnerabilities
- **Multi-Ecosystem Support**: Works with multiple package ecosystems including PyPI, npm, Go, Maven, and more
- **Confidence Scoring**: Assigns confidence scores to identified vulnerable functions
- **Persistent Storage**: Stores all vulnerability and analysis data in a PostgreSQL database

## Getting Started

### Prerequisites

- Go 1.16 or higher
- Linux kernel 5.5+ (for eBPF features)
- BCC (BPF Compiler Collection) tools
- PostgreSQL database
- Git command-line tools
- Access to an LLM service (local or remote)

### Environment Setup

```bash
# Database connection
export POSTGRES_HOST=localhost
export POSTGRES_USERNAME=postgres
export POSTGRES_PASSWORD=your_password
export POSTGRES_DATABASE=osv

# LLM configuration
export LLM_SERVER_URL=http://127.0.0.1:8080/completion
export LLM_REQUEST_TIMEOUT=5m  # Optional, default is 5 minutes
```

### Building the Project

```bash
git clone https://github.com/AnthonyHerman/project-x.git
cd project-x
go build -o project-x
```

### Basic Usage

#### Bootstrap the Database

```bash
./project-x bootstrap
```

This command:
1. Creates the necessary database schema
2. Downloads vulnerability data for all supported ecosystems
3. Processes and loads the data into the database
4. Queues vulnerabilities for function-level analysis

#### Analyze a Specific Vulnerability

```bash
./project-x analyze --id GHSA-22cc-w7xm-rfhx
```

This command:
1. Retrieves vulnerability details from the database
2. Clones the associated repository
3. Identifies relevant files for analysis
4. Uses an LLM to analyze the code and identify vulnerable functions
5. Saves the results in the database and displays them

#### Monitor Applications with eBPF

```bash
sudo ./project-x monitor --pid 1234
```

This command:
1. Attaches eBPF probes to the specified running process
2. Monitors function calls in real-time
3. Compares function calls against the vulnerability database
4. Alerts when vulnerable functions are executed

```bash
sudo ./project-x monitor --binary /path/to/application
```

This command:
1. Launches the specified application with eBPF monitoring
2. Tracks all function calls for vulnerability matching
3. Provides real-time alerts for detected vulnerabilities

## Supported Ecosystems

- PyPI (Python)
- npm (JavaScript)
- Go
- Maven (Java)
- RubyGems (Ruby)
- crates.io (Rust)
- Hex (Elixir)
- NuGet (.NET)
- Packagist (PHP)
- Pub (Dart)
- Haskell

## Architecture

The system consists of several key components:

1. **eBPF Runtime Module**: Leverages eBPF for real-time monitoring of running applications
2. **Database Module**: Handles database connections and schema management
3. **OSV Module**: Downloads and processes vulnerability data from upstream sources
4. **Grabber Module**: Clones repositories associated with vulnerabilities
5. **Analyzer Module**: Uses LLM to analyze code and identify vulnerable functions

### Runtime SCA Architecture

Project-X uses eBPF to attach to application runtimes and monitor function calls in real-time:

1. **Function Tracing**: Hooks into function entry points to identify when vulnerable functions are called
2. **Call Stack Analysis**: Captures call stack information to understand the execution context
3. **Vulnerability Matching**: Cross-references runtime function calls against the vulnerability database
4. **Real-time Alerting**: Generates alerts when vulnerable functions are executed in production

## Using with Local LLMs

When running with local LLMs (like llama.cpp), be aware that code analysis can be resource-intensive and may take several minutes per vulnerability. The system is designed to handle timeouts gracefully and will retry operations with increasing timeout values.

For best results with local LLMs:
- Ensure your LLM has enough context window to process code files
- Consider using a model specifically trained or fine-tuned for code understanding
- Set appropriate timeout values via the `LLM_REQUEST_TIMEOUT` environment variable

## License

[MIT License](LICENSE)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
