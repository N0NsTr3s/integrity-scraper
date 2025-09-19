# Website Integrity Monitor

A comprehensive tool for monitoring website integrity, analyzing PCI DSS compliance, and detecting changes in website files with enhanced baseline comparison and detailed change analysis.

## Features

- **Website Scanning**: Recursively monitor websites and capture network traffic using Selenium and Chrome DevTools Protocol
- **Enhanced File Change Detection**: Compare current scans with baseline (first scan) to detect modifications, with line-by-line analysis and row range reporting
- **PCI DSS Compliance Analysis**: Analyze captured data for PCI DSS v4.0 compliance requirements
- **Detailed Change Reporting**: Shows exact line changes, modifications, additions, and deletions with content previews
- **Automatic Directory Management**: Creates versioned directories (domain, domain_1, domain_2) for multiple scans
- **Dual Storage System**: Separates scan data (main directories) from reports and analysis results

## Installation

1. Make sure you have Python 3.8+ installed
2. Clone this repository
3. Install the required dependencies:

```bash
pip install -r requirements.txt
```

## Configuration

The tool includes a YAML configuration file (`config.yaml`) for basic settings, though it's optional as the system uses sensible defaults:

```yaml
# Scanning settings
default_depth: 3          # Default recursion depth
headless: true            # Run browser in headless mode
wait_time: 10            # Wait time for page loading

# Exclusion settings (Note: Currently hardcoded in the application)
excluded_domains:
  - "github.com"
  - "fonts.googleapis.com"
  - "api.google.com"
  - "analytics."
```

**Note**: The configuration file is optional. If missing, the system uses built-in defaults. Most settings can be overridden via command-line arguments.

## Usage

### Primary Command-Line Interface

The main entry point is `integrity_monitor.py` which provides three commands:

#### 1. Scanning a Website

```bash
python integrity_monitor.py scan https://example.com --depth 3 --headless
```

**Arguments:**
- `url`: The URL to scan (required)
- `--depth`: Recursion depth (default: from config or 2)
- `--headless`: Run browser in headless mode (default: true)


**What it does:**
- Creates versioned directories (`example.com`, `example.com_1`, `example.com_2`, etc.)
- Captures all network traffic, scripts, stylesheets, and page content
- Performs automatic PCI DSS compliance analysis
- **Enhanced Change Detection**: Compares with first scan (baseline) using `file_hashes.json`
- Shows detailed line-by-line changes with row ranges (e.g., "rows 8-9 were modified")
- Generates comprehensive reports in the `reports/` directory

#### 2. Analyzing Existing Scan Data

```bash
python integrity_monitor.py analyze path/to/scan_file.json
```

**Arguments:**
- `file`: Path to a scan JSON file (required)

**What it does:**
- Performs PCI DSS compliance analysis on existing scan data
- Displays compliance score and identified issues
- Shows security recommendations

#### 3. Comparing Two Files

```bash
python integrity_monitor.py compare file1.js file2.js
```

**Arguments:**
- `file1`: Original file path (required)
- `file2`: Modified file path (required)

**What it does:**
- Shows line-by-line differences between two files
- Identifies added, deleted, and meaningful changes

## Directory Structure

The tool creates a dual directory system for organized data management:

### Main Scan Directories
```
./example.com/                    # First scan (baseline)
├── captured_files/               # Downloaded website files
│   ├── html.html
│   ├── script.js
│   └── styles.css
└── scan_info.json               # Scan metadata

./example.com_1/                 # Second scan
├── captured_files/              # Updated website files
└── scan_info.json

./example.com_2/                 # Third scan (if any)
└── ...
```

### Reports Directory
```
./reports/example.com/           # Analysis and comparison reports
├── scan_20250920_143000.json   # Raw scan data
├── analysis_20250920_143000.json # PCI compliance analysis
├── report_20250920_143000.html # HTML report
├── file_hashes.json            # Baseline file hashes for comparison
└── changes_20250920_143000.txt # Detailed change analysis
```

### Key Features:
- **Baseline Comparison**: First scan creates `file_hashes.json` baseline
- **Change Detection**: Subsequent scans compare against the baseline
- **Row Range Analysis**: Shows "rows 5-10 were deleted", "row 15 was added"
- **Modification Detection**: Identifies when lines are similar but changed (60% similarity threshold)
- **Versioned Storage**: Each scan gets its own directory to preserve history

## Alternative Usage Methods

### Workflow Manager (Direct Python Usage)

For programmatic usage or custom workflows:

```python
from workflow_manager import IntegrityWorkflow

# Create and run a complete workflow
workflow = IntegrityWorkflow("https://example.com")
success = workflow.run_full_workflow()
```

### Standalone Analysis

You can also run individual components:

```bash
# Direct PCI compliance analysis
python analyze_pci_compliance.py scan_data.json

# Direct file change detection
python file_change_detector.py file1.js file2.js

# Workflow manager as standalone script
python workflow_manager.py https://example.com --depth 2 --headless
```

## Enhanced Change Detection Features

The tool provides sophisticated change detection capabilities:

1. **Baseline Comparison**: Always compares against the first scan (not just previous scan)
2. **Line-by-Line Analysis**: Shows exact content that was added, deleted, or modified
3. **Row Range Grouping**: Groups adjacent changes (e.g., "rows 13-29 were deleted")
4. **Modification Detection**: Identifies similar lines that were changed (parameter updates, etc.)
5. **Significance Filtering**: Filters out minor whitespace changes and focuses on meaningful modifications
6. **Content Previews**: Shows actual content of changes for easier review

### Example Change Output:
```
🔄 File: payment-form.js
✅ Baseline scan found: ./reports/stripe-payments-demo.appspot.com/file_hashes.json
📊 Analysis: 29 lines added, 6 lines deleted

Additions:
   row 4 was added: "const STRIPE_API_VERSION = '2024-06-20';"
   rows 8-9 were added: 
   "// Enhanced security features"
   "const enableAdvancedFraud = true;"

Deletions: 
   row 15 was deleted: "console.log('Debug mode active');"

Modifications:
   rows 60-61 were modified:
   - const apiKey = 'pk_test_old';
   + const apiKey = 'pk_test_new_key_2024';
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.