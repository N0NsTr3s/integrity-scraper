#!/usr/bin/env python3
"""
Website Integrity Monitor - Main CLI Entry Point
"""
import argparse
import sys
import os
import yaml
import logging
from datetime import datetime
import traceback
from analyze_pci_compliance import analyze_captured_data
from file_change_detector import detect_changes
from utils import load_config

def setup_logger(name):
    """Set up logging for the application"""
    log_dir = "logs"
    os.makedirs(log_dir, exist_ok=True)
    
    log_file = os.path.join(log_dir, f"{name}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log")
    
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    file_handler = logging.FileHandler(log_file)
    console_handler = logging.StreamHandler()
    
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)
    
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def handle_scan_command(args, config, logger):
    """Handle the scan command"""
    from workflow_manager import IntegrityWorkflow
    
    logger.info(f"Starting scan of {args.url} with depth {args.depth}")
    
    # Update config with command line arguments
    if args.depth:
        config["default_depth"] = args.depth
    
    if args.output:
        # If output is specified, use it as the output directory
        output_dir = os.path.dirname(args.output)
        if output_dir:
            config["output_dir"] = output_dir
    
    # Create workflow manager
    workflow = IntegrityWorkflow(args.url, config=config, logger=logger)
    
    # Run full workflow
    success = workflow.run_full_workflow()
    return 0 if success else 1

def handle_analyze_command(args, logger):
    """Handle the analyze command"""
    logger.info(f"Analyzing file: {args.file}")
    results = analyze_captured_data(args.file, return_results=True)
    
    # Print analysis results
    if results:
        print(f"\nCompliance Score: {results['compliance_score']}%")
        print("\nIssues:")
        for issue in results['issues']:
            print(f"- [{issue['severity']}] {issue['description']}")
            print(f"  Recommendation: {issue['recommendation']}")
    
    return 0

def handle_compare_command(args, logger):
    """Handle the compare command"""
    logger.info(f"Comparing files: {args.file1} and {args.file2}")
    
    changes = detect_changes(args.file1, args.file2)
    
    print("\nFile Change Analysis:")
    print(f"Type: {'Text' if not changes.get('is_binary', False) else 'Binary'}")
    print(f"Size Change: {changes.get('size_change', 'N/A')} bytes")
    print(f"Is Significant Change: {'Yes' if changes.get('is_significant_change', False) else 'No'}")
    
    print("\nAdded Lines:")
    for line in changes.get('added_lines', []):
        print(f"+ {line.strip()}")
    
    print("\nDeleted Lines:")
    for line in changes.get('deleted_lines', []):
        print(f"- {line.strip()}")
    
    print("\nMeaningful Changes:")
    for line in changes.get('meaningful_changes', []):
        print(f"! {line.strip()}")
        
    return 0

def main():
    """Main entry point for the Website Integrity Monitor CLI"""
    config = load_config()
    logger = setup_logger("website-integrity-monitor")
    
    parser = argparse.ArgumentParser(description="Website Integrity Monitor")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")
    
    # Scan command
    scan_parser = subparsers.add_parser("scan", help="Scan a website")
    scan_parser.add_argument("url", help="URL to scan")
    scan_parser.add_argument("--depth", type=int, default=config["default_depth"], help="Recursion depth")
    scan_parser.add_argument("--headless", action="store_true", default=config["headless"], help="Run browser in headless mode")
    scan_parser.add_argument("--output", "-o", help="Output file for results")
    
    # Analyze command
    analyze_parser = subparsers.add_parser("analyze", help="Analyze scan results")
    analyze_parser.add_argument("file", help="JSON file to analyze")
    
    # Compare command
    compare_parser = subparsers.add_parser("compare", help="Compare two files for changes")
    compare_parser.add_argument("file1", help="Original file")
    compare_parser.add_argument("file2", help="Modified file")
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return 1
    
    try:
        if args.command == "scan":
            return handle_scan_command(args, config, logger)
        
        if args.command == "analyze":
            return handle_analyze_command(args, logger)
        
        if args.command == "compare":
            return handle_compare_command(args, logger)
        
        # If we get here, it's an unknown command
        logger.error(f"Unknown command: {args.command}")
        parser.print_help()
        return 1
    except Exception as e:
        logger.error(f"Error in command {args.command}: {e}")
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())