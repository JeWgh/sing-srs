import pandas as pd
import re
import os
import json
import requests
import yaml
import ipaddress
import subprocess
import logging
from io import StringIO
from pathlib import Path
from typing import Dict, List, Tuple, Optional, Any

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Constants
USER_AGENT = 'Mozilla/5.0'
RULE_VERSION = 2
SCRIPT_DIR = Path(__file__).parent

# Get links.txt file path (supports environment variables)
def get_links_file() -> Path:
    """Get links.txt file path with multiple fallback options"""
    # 1. Environment variable
    env_path = os.getenv('LINKS_FILE')
    if env_path:
        return Path(env_path)
    
    # 2. Try parent directory
    parent_links = SCRIPT_DIR.parent / 'links.txt'
    if parent_links.exists():
        return parent_links
    
    # 3. Try current directory
    current_links = SCRIPT_DIR / 'links.txt'
    if current_links.exists():
        return current_links
    
    # 4. Default to parent directory path
    return parent_links

# Pattern mapping dictionary
MAP_DICT: Dict[str, str] = {
    'DOMAIN-SUFFIX': 'domain_suffix', 'HOST-SUFFIX': 'domain_suffix', 'host-suffix': 'domain_suffix',
    'DOMAIN': 'domain', 'HOST': 'domain', 'host': 'domain',
    'DOMAIN-KEYWORD': 'domain_keyword', 'HOST-KEYWORD': 'domain_keyword', 'host-keyword': 'domain_keyword',
    'IP-CIDR': 'ip_cidr', 'ip-cidr': 'ip_cidr', 'IP-CIDR6': 'ip_cidr', 'IP6-CIDR': 'ip_cidr',
    'SRC-IP-CIDR': 'source_ip_cidr', 'DST-PORT': 'port',
    'SRC-PORT': 'source_port', 'URL-REGEX': 'domain_regex', 'DOMAIN-REGEX': 'domain_regex'
}

def fetch_url(url: str, timeout: int = 30, retries: int = 3) -> str:
    """Unified HTTP request function with retry mechanism
    
    Args:
        url: Request URL
        timeout: Timeout in seconds
        retries: Number of retry attempts
        
    Returns:
        Response text content
    """
    last_error = None
    for attempt in range(retries):
        try:
            response = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=timeout)
            response.raise_for_status()
            return response.text
        except (requests.RequestException, requests.Timeout) as e:
            last_error = e
            if attempt < retries - 1:
                logger.warning(f"Retry {attempt + 1}/{retries} for {url}: {e}")
    raise last_error if last_error else requests.RequestException("Unknown error")

def read_yaml_from_url(url: str, timeout: int = 30) -> Any:
    """Read YAML data from URL"""
    return yaml.safe_load(fetch_url(url, timeout))

def read_list_from_url(url: str, timeout: int = 30) -> Tuple[pd.DataFrame, List[Dict]]:
    """Read list data from URL and parse into DataFrame"""
    text = fetch_url(url, timeout)
    df = pd.read_csv(StringIO(text), header=None, 
                     names=['pattern', 'address', 'other', 'other2', 'other3'], 
                     on_bad_lines='skip')
    
    rules: List[Dict] = []
    
    # Process logical rules (if AND patterns exist)
    if 'AND' in df['pattern'].values:
        and_rows = df[df['pattern'].str.contains('AND', na=False)]
        for _, row in and_rows.iterrows():
            rule = {"type": "logical", "mode": "and", "rules": []}
            pattern = ",".join(row.values.astype(str))
            
            for component in re.findall(r'\((.*?)\)', pattern):
                for keyword, mapped_value in MAP_DICT.items():
                    if keyword in component:
                        if match := re.search(f'{keyword},(.*)', component):
                            rule["rules"].append({mapped_value: match.group(1)})
            
            if rule["rules"]:  # Only add valid rules
                rules.append(rule)
    
    # Filter out AND rows and return
    df_filtered: pd.DataFrame = df[~df['pattern'].str.contains('AND', na=False)].copy()  # type: ignore[assignment]
    df_filtered = df_filtered.reset_index(drop=True)
    return df_filtered, rules

def normalize_address(address: str, rule_type: str) -> str:
    """Normalize address for consistent deduplication
    
    Args:
        address: Address string to normalize
        rule_type: Rule type (ip_cidr, domain, etc.)
        
    Returns:
        Normalized address string
    """
    address = address.strip()
    
    # Normalize IP CIDRs: lowercase and standardize format
    if 'ip_cidr' in rule_type or 'cidr' in rule_type:
        try:
            # Parse and reformat to canonical form
            network = ipaddress.ip_network(address, strict=False)
            return str(network).lower()
        except ValueError:
            return address.lower()
    
    # Normalize domains: lowercase
    elif 'domain' in rule_type:
        return address.lower()
    
    # Keep others as-is but strip whitespace
    return address

def is_ipv4_or_ipv6(address: str) -> Optional[str]:
    """Determine if address is IPv4 or IPv6
    
    Args:
        address: IP address string
        
    Returns:
        'ipv4', 'ipv6', or None
    """
    try:
        ipaddress.IPv4Network(address, strict=False)
        return 'ipv4'
    except ValueError:
        try:
            ipaddress.IPv6Network(address, strict=False)
            return 'ipv6'
        except ValueError:
            return None

def parse_and_convert_to_dataframe(link: str) -> Tuple[pd.DataFrame, List[Dict]]:
    """Parse link and convert to DataFrame"""
    # Try to process as YAML/TXT first
    if link.endswith(('.yaml', '.txt')):
        try:
            yaml_data = read_yaml_from_url(link)
            
            # Extract items
            if isinstance(yaml_data, str):
                items = yaml_data.splitlines()[0].split() if yaml_data.splitlines() else []
            else:
                items = yaml_data.get('payload', [])
            
            # Parse each item
            rows = []
            for item in items:
                address = item.strip("'")
                
                # Determine pattern type
                if ',' in item:
                    pattern, address = item.split(',', 1)
                    address = address.split(',')[0]  # Take first part
                elif is_ipv4_or_ipv6(item):
                    pattern = 'IP-CIDR'
                elif address.startswith(('+', '.')):
                    pattern = 'DOMAIN-SUFFIX'
                    address = address.lstrip('+.')
                else:
                    pattern = 'DOMAIN'
                
                rows.append({'pattern': pattern.strip(), 'address': address.strip(), 'other': None})
            
            return pd.DataFrame(rows, columns=['pattern', 'address', 'other']), []
            
        except (requests.RequestException, yaml.YAMLError, ValueError) as e:
            logger.warning(f"YAML/TXT parsing failed, trying CSV mode: {link}")
    
    # Process as CSV list
    return read_list_from_url(link)

def deduplicate_addresses(addresses: List[str], rule_type: str) -> List[str]:
    """Deduplicate addresses with normalization
    
    Args:
        addresses: List of addresses to deduplicate
        rule_type: Rule type for normalization
        
    Returns:
        Sorted list of unique addresses
    """
    normalized_map = {}
    for addr in addresses:
        addr_stripped = addr.strip()
        normalized = normalize_address(addr_stripped, rule_type)
        if normalized not in normalized_map:
            normalized_map[normalized] = addr_stripped
    return sorted(normalized_map.values())

def sort_dict(obj: Any) -> Any:
    """Recursively sort dictionaries and lists"""
    if isinstance(obj, dict):
        return {k: sort_dict(obj[k]) for k in sorted(obj)}
    elif isinstance(obj, list) and obj and all(isinstance(elem, dict) for elem in obj):
        return sorted([sort_dict(x) for x in obj], key=lambda d: sorted(d.keys())[0] if d else '')
    elif isinstance(obj, list):
        return sorted(sort_dict(x) for x in obj)
    else:
        return obj

def write_json_file(file_path: Path, data: Dict[str, Any]) -> None:
    """Write JSON data to file with consistent formatting
    
    Args:
        file_path: Path to write JSON file
        data: Data to write
    """
    file_path.write_text(
        json.dumps(sort_dict(data), ensure_ascii=False, indent=2),
        encoding='utf-8'
    )

def copy_json_file(url: str, output_path: Path, custom_name: Optional[str] = None) -> Optional[str]:
    """Copy JSON file from URL directly
    
    Args:
        url: JSON file URL
        output_path: Output directory
        custom_name: Custom filename (without extension)
        
    Returns:
        Path to saved JSON file, or None on failure
    """
    try:
        json_text = fetch_url(url)
        json_data = json.loads(json_text)
        
        # Validate it's a sing-box rule set
        if not isinstance(json_data, dict) or 'version' not in json_data:
            logger.warning(f"Invalid sing-box JSON format (missing 'version' field): {url}")
            return None
        
        if json_data.get('version') != RULE_VERSION:
            logger.warning(f"JSON version mismatch (expected {RULE_VERSION}, got {json_data.get('version')}): {url}")
        
        filename = custom_name if custom_name else Path(url).stem
        file_path = output_path / f"{filename}.json"
        
        # Write formatted JSON
        write_json_file(file_path, json_data)
        logger.info(f"Copied JSON: {file_path}")
        return str(file_path)
        
    except (json.JSONDecodeError, requests.RequestException) as e:
        logger.error(f"Failed to copy JSON from {url}: {e}")
        return None

def copy_srs_file(url: str, output_path: Path, custom_name: Optional[str] = None) -> Optional[str]:
    """Copy SRS (binary) file from URL and decompile to JSON
    
    Args:
        url: SRS file URL
        output_path: Output directory
        custom_name: Custom filename (without extension)
        
    Returns:
        Path to saved JSON file (decompiled from SRS), or None on failure
    """
    try:
        response = requests.get(url, headers={'User-Agent': USER_AGENT}, timeout=30)
        response.raise_for_status()
        
        filename = custom_name if custom_name else Path(url).stem
        srs_path = output_path / f"{filename}.srs"
        json_path = output_path / f"{filename}.json"
        
        # Write binary SRS content
        srs_path.write_bytes(response.content)
        logger.info(f"Downloaded SRS: {srs_path}")
        
        # Decompile SRS to JSON
        try:
            result = subprocess.run(
                ['sing-box', 'rule-set', 'decompile', '--output', str(json_path), str(srs_path)],
                check=True, capture_output=True, text=True, timeout=60
            )
            logger.info(f"Decompiled to JSON: {json_path}")
            return str(json_path)
        except subprocess.CalledProcessError as e:
            logger.error(f"SRS decompilation failed: {e.stderr}")
            return None
        except FileNotFoundError:
            logger.warning("sing-box command not found, keeping SRS file only")
            return None
        except subprocess.TimeoutExpired:
            logger.error(f"Decompilation timeout: {srs_path}")
            return None
        
    except requests.RequestException as e:
        logger.error(f"Failed to download SRS from {url}: {e}")
        return None

def compile_to_srs(json_file: str) -> None:
    """Compile JSON rule set to SRS format"""
    srs_path = json_file.replace(".json", ".srs")
    try:
        subprocess.run(
            ['sing-box', 'rule-set', 'compile', '--output', srs_path, json_file],
            check=True, capture_output=True, text=True, timeout=60
        )
        logger.info(f"SRS compilation successful: {srs_path}")
    except subprocess.CalledProcessError as e:
        logger.error(f"SRS compilation failed: {e.stderr}")
    except FileNotFoundError:
        logger.warning("sing-box command not found, skipping SRS compilation")
    except subprocess.TimeoutExpired:
        logger.error(f"Compilation timeout: {json_file}")

def merge_rule_sets(json_files: List[str], output_path: Path, merged_name: str) -> Optional[str]:
    """Merge multiple JSON rule files into a single rule set
    
    Args:
        json_files: List of JSON file paths to merge
        output_path: Output directory
        merged_name: Name for the merged file (without extension)
        
    Returns:
        Path to merged JSON file, or None on failure
    """
    try:
        merged_rules: Dict[str, List] = {}
        logical_rules: List[Dict] = []
        
        logger.info(f"Reading {len(json_files)} files for merge...")
        
        # Read and merge all JSON files
        for idx, json_file in enumerate(json_files, 1):
            if not json_file or not Path(json_file).exists():
                continue
            
            if idx % 5 == 0 or idx == len(json_files):  # Progress every 5 files
                logger.info(f"  Processing file {idx}/{len(json_files)}...")
                
            data = json.loads(Path(json_file).read_text(encoding='utf-8'))
            
            # Extract and merge rules
            for rule in data.get('rules', []):
                if 'type' in rule and rule.get('type') == 'logical':
                    # Collect logical rules separately
                    logical_rules.append(rule)
                else:
                    # Merge by rule type
                    for rule_type, values in rule.items():
                        if rule_type not in merged_rules:
                            merged_rules[rule_type] = []
                        if isinstance(values, list):
                            merged_rules[rule_type].extend(values)
                        else:
                            merged_rules[rule_type].append(values)
        
        # Build merged result
        result_rules: Dict[str, Any] = {"version": RULE_VERSION, "rules": []}
        
        # Add merged rules (deduplicated and sorted with normalization)
        for rule_type in sorted(merged_rules.keys()):
            unique_values = deduplicate_addresses(merged_rules[rule_type], rule_type)
            result_rules["rules"].append({rule_type: unique_values})
        
        # Add logical rules
        if logical_rules:
            result_rules["rules"].extend(logical_rules)
        
        # Write merged JSON file
        merged_file = output_path / f"{merged_name}.json"
        write_json_file(merged_file, result_rules)
        
        # Log statistics
        stats = get_rule_stats(result_rules)
        stats_str = ', '.join([f"{k}: {v}" for k, v in sorted(stats.items())])
        logger.info(f"Merged {len(json_files)} files into: {merged_file} ({stats_str})")
        
        # Compile to SRS
        compile_to_srs(str(merged_file))
        
        # Extract and save separate rule types
        extract_rule_types(result_rules, output_path, merged_name)
        
        return str(merged_file)
        
    except Exception as e:
        logger.error(f"Failed to merge rule sets: {e}", exc_info=True)
        return None

def extract_rule_types(rules_data: Dict[str, Any], output_path: Path, base_name: str) -> None:
    """Extract and save IP and domain rules to separate subdirectories
    
    Args:
        rules_data: Rule set data dictionary
        output_path: Base output directory
        base_name: Base filename for extracted rules
    """
    try:
        # Create subdirectories
        ipcidr_dir = output_path / 'ip-cidr'
        domain_dir = output_path / 'domain'
        ipcidr_dir.mkdir(parents=True, exist_ok=True)
        domain_dir.mkdir(parents=True, exist_ok=True)
        
        ip_rules = []
        domain_rules = []
        
        # Extract rules by type
        for rule in rules_data.get('rules', []):
            if isinstance(rule, dict):
                for rule_type, values in rule.items():
                    # IP-related rules
                    if 'ip_cidr' in rule_type or 'cidr' in rule_type:
                        ip_rules.append({rule_type: values})
                    # Domain-related rules
                    elif 'domain' in rule_type:
                        domain_rules.append({rule_type: values})
        
        # Save IP CIDR rules
        if ip_rules:
            ipcidr_data = {"version": RULE_VERSION, "rules": ip_rules}
            ipcidr_file = ipcidr_dir / f"{base_name}.json"
            write_json_file(ipcidr_file, ipcidr_data)
            logger.info(f"Extracted IP rules: {ipcidr_file}")
            compile_to_srs(str(ipcidr_file))
        
        # Save domain rules
        if domain_rules:
            domain_data = {"version": RULE_VERSION, "rules": domain_rules}
            domain_file = domain_dir / f"{base_name}.json"
            write_json_file(domain_file, domain_data)
            logger.info(f"Extracted domain rules: {domain_file}")
            compile_to_srs(str(domain_file))
            
    except Exception as e:
        logger.error(f"Failed to extract rule types: {e}", exc_info=True)

def parse_list_file(link: str, output_directory: str, custom_name: Optional[str] = None, is_temp: bool = False) -> Optional[str]:
    """Parse link file and generate rule set file
    
    Args:
        link: URL to parse
        output_directory: Output directory path
        custom_name: Custom filename (without extension), uses URL stem if not provided
        is_temp: If True, skip SRS compilation and rule extraction (for temporary merge files)
    """
    output_path = Path(output_directory)
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Handle JSON files directly
    if link.endswith('.json'):
        logger.info(f"Detected JSON file, copying directly...")
        if json_file := copy_json_file(link, output_path, custom_name):
            if not is_temp:
                compile_to_srs(json_file)
            return json_file
        return None
    
    # Handle SRS files directly
    if link.endswith('.srs'):
        logger.info(f"Detected SRS file, downloading and decompiling...")
        return copy_srs_file(link, output_path, custom_name)
    
    # Process other formats (YAML, TXT, CSV, etc.)
    try:
        # Parse link
        df, rules_list = parse_and_convert_to_dataframe(link)
        
        # Clean data (chain operations)
        df = (df[~df['pattern'].str.contains('#', na=False)]
              .loc[lambda x: x['pattern'].isin(MAP_DICT.keys())]
              .drop_duplicates()
              .assign(pattern=lambda x: x['pattern'].replace(MAP_DICT))
              .reset_index(drop=True))
        
        # Build rule set
        result_rules: Dict[str, Any] = {"version": RULE_VERSION, "rules": []}
        domain_entries: List[str] = []
        
        for pattern, addresses in df.groupby('pattern')['address'].apply(list).items():
            unique_addresses = deduplicate_addresses(addresses, pattern)
            
            if pattern == 'domain':
                domain_entries.extend(unique_addresses)
            else:
                result_rules["rules"].append({pattern: unique_addresses})
        
        # Insert domain rules at the beginning
        if domain_entries:
            result_rules["rules"].insert(0, {'domain': domain_entries})
        
        # Add logical rules
        if rules_list:
            result_rules["rules"].extend(rules_list)
        
        # Generate file path
        filename = custom_name if custom_name else Path(link).stem
        json_file_path = output_path / f"{filename}.json"
        
        # Write JSON file
        write_json_file(json_file_path, result_rules)
        file_name = str(json_file_path)
        
        # Log statistics
        stats = get_rule_stats(result_rules)
        stats_str = ', '.join([f"{k}: {v}" for k, v in sorted(stats.items())])
        logger.info(f"Generated JSON: {file_name} ({stats_str})")
        
        # Skip SRS compilation and extraction for temporary files
        if not is_temp:
            compile_to_srs(file_name)
            extract_rule_types(result_rules, output_path, filename)
        
        return file_name
    except Exception as e:
        logger.error(f'Link processing failed: {link}, error: {str(e)}', exc_info=True)
        return None

def check_singbox_availability() -> bool:
    """Check if sing-box command is available
    
    Returns:
        True if sing-box is available, False otherwise
    """
    try:
        result = subprocess.run(
            ['sing-box', 'version'],
            capture_output=True,
            text=True,
            timeout=5
        )
        if result.returncode == 0:
            logger.info(f"sing-box is available: {result.stdout.strip()}")
            return True
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    
    logger.warning("sing-box command not found - SRS compilation will be skipped")
    return False

def get_rule_stats(rules_data: Dict[str, Any]) -> Dict[str, int]:
    """Get statistics for rule set
    
    Args:
        rules_data: Rule set data dictionary
        
    Returns:
        Dictionary with rule type counts
    """
    stats = {}
    for rule in rules_data.get('rules', []):
        if isinstance(rule, dict):
            for rule_type, values in rule.items():
                if rule_type == 'type':  # Skip logical rule type field
                    continue
                count = len(values) if isinstance(values, list) else 1
                stats[rule_type] = stats.get(rule_type, 0) + count
    return stats

def cleanup_temp_files(output_path: Path, temp_base: str) -> None:
    """Clean up temporary files from all directories
    
    Args:
        output_path: Base output directory
        temp_base: Base name of temporary files
    """
    try:
        # Main directory
        for ext in ['.json', '.srs']:
            (output_path / f"{temp_base}{ext}").unlink(missing_ok=True)
        
        # Subdirectories
        for subdir in ['ip-cidr', 'domain']:
            for ext in ['.json', '.srs']:
                (output_path / subdir / f"{temp_base}{ext}").unlink(missing_ok=True)
    except Exception:
        pass

def main():
    """Main function: Read links file and generate rule sets"""
    # Check sing-box availability
    singbox_available = check_singbox_availability()
    
    # Read and validate links file
    links_file_path = get_links_file()
    logger.info(f"Links file: {links_file_path}")
    
    if not links_file_path.exists():
        logger.error(f"File not found: {links_file_path}")
        return
    
    try:
        raw_lines = [l.strip() for l in links_file_path.read_text(encoding='utf-8').splitlines()
                     if l.strip() and not l.strip().startswith("#")]
    except IOError as e:
        logger.error(f"Read failed: {e}")
        return
    
    # Parse links with optional custom names and merge groups
    # Format: 
    #   - [name]: followed by single or multiple URLs on next lines
    links_data = []
    merge_groups = []
    current_group_name = None
    current_group_urls = []
    
    for line in raw_lines:
        # Check for group start: [name]:
        if line.startswith('[') and line.endswith(':'):
            # Save previous group if exists
            if current_group_name is not None:
                if len(current_group_urls) == 1:
                    # Single URL: treat as regular file with custom name
                    links_data.append((current_group_urls[0], current_group_name))
                elif len(current_group_urls) > 1:
                    # Multiple URLs: treat as merge group
                    merge_groups.append((current_group_name, current_group_urls))
            
            # Start new group
            current_group_name = line.strip('[]:').strip()
            current_group_urls = []
        elif line.startswith(('http://', 'https://')):
            # Add URL to current group
            if current_group_name is not None:
                current_group_urls.append(line.strip())
            else:
                # Standalone URL without group (shouldn't happen with new format)
                links_data.append((line.strip(), None))
    
    # Save last group if exists
    if current_group_name is not None:
        if len(current_group_urls) == 1:
            links_data.append((current_group_urls[0], current_group_name))
        elif len(current_group_urls) > 1:
            merge_groups.append((current_group_name, current_group_urls))
    
    logger.info(f"Single files: {len(links_data)}, Merge groups: {len(merge_groups)}")
    
    # Set output directory
    output_path = Path(os.getenv('OUTPUT_DIR', os.getcwd()))
    output_path.mkdir(parents=True, exist_ok=True)
    logger.info(f"Output directory: {output_path}")
    
    # Process single links
    results = []
    for idx, (link, custom_name) in enumerate(links_data, 1):
        display_name = f"{link} -> {custom_name}" if custom_name else link
        logger.info(f"[{idx}/{len(links_data)}] {display_name}")
        if result := parse_list_file(link, str(output_path), custom_name):
            results.append(result)
    
    # Process merge groups
    for idx, (merged_name, urls) in enumerate(merge_groups, 1):
        logger.info(f"[Merge {idx}/{len(merge_groups)}] {merged_name} <- {len(urls)} sources")
        
        # Parse each URL in the group (as temporary files)
        temp_files = []
        for url_idx, url in enumerate(urls, 1):
            logger.info(f"  [{url_idx}/{len(urls)}] {url}")
            temp_name = f"_temp_{merged_name}_{url_idx}"
            # Mark as temporary to skip SRS compilation and extraction
            if temp_result := parse_list_file(url, str(output_path), temp_name, is_temp=True):
                temp_files.append(temp_result)
        
        # Merge all temporary files
        if temp_files:
            if merged_result := merge_rule_sets(temp_files, output_path, merged_name):
                results.append(merged_result)
                
                # Clean up temporary files
                for temp_file in temp_files:
                    cleanup_temp_files(output_path, Path(temp_file).stem)
    
    # Output statistics
    total_tasks = len(links_data) + len(merge_groups)
    logger.info(f"Completed: {len(results)}/{total_tasks} successful")
    if results:
        logger.info("\n".join([f"  ✓ {Path(f).name}" for f in results]))


if __name__ == '__main__':
    main()