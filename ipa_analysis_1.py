import zipfile
import os
import plistlib
import re
import logging
from pathlib import Path

# Configure logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

# Constants
IPA_FILE = "/Users/abhishek/Documents/Bankbazaar.ipa"
EXTRACTED_PATH = "extracted_app"
REPORT_FILE = "analysis_report.txt"

SENSITIVE_DATA_PATTERNS = [
    re.compile(rb"password", re.IGNORECASE),
    re.compile(rb"token", re.IGNORECASE),
    re.compile(rb"secret", re.IGNORECASE),
    re.compile(rb"private_key", re.IGNORECASE),
    re.compile(rb"api_key", re.IGNORECASE)
]

JAILBREAK_INDICATORS = [
    "cydia",  # Cydia app
    "/bin/bash",  # Presence of bash
    "/usr/sbin/sshd",  # SSH service
    "/etc/apt",  # APT package manager
    "MobileSubstrate",  # Jailbreak tweak framework
    "libcycript.dylib",  # Cycript dynamic library
    "/private/var/stash",  # Directory often present on jailbroken devices
]

INSECURE_APIS = [
    re.compile(rb"_fopen", re.IGNORECASE),
    re.compile(rb"_memcpy", re.IGNORECASE),
    re.compile(rb"_printf", re.IGNORECASE),
    re.compile(rb"_sscanf", re.IGNORECASE),
]

TRACKERS = [
    b"GoogleAnalytics",
    b"firebase",
    b"Appsflyer",
    b"Adjust",
    b"FacebookSDK",
    b"Crashlytics",
]

CRITICAL_PERMISSIONS = [
    "NSLocationAlwaysUsageDescription",
    "NSLocationWhenInUseUsageDescription",
    "NSCameraUsageDescription",
    "NSMicrophoneUsageDescription",
    "NSPhotoLibraryUsageDescription",
    "NSContactsUsageDescription"
]

OFAC_COUNTRIES = [
    "Cuba", "Iran", "North Korea", "Sudan", "Syria", "Venezuela", "China"
]

class IPAAnalyzer:
    def __init__(self, ipa_file: str, extracted_path: str, report_file: str):
        self.ipa_file = ipa_file
        self.extracted_path = Path(extracted_path)
        self.report_file = Path(report_file)
        self.report_content = []

    def extract_ipa(self) -> bool:
        """Extract the contents of the IPA file."""
        try:
            with zipfile.ZipFile(self.ipa_file, 'r') as zip_ref:
                zip_ref.extractall(self.extracted_path)
            logging.info(f"IPA file extracted successfully to {self.extracted_path}")
            return True
        except zipfile.BadZipFile:
            logging.error(f"{self.ipa_file} is not a valid IPA file.")
        except Exception as e:
            logging.error(f"An error occurred during extraction: {e}")
        return False

    def search_sensitive_data(self, content: bytes, file_path: Path):
        """Search for sensitive data patterns in the given file."""
        logging.debug(f"Analyzing file: {file_path}")
        for pattern in SENSITIVE_DATA_PATTERNS:
            match = pattern.search(content)
            if match:
                snippet = self.extract_snippet(content, match.start())
                self.report_issue(
                    file_path, 
                    "Sensitive Data", 
                    pattern.pattern.decode(), 
                    match.start(), 
                    snippet
                )

    def check_encryption_in_plist(self, plist_content: dict, file_path: Path):
        """Check for encryption-related information in plist files."""
        for key, value in plist_content.items():
            if isinstance(value, str) and "crypt" in value.lower():
                snippet = f"{key}: {value}"
                self.report_issue(
                    file_path, 
                    "Encryption", 
                    key, 
                    0,  # Assuming key-value pairs are at the top level
                    snippet
                )
            self.check_critical_permissions(key, value, file_path)

    def check_critical_permissions(self, key: str, value: str, file_path: Path):
        """Check for critical permissions in the plist file."""
        if key in CRITICAL_PERMISSIONS:
            snippet = f"{key}: {value}"
            self.report_issue(
                file_path, 
                "Critical Permission", 
                key, 
                0,  # Assuming key-value pairs are at the top level
                snippet
            )

    def check_ofac_sanctioned_countries(self, content: bytes, file_path: Path):
        """Check for references to OFAC sanctioned countries in binaries or plist files."""
        for country in OFAC_COUNTRIES:
            if country.encode() in content:
                snippet = self.extract_snippet(content, content.find(country.encode()))
                self.report_issue(
                    file_path, 
                    "OFAC Sanctioned Country", 
                    country, 
                    content.find(country.encode()), 
                    snippet
                )

    def check_insecure_apis(self, content: bytes, file_path: Path):
        """Check for insecure API usage in the binary."""
        logging.debug(f"Analyzing file for insecure APIs: {file_path}")
        for pattern in INSECURE_APIS:
            match = pattern.search(content)
            if match:
                snippet = self.extract_snippet(content, match.start())
                self.report_issue(
                    file_path, 
                    "Insecure API", 
                    pattern.pattern.decode(), 
                    match.start(), 
                    snippet
                )

    def check_runpath(self, content: bytes, file_path: Path):
        """Check if the binary has Runpath Search Path (@rpath) set."""
        if b"@rpath" in content:
            snippet = self.extract_snippet(content, content.find(b"@rpath"))
            self.report_issue(
                file_path, 
                "Runpath Search Path", 
                "@rpath", 
                content.find(b"@rpath"), 
                snippet
            )

    def check_malloc_usage(self, content: bytes, file_path: Path):
        """Check if the binary uses _malloc."""
        if b"_malloc" in content:
            snippet = self.extract_snippet(content, content.find(b"_malloc"))
            self.report_issue(
                file_path, 
                "Malloc Usage", 
                "_malloc", 
                content.find(b"_malloc"), 
                snippet
            )

    def check_for_trackers(self, content: bytes, file_path: Path):
        """Check if the application contains known trackers."""
        logging.debug(f"Analyzing file for trackers: {file_path}")
        for tracker in TRACKERS:
            if tracker in content:
                snippet = self.extract_snippet(content, content.find(tracker))
                self.report_issue(
                    file_path, 
                    "Tracker Detected", 
                    tracker.decode(), 
                    content.find(tracker), 
                    snippet
                )

    def analyze_files(self):
        """Analyze the extracted files for various security and privacy concerns."""
        for root, dirs, files in os.walk(self.extracted_path):
            for file in files:
                file_path = Path(root) / file
                try:
                    with file_path.open('rb') as file_content:
                        content = file_content.read()
                        if file_path.suffix == ".plist":
                            try:
                                plist_content = plistlib.loads(content)
                                self.check_encryption_in_plist(plist_content, file_path)
                            except Exception as e:
                                logging.debug(f"Failed to parse plist {file_path}: {e}")
                        self.search_sensitive_data(content, file_path)
                        self.check_malloc_usage(content, file_path)
                        self.check_insecure_apis(content, file_path)
                        self.check_runpath(content, file_path)
                        self.check_for_trackers(content, file_path)
                        self.check_ofac_sanctioned_countries(content, file_path)
                except Exception as e:
                    logging.error(f"Error analyzing file {file_path}: {e}")

    def extract_snippet(self, content: bytes, position: int, context: int = 40) -> str:
        """Extract a code snippet around a specific position for context."""
        # Get 3 lines before and 3 lines after the matched position
        lines = content.decode(errors='ignore').splitlines()
        line_index = 0
        char_count = 0
        for i, line in enumerate(lines):
            char_count += len(line) + 1  # +1 for the newline character
            if char_count > position:
                line_index = i
                break
        
        start_line = max(0, line_index - 3)
        end_line = min(len(lines), line_index + 4)
        
        snippet_lines = lines[start_line:end_line]
        snippet = "\n".join(snippet_lines)
        return snippet

    def report_issue(self, file_path: Path, issue_type: str, pattern: str, location: int, snippet: str):
        """Record the identified issue in the report."""
        issue_report = (
            f"File: {file_path}\n"
            f"Issue Type: {issue_type}\n"
            f"Pattern: {pattern}\n"
            f"Location in File: {location}\n"
            f"Code Snippet:\n{snippet}\n"
            "----------------------------------------\n"
        )
        logging.warning(issue_report)
        self.report_content.append(issue_report)

    def write_report(self):
        """Write the analysis report to a file."""
        if self.report_content:
            with self.report_file.open('w') as report:
                report.write("\n".join(self.report_content))
            logging.info(f"Report written to {self.report_file}")
        else:
            logging.info("No issues found during analysis.")

    def clean_extracted_path(self):
        """Clean up the extracted directory."""
        if self.extracted_path.exists():
            for item in self.extracted_path.iterdir():
                try:
                    if item.is_dir():
                        os.rmdir(item)
                    else:
                        item.unlink()
                except Exception as e:
                    logging.error(f"Error cleaning up {item}: {e}")
            try:
                os.rmdir(self.extracted_path)
            except Exception as e:
                logging.error(f"Error removing directory {self.extracted_path}: {e}")

    def run(self):
        """Run the analysis process."""
        if not Path(self.ipa_file).exists():
            logging.error(f"The IPA file {self.ipa_file} does not exist.")
            return

        self.clean_extracted_path()

        if self.extract_ipa():
            self.analyze_files()
            self.write_report()
        else:
            logging.error("Extraction failed. Exiting.")

if __name__ == "__main__":
    analyzer = IPAAnalyzer(IPA_FILE, EXTRACTED_PATH, REPORT_FILE)
    analyzer.run()

