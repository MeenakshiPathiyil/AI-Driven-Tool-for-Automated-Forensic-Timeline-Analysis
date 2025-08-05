import pandas as pd
from datetime import datetime, timedelta
import re
from collections import defaultdict
import logging
from typing import Dict, List, Tuple

# Set up logging
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class BruteForceDetector:
    def __init__(self, csv_file: str = None, output_file: str = None, time_window_minutes: int = 5, event_threshold: int = 5):
        self.csv_file = csv_file
        self.output_file = output_file
        self.time_window = timedelta(minutes=time_window_minutes)
        self.event_threshold = event_threshold
        self.detections = []

    def load_csv(self) -> pd.DataFrame:
        # Load and parse the log2timeline CSV file
        try:
            df = pd.read_csv(self.csv_file, parse_dates=['datetime'], low_memory=False)
            logger.info(f"Loaded CSV with {len(df)} events")
            return df
        except Exception as e:
            logger.error(f"Error loading CSV file: {e}")
            raise

    def filter_relevant_events(self, df: pd.DataFrame) -> pd.DataFrame:
        # Filter events related to brute force
        event_keywords = ['4624', '4625', '4648']
        relevant_df = df[
            df['desc'].str.contains('|'.join(event_keywords) + '|Netlogon|winevt', case=False, na=False) &
            ~df['parser'].str.contains('filestat', case=False, na=False)
        ]
        logger.debug(f"Filtered {len(relevant_df)} brute force-related events")
        return relevant_df

    def extract_event_details(self, message: str, event_id: str, parser: str) -> Tuple[str, str, str, str]:
        event_id = event_id
        username = 'Unknown'
        ip_address = 'Local'
        details = ''

        message = str(message).replace('\t', ' ').replace('\n', ' ').strip()
        parser = str(parser).lower()

        # Username extraction
        if event_id == '4625':
            username_match = re.search(r'Account For Which Logon Failed:.*?Account Name:\s*([^\s]+)', message, re.IGNORECASE)
            if username_match:
                username = username_match.group(1).split('@')[0].strip()
                logger.debug(f"Extracted failed logon username: {username} for event ID {event_id}")
            else:
                username_match = re.search(r'(?:Account Name|Subject:.*?Account Name|User):\s*([^\s]+)', message, re.IGNORECASE)
                if username_match:
                    username = username_match.group(1).split('@')[0].strip()
                    logger.debug(f"Extracted subject username: {username} for event ID {event_id}")
        else:
            username_match = re.search(r'(?:Account Name|Subject:.*?Account Name|User):\s*([^\s]+)', message, re.IGNORECASE)
            if username_match:
                username = username_match.group(1).split('@')[0].strip()
                logger.debug(f"Extracted username: {username} for event ID {event_id}")

        # IP address extraction
        ip_match = re.search(r'(?:Source Network Address|Source Address):\s*([^\s]+)', message, re.IGNORECASE)
        if ip_match and ip_match.group(1).strip() != '-':
            ip_address = ip_match.group(1).strip()
            logger.debug(f"Extracted IP address: {ip_address}")

        # Handle events
        if event_id == '4625':
            reason_match = re.search(r'Failure Reason:\s*([^\;]+)', message, re.IGNORECASE)
            logon_type_match = re.search(r'Logon Type:\s*([^\s]+)', message, re.IGNORECASE)
            details = []
            if reason_match:
                reason = reason_match.group(1).strip()
                details.append(f"Failed: {reason[:30]}..." if len(reason) > 30 else f"Failed: {reason}")
            if logon_type_match:
                details.append(f"Type: {logon_type_match.group(1).strip()}")
            details = '; '.join(details) if details else 'Failed login'
            logger.debug(f"Extracted details: {details}")
        elif event_id in ['4624', '4648']:
            logon_type_match = re.search(r'Logon Type:\s*([^\s]+)', message, re.IGNORECASE)
            details = f"Success: Type {logon_type_match.group(1).strip()}" if logon_type_match else 'Successful login'
            logger.debug(f"Extracted details: {details}")
        elif 'reg' in parser or 'winreg' in parser:
            key_match = re.search(r'(?:Key Path|Object Name):\s*([^\;]+)', message, re.IGNORECASE)
            value_match = re.search(r'(?:Value Name|Value):\s*([^\;]+)', message, re.IGNORECASE)
            process_match = re.search(r'(?:Process Name|Image):\s*([^\s]+)', message, re.IGNORECASE)
            if process_match:
                ip_address = process_match.group(1).rsplit('\\', 1)[-1].lower()
                logger.debug(f"Extracted process name: {ip_address}")
            details = []
            if key_match:
                key_path = key_match.group(1).strip()
                key_components = key_path.rsplit('\\', 2)[-2:]
                formatted_key = '\\'.join(key_components)
                details.append(f"Registry: {formatted_key}")
            if value_match:
                details.append(f"Value: {value_match.group(1).strip()}")
            details = '; '.join(details) if details else 'Registry modification'
            event_id = 'REG'
            logger.debug(f"Extracted registry details: {details}")
        elif 'file' in parser or 'mft' in parser:
            file_match = re.search(r'(?:Filename|Object Name):\s*([^\;]+)', message, re.IGNORECASE)
            access_match = re.search(r'Accesses:\s*([^\;]+)', message, re.IGNORECASE)
            process_match = re.search(r'(?:Process Name|Image):\s*([^\s]+)', message, re.IGNORECASE)
            if process_match:
                ip_address = process_match.group(1).rsplit('\\', 1)[-1].lower()
                logger.debug(f"Extracted process name: {ip_address}")
            details = []
            if file_match:
                file_path = file_match.group(1).strip()
                file_name = file_path.rsplit('\\', 1)[-1]
                details.append(f"File: {file_name}")
            if access_match:
                details.append(f"Access: {access_match.group(1).strip()}")
            details = '; '.join(details) if details else 'File access'
            event_id = 'FILE'
            logger.debug(f"Extracted file details: {details}")

        return event_id, username, ip_address, details

    def detect_brute_force(self, event_df: pd.DataFrame) -> List[Dict]:
        # Detect T1110 brute force patterns
        detections = []
        failed_logins = defaultdict(list)
        successful_logins = defaultdict(list)

        # Suspicious indicators
        suspicious_registry_keys = ['HKLM\\System\\CurrentControlSet\\Services\\Netlogon\\Parameters']
        suspicious_file_paths = ['C:\\Windows\\System32\\winevt\\Logs\\Security.evtx']

        # # Add IoCs
        # if iocs:
        #     for ioc in iocs:
        #         if ioc.get('category') == 'user':
        #             suspicious_registry_keys.append(ioc.get('value').lower())
        #         elif ioc.get('category') == 'file':
        #             suspicious_file_paths.append(ioc.get('value').lower())
        #         elif ioc.get('category') == 'ip_address':
        #             suspicious_file_paths.append(ioc.get('value').lower())

        for _, row in event_df.iterrows():
            event_id = 'Unknown'
            message = row.get('desc', '')
            parser = row.get('parser', '')
            event_id_match = re.search(r'\[(\d+) /', str(message), re.IGNORECASE)
            if event_id_match:
                event_id = event_id_match.group(1)
            event_id, username, ip_address, details = self.extract_event_details(message, event_id, parser)
            timestamp = row['datetime']

            if event_id == '4625':
                failed_logins[(username, ip_address)].append((timestamp, details))
                logger.debug(f"Added failed login for {username} from {ip_address} at {timestamp}")
            elif event_id in ['4624', '4648']:
                successful_logins[(username, ip_address)].append((timestamp, details))
                logger.debug(f"Added successful login for {username} from {ip_address} at {timestamp}")
            elif event_id == 'REG' and any(key.lower() in details.lower() for key in suspicious_registry_keys):
                failed_logins[(username, ip_address)].append((timestamp, details))
                logger.debug(f"Added suspicious registry event for {username}: {details}")
            elif event_id == 'FILE' and any(path.lower() in details.lower() for path in suspicious_file_paths):
                failed_logins[(username, ip_address)].append((timestamp, details))
                logger.debug(f"Added suspicious file event for {username}: {details}")

        for (username, ip_address), events in failed_logins.items():
            if username == 'Unknown' or not username:
                logger.debug(f"Skipping Unknown username with {len(events)} events")
                continue
            detection_types = []
            details_list = []
            time_range = f"{min(t for t, _ in events)} to {max(t for t, _ in events)}"
            attack_count = len(events)

            failed_events = [(t, d) for t, d in events if 'Failed' in d]
            if len(failed_events) >= self.event_threshold:
                detection_types.append("High Volume")
                details_list.append(f"{len(failed_events)} failed logins")
                logger.debug(f"Detected High Volume Failed Logins for {username} from {ip_address}")

            failed_events_sorted = sorted(failed_events, key=lambda x: x[0])
            if len(failed_events_sorted) >= self.event_threshold:
                time_diff = (failed_events_sorted[-1][0] - failed_events_sorted[0][0]).total_seconds()
                if time_diff <= self.time_window.total_seconds():
                    detection_types.append("Rapid")
                    details_list.append(f"{len(failed_events_sorted)} rapid logins in {time_diff:.0f} seconds")
                    logger.debug(f"Detected Rapid Failed Logins for {username} from {ip_address}")

            success_events = successful_logins.get((username, ip_address), [])
            if success_events:
                detection_types.append("Successful Login")
                details_list.append(f"{len(success_events)} successful login{'s' if len(success_events) > 1 else ''}")
                logger.debug(f"Detected Successful Login After Failures for {username} from {ip_address}")

            reg_events = [(t, d) for t, d in events if 'Registry' in d]
            file_events = [(t, d) for t, d in events if 'File' in d]
            if reg_events:
                detection_types.append("Registry Modification")
                details_list.append(f"Modified: {', '.join(d for _, d in reg_events)}")
                logger.debug(f"Detected Suspicious Registry Modification for {username}")
            if file_events:
                detection_types.append("File Access")
                details_list.append(f"Accessed: {', '.join(d for _, d in file_events)}")
                logger.debug(f"Detected Suspicious File Access for {username}")

            if detection_types:
                detections.append({
                    'type': 'Brute Force (T1110)',
                    'username': username,
                    'ip_address': ip_address,
                    'attack_count': attack_count,
                    'time_range': time_range,
                    'details': f"{attack_count} events ({', '.join(detection_types)}): {'; '.join(details_list)}"
                })
                logger.info(f"Detected brute force attack for {username} from {ip_address} with {attack_count} events")

        if not detections:
            logger.warning("No brute force patterns detected")
        return detections

    def run(self):
        # Run the brute force detection process
        logger.info("Starting T1110 Brute Force Detection")
        df = self.load_csv()
        event_df = self.filter_relevant_events(df)
        detections = self.detect_brute_force(event_df)
        return detections


