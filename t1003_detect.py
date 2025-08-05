import pandas as pd
from datetime import datetime, timedelta
import re
from collections import defaultdict
import logging
from typing import Dict, List, Tuple

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class CredentialDumpingDetector:
    def __init__(self, csv_file: str = None, output_file: str = None, time_window_minutes: int = 5, event_threshold: int = 3):
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
        # Filter events related to credential dumping
        event_keywords = ['4688', '4657', '10', '4661']
        relevant_df = df[
            df['desc'].str.contains('|'.join(event_keywords) + '|SAM|SECURITY|lsass|credential', case=False, na=False) &
            ~df['parser'].str.contains('filestat', case=False, na=False)
        ]
        logger.debug(f"Filtered {len(relevant_df)} credential dumping-related events")
        return relevant_df

    def extract_event_details(self, message: str, event_id: str, parser: str) -> Tuple[str, str, str, str]:
        event_id = event_id
        username = 'Unknown'
        process_name = 'Unknown'
        details = ''

        message = str(message).replace('\t', ' ').replace('\n', ' ').strip()
        parser = str(parser).lower()

        # Extract event ID
        event_id_match = re.search(r'\[(\d+) /', message, re.IGNORECASE)
        if event_id_match:
            event_id = event_id_match.group(1)
            logger.debug(f"Extracted event ID: {event_id}")

        # Username extraction
        username_match = re.search(r'(?:Account Name|Subject:.*?Account Name|User):\s*([^\s]+)', message, re.IGNORECASE)
        if username_match:
            username = username_match.group(1).split('@')[0].strip()
            logger.debug(f"Extracted username: {username} for event ID {event_id}")

        # Process name extraction
        process_match = re.search(r'(?:Process Name|Image|TargetImage):\s*([^\s]+)', message, re.IGNORECASE)
        if process_match:
            process_name = process_match.group(1).rsplit('\\', 1)[-1].lower().strip()
            logger.debug(f"Extracted process name: {process_name}")
        elif 'lsass.exe' in message.lower():
            process_name = 'lsass.exe'
            logger.debug(f"Extracted process name: lsass.exe from message")

        # Handle events
        if event_id == '4688':
            command_line_match = re.search(r'Command Line:\s*([^\;]+)', message, re.IGNORECASE)
            details = f"Process: {process_name}"
            if command_line_match:
                command_line = command_line_match.group(1).strip()
                details += f"; Command: {command_line[:50]}..." if len(command_line) > 50 else f"; Command: {command_line}"
            logger.debug(f"Extracted 4688 details: {details}")
        elif event_id == '4657':
            key_match = re.search(r'(?:Key Path|Object Name):\s*([^\;]+)', message, re.IGNORECASE)
            value_match = re.search(r'(?:Value Name|Value):\s*([^\;]+)', message, re.IGNORECASE)
            details = []
            if key_match:
                key_path = key_match.group(1).strip()
                key_components = key_path.rsplit('\\', 2)[-2:]
                formatted_key = '\\'.join(key_components)
                details.append(f"Registry: {formatted_key}")
            if value_match:
                details.append(f"Value: {value_match.group(1).strip()}")
            details = '; '.join(details) if details else 'Registry modification'
            logger.debug(f"Extracted 4657 details: {details}")
        elif event_id == '10':
            target_process_match = re.search(r'TargetImage:\s*([^\s]+)', message, re.IGNORECASE)
            granted_access_match = re.search(r'GrantedAccess:\s*([^\s]+)', message, re.IGNORECASE)
            details = f"Process Access: {process_name}"
            if target_process_match:
                target_process = target_process_match.group(1).rsplit('\\', 1)[-1].lower().strip()
                details += f"; Target: {target_process}"
            if granted_access_match:
                details += f"; Access: {granted_access_match.group(1).strip()}"
            logger.debug(f"Extracted 10 details: {details}")
        elif event_id == '4661':
            object_type_match = re.search(r'Object Type:\s*([^\s]+)', message, re.IGNORECASE)
            object_name_match = re.search(r'Object Name:\s*([^\s]+)', message, re.IGNORECASE)
            access_match = re.search(r'Accesses:\s*([^\;]+)', message, re.IGNORECASE)
            details = []
            if object_type_match:
                details.append(f"Object Type: {object_type_match.group(1).strip()}")
            if object_name_match:
                details.append(f"Object: {object_name_match.group(1).strip()}")
            if access_match:
                details.append(f"Access: {access_match.group(1).strip()}")
            details = '; '.join(details) if details else 'SAM handle request'
            logger.debug(f"Extracted 4661 details: {details}")
        elif 'reg' in parser or 'winreg' in parser:
            key_match = re.search(r'(?:Key Path|Object Name):\s*([^\;]+)', message, re.IGNORECASE)
            value_match = re.search(r'(?:Value Name|Value):\s*([^\;]+)', message, re.IGNORECASE)
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

        return event_id, username, process_name, details

    def detect_credential_dumping(self, event_df: pd.DataFrame) -> List[Dict]:
        # Detect T1003 credential dumping patterns
        detections = []
        suspicious_events = defaultdict(list)

        # Suspicious indicators
        suspicious_processes = ['mimikatz', 'procdump', 'sekurlsa', 'lsadump']
        suspicious_registry_keys = ['HKLM\\SAM', 'HKLM\\SECURITY', 'HKLM\\SYSTEM']
        suspicious_file_paths = ['SAM', 'SECURITY', 'lsass.dmp', 'credential', 'dump']
        suspicious_sam_objects = ['SAM_SERVER', 'SAM_DOMAIN', 'SAM_USER']

        # # Add IoCs
        # if iocs:
        #     for ioc in iocs:
        #         if ioc.get('category') == 'process':
        #             suspicious_processes.append(ioc.get('value').lower())
        #         elif ioc.get('category') == 'user':
        #             suspicious_sam_objects.append(ioc.get('value').lower())
        #         elif ioc.get('category') == 'file':
        #             suspicious_file_paths.append(ioc.get('value').lower())

        for _, row in event_df.iterrows():
            event_id = 'Unknown'
            message = row.get('desc', '')
            parser = row.get('parser', '')
            event_id_match = re.search(r'\[(\d+) /', str(message), re.IGNORECASE)
            if event_id_match:
                event_id = event_id_match.group(1)
            event_id, username, process_name, details = self.extract_event_details(message, event_id, parser)
            timestamp = row['datetime']

            # Flag suspicious events
            is_suspicious = False
            detection_type = []
            detection_details = details

            if event_id == '4688' and any(proc.lower() in process_name.lower() for proc in suspicious_processes):
                is_suspicious = True
                detection_type.append("Suspicious Process")
                detection_details = f"Process: {process_name}; {details}"
                logger.debug(f"Flagged suspicious process {process_name} for {username}")
            elif event_id == '10' and 'lsass.exe' in details.lower():
                is_suspicious = True
                detection_type.append("LSASS Access")
                detection_details = f"Process: {process_name}; {details}"
                logger.debug(f"Flagged LSASS access by {process_name} for {username}")
            elif event_id == '4657' and any(key.lower() in details.lower() for key in suspicious_registry_keys):
                is_suspicious = True
                detection_type.append("Registry Modification")
                detection_details = f"Registry: {details}"
                logger.debug(f"Flagged registry modification for {username}: {details}")
            elif event_id == '4661' and any(obj.lower() in details.lower() for obj in suspicious_sam_objects):
                is_suspicious = True
                detection_type.append("SAM Access")
                detection_details = f"SAM Object: {details}"
                logger.debug(f"Flagged SAM access for {username}: {details}")
            elif event_id == 'REG' and any(key.lower() in details.lower() for key in suspicious_registry_keys):
                is_suspicious = True
                detection_type.append("Registry Modification")
                detection_details = f"Registry: {details}"
                logger.debug(f"Flagged registry modification for {username}: {details}")
            elif event_id == 'FILE' and any(path.lower() in details.lower() for path in suspicious_file_paths):
                is_suspicious = True
                detection_type.append("File Access")
                detection_details = f"File: {details}"
                logger.debug(f"Flagged file access for {username}: {details}")

            if is_suspicious:
                suspicious_events[(username, process_name)].append((timestamp, detection_type, detection_details))
                logger.debug(f"Added suspicious event for {username} with process {process_name} at {timestamp}")

        # Process detections
        for (username, process_name), events in suspicious_events.items():
            if username == 'Unknown' or not username:
                logger.debug(f"Skipping Unknown username with {len(events)} events")
                continue

            events_sorted = sorted(events, key=lambda x: x[0])
            attack_count = len(events_sorted)
            if attack_count < self.event_threshold:
                logger.debug(f"Skipping {username} with {process_name}: {attack_count} events below threshold {self.event_threshold}")
                continue

            time_diff = (events_sorted[-1][0] - events_sorted[0][0]).total_seconds()
            if time_diff > self.time_window.total_seconds():
                logger.debug(f"Skipping {username} with {process_name}: events span {time_diff:.0f} seconds, exceeding time window")
                continue

            detection_types = set()
            details_list = []
            time_range = f"{events_sorted[0][0]} to {events_sorted[-1][0]}"
            for _, event_types, event_details in events_sorted:
                detection_types.update(event_types)
                details_list.append(event_details)

            detections.append({
                'type': 'Credential Dumping (T1003)',
                'username': username,
                'process_name': process_name,
                'attack_count': attack_count,
                'time_range': time_range,
                'details': f"{attack_count} events ({', '.join(detection_types)}): {'; '.join(details_list)}"
            })
            logger.info(f"Detected credential dumping for {username} with {process_name} ({attack_count} events)")

        if not detections:
            logger.warning("No credential dumping patterns detected")
        return detections

    def run(self):
        # Run the credential dumping detection process
        logger.info("Starting T1003 Credential Dumping Detection")
        df = self.load_csv()
        event_df = self.filter_relevant_events(df)
        detections = self.detect_credential_dumping(event_df)
        return detections

