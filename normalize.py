import pandas as pd
import re

def normalize_df(df: pd.DataFrame) -> pd.DataFrame:
    # Normalize the DataFrame to a standard format
    df = df.copy()

    # Rename columns
    column_map = {
        'datetime': 'datetime',
        'message': 'desc',
        'source_long': 'source_long',
        'parser': 'parser'
    }
    available_columns = {k: v for k, v in column_map.items() if k in df.columns}
    df = df.rename(columns=available_columns)

    # Ensure datetime is parsed
    if 'datetime' in df.columns:
        df['datetime'] = pd.to_datetime(df['datetime'], errors='coerce')

    # Fill missing values
    df['desc'] = df['desc'].fillna('').astype(str)
    df['parser'] = df['parser'].fillna('').astype(str)
    df['source_long'] = df['source_long'].fillna('').astype(str)

    # Extract event ID if not in a separate column
    if 'event_id' not in df.columns:
        df['event_id'] = df['desc'].str.extract(r'\[(\d+) /', expand=False).fillna('Unknown')

    return df

