import pandas as pd
from normalize import normalize_df

class LogParser:
    def __init__(self, df: pd.DataFrame):
        self.df = df

    def parse(self) -> pd.DataFrame:
        """Parse and normalize the input DataFrame."""
        try:
            normalized_df = normalize_df(self.df)
            return normalized_df
        except Exception as e:
            print(f"Error parsing logs: {e}")
            return self.df

