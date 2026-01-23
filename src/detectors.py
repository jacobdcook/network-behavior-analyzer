import pandas as pd
import numpy as np

class AnomalyDetector:
    def __init__(self, df):
        self.df = df

    def detect_beaconing(self, threshold_std=0.1):
        """
        Identify potential C2 beaconing by detecting rhythmic traffic patterns.
        Calculates the standard deviation of time intervals between packets in a flow.
        """
        if self.df.empty:
            return []

        anomalies = []
        # Group by source, destination, and destination port
        grouped = self.df.groupby(['src', 'dst', 'proto'])

        for (src, dst, proto), group in grouped:
            if len(group) < 5:  # Need enough packets to determine a pattern
                continue
            
            # Calculate time differences between consecutive packets
            intervals = group['timestamp'].diff().dt.total_seconds().dropna()
            
            if intervals.empty:
                continue

            # Rhythmic traffic has low variance in intervals
            std_dev = intervals.std()
            avg_interval = intervals.mean()

            if std_dev < threshold_std and avg_interval > 0:
                anomalies.append({
                    'type': 'Potential Beaconing',
                    'src': src,
                    'dst': dst,
                    'avg_interval': round(avg_interval, 2),
                    'std_dev': round(std_dev, 4),
                    'count': len(group)
                })
        
        return anomalies

    def detect_exfiltration(self, byte_threshold=1000000):
        """
        Detect potential data exfiltration by monitoring unusual upload volumes.
        """
        if self.df.empty:
            return []

        anomalies = []
        # Group by source and destination
        usage = self.df.groupby(['src', 'dst'])['size'].sum().reset_index()

        for _, row in usage.iterrows():
            if row['size'] > byte_threshold:
                anomalies.append({
                    'type': 'High Volume Upload',
                    'src': row['src'],
                    'dst': row['dst'],
                    'total_bytes': row['size'],
                    'risk': 'High'
                })
        
        return anomalies

if __name__ == "__main__":
    # Test with dummy data
    pass
