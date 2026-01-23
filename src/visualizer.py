import plotly.express as px
import pandas as pd

class Visualizer:
    def __init__(self, df):
        self.df = df

    def plot_traffic_volume(self, output_path='outputs/traffic_volume.html'):
        """Plot traffic volume over time."""
        if self.df.empty:
            print("No data to plot.")
            return

        # Resample data to see spikes
        df_resampled = self.df.set_index('timestamp').resample('1S').size().reset_index(name='packet_count')
        
        fig = px.line(df_resampled, x='timestamp', y='packet_count', title='Network Traffic Volume (Packets per Second)')
        fig.write_html(output_path)
        print(f"Traffic volume plot saved to {output_path}")

    def plot_protocol_distribution(self, output_path='outputs/protocol_dist.html'):
        """Plot distribution of protocols."""
        if self.df.empty:
            print("No data to plot.")
            return

        fig = px.pie(self.df, names='proto', title='Protocol Distribution')
        fig.write_html(output_path)
        print(f"Protocol distribution plot saved to {output_path}")

if __name__ == "__main__":
    # Test plotting
    pass
