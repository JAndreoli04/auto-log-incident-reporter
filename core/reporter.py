import json
from pathlib import Path
from typing import Dict, Any
import pandas as pd
from jinja2 import Environment, FileSystemLoader


class TimelineReporter:
    """Generate interactive HTML timeline reports from incident events."""

    def __init__(self, template_dir: str = "templates"):
        """Initialize reporter with template directory."""
        self.template_dir = Path(template_dir)
        self.env = Environment(loader=FileSystemLoader(self.template_dir))

    def render(
        self,
        events_df: pd.DataFrame,
        output_path: str,
    ) -> None:
        """
        Render events DataFrame to interactive HTML timeline.

        Args:
            events_df: DataFrame containing processed events with columns:
                      timestamp, source_ip, event_type, severity, description, metadata
            output_path: Path where HTML file will be written
        """
        # Ensure output directory exists
        output_file = Path(output_path)
        output_file.parent.mkdir(parents=True, exist_ok=True)

        # Calculate KPI metrics
        kpi = self._calculate_kpi(events_df)

        # Convert DataFrame to JSON-serializable format
        events_json = self._serialize_events(events_df)

        # Load template and render
        template = self.env.get_template("timeline_template.html")
        html_content = template.render(
            events_json=events_json,
            kpi=kpi,
        )

        # Write to file
        with open(output_file, "w") as f:
            f.write(html_content)

        print(f"✓ Report generated: {output_path}")

    def _calculate_kpi(self, df: pd.DataFrame) -> Dict[str, Any]:
        """Calculate key performance indicators from events."""
        total_events = len(df)
        failed_logins = len(df[df["event_type"] == "AUTH_FAILURE"])
        critical_alerts = len(df[df["severity"] == "CRITICAL"])
        alert_events = len(df[df["event_type"].str.startswith("ALERT_", na=False)])
        high_critical_events = len(
            df[df["severity"].isin(["HIGH", "CRITICAL"])]
        )

        return {
            "total_events": total_events,
            "failed_logins": failed_logins,
            "critical_alerts": critical_alerts,
            "alert_events": alert_events,
            "high_critical_events": high_critical_events,
        }

    def _serialize_events(self, df: pd.DataFrame) -> str:
        """Convert DataFrame events to JSON string for JavaScript consumption."""
        events = []

        for _, row in df.iterrows():
            event = {
                "timestamp": row["timestamp"],
                "source_ip": row["source_ip"],
                "destination_ip": row.get("destination_ip"),
                "event_type": row["event_type"],
                "severity": row["severity"],
                "description": row["description"],
                "metadata": row.get("metadata", {}),
            }

            # Handle datetime serialization
            if pd.notna(row["timestamp"]):
                if isinstance(row["timestamp"], pd.Timestamp):
                    event["timestamp"] = row["timestamp"].isoformat()
                elif isinstance(row["timestamp"], str):
                    event["timestamp"] = row["timestamp"]

            events.append(event)

        # Return as JSON string, which Jinja2 will mark as safe
        return json.dumps(events, default=str)
