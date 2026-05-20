import asyncio
import time
from collections import defaultdict
from datetime import timedelta
from typing import List, Dict, Tuple, Optional
import pandas as pd
import requests

from core.parsers import LogEvent


class IPGeolocationCache:
    """Cache for IP geolocation API calls to avoid rate limiting."""

    def __init__(self, ttl_seconds: int = 3600):
        self.cache: Dict[str, Dict] = {}
        self.ttl = ttl_seconds
        self.timestamps: Dict[str, float] = {}

    def get(self, ip: str) -> Optional[Dict]:
        """Get cached geolocation for IP if available and not expired."""
        if ip in self.cache:
            if time.time() - self.timestamps[ip] < self.ttl:
                return self.cache[ip]
            else:
                # Expired, remove it
                del self.cache[ip]
                del self.timestamps[ip]
        return None

    def set(self, ip: str, data: Dict) -> None:
        """Cache geolocation data for an IP."""
        self.cache[ip] = data
        self.timestamps[ip] = time.time()


class IncidentEngine:
    """Security heuristics engine for log analysis."""

    BRUTE_FORCE_FAILURE_THRESHOLD = 3
    BRUTE_FORCE_TIME_WINDOW = timedelta(minutes=5)
    IMPOSSIBLE_TRAVEL_TIME_THRESHOLD = timedelta(minutes=15)
    IMPOSSIBLE_TRAVEL_MIN_DISTANCE_KM = 900  # Roughly continental distance

    def __init__(self, enable_geolocation: bool = True):
        self.enable_geolocation = enable_geolocation
        self.geo_cache = IPGeolocationCache()
        self.alerts = []

    def process(self, events: List[LogEvent]) -> pd.DataFrame:
        """
        Process events through heuristics engine.
        Returns a DataFrame with all events (original + synthetic alerts) sorted by timestamp.
        """
        # Convert to DataFrame for easier manipulation
        df = pd.DataFrame([e.to_dict() for e in events])

        if df.empty:
            return df

        # Convert timestamp strings back to datetime for processing
        df["timestamp"] = pd.to_datetime(df["timestamp"])

        # Enrich with geolocation first (needed for impossible travel detection)
        if self.enable_geolocation:
            df = self._enrich_geolocation(df)

        # Detect impossible travel (requires geolocation data)
        df = self._detect_impossible_travel(df, events)

        # Detect brute force attacks
        df = self._detect_brute_force(df, events)

        # Sort by timestamp
        df = df.sort_values("timestamp").reset_index(drop=True)

        return df

    def _detect_brute_force(self, df: pd.DataFrame, events: List[LogEvent]) -> pd.DataFrame:
        """Detect brute force attacks and update DataFrame."""
        # Create index for events by ID for quick lookup
        event_map = {id(e): e for e in events}

        # Group by source_ip
        for source_ip in df["source_ip"].unique():
            ip_events = df[df["source_ip"] == source_ip].copy()

            # Find all AUTH_SUCCESS events for this IP
            success_events = ip_events[ip_events["event_type"] == "AUTH_SUCCESS"]

            for success_idx, success_row in success_events.iterrows():
                success_time = success_row["timestamp"]
                window_start = success_time - self.BRUTE_FORCE_TIME_WINDOW

                # Count AUTH_FAILURE events in the 5-min window before this success
                window_events = ip_events[
                    (ip_events["event_type"] == "AUTH_FAILURE")
                    & (ip_events["timestamp"] >= window_start)
                    & (ip_events["timestamp"] < success_time)
                ]

                failure_count = len(window_events)

                # If >= 3 failures before success, generate alert
                if failure_count >= self.BRUTE_FORCE_FAILURE_THRESHOLD:
                    # Update original success event severity to HIGH
                    df.at[success_idx, "severity"] = "HIGH"

                    # Create synthetic alert event
                    alert = {
                        "timestamp": success_row["timestamp"].isoformat(),
                        "source_ip": source_ip,
                        "destination_ip": success_row.get("destination_ip"),
                        "event_type": "ALERT_BRUTE_FORCE_SUCCESS",
                        "severity": "CRITICAL",
                        "description": (
                            f"Brute force attack succeeded: {failure_count} failed login attempts "
                            f"from {source_ip} followed by successful login for '{success_row['metadata'].get('user', 'unknown')}'"
                        ),
                        "metadata": {
                            "failure_count": failure_count,
                            "success_user": success_row["metadata"].get("user", "unknown"),
                            "source_ip": source_ip,
                        },
                    }
                    self.alerts.append(alert)

        # Append alerts to DataFrame
        if self.alerts:
            alerts_df = pd.DataFrame(self.alerts)
            alerts_df["timestamp"] = pd.to_datetime(alerts_df["timestamp"])
            df = pd.concat([df, alerts_df], ignore_index=True)

        return df

    def _detect_impossible_travel(
        self, df: pd.DataFrame, events: List[LogEvent]
    ) -> pd.DataFrame:
        """Detect impossible travel (user in two locations too quickly)."""
        # Track per-user state: user -> (timestamp, IP, country)
        user_state: Dict[str, Tuple[pd.Timestamp, str, str]] = {}

        # Sort by timestamp to process chronologically
        df_sorted = df.sort_values("timestamp")

        for idx, row in df_sorted.iterrows():
            if row["event_type"] not in ["AUTH_SUCCESS", "AUTH_FAILURE"]:
                continue

            user = row["metadata"].get("user", "unknown") if isinstance(row["metadata"], dict) else "unknown"
            source_ip = row["source_ip"]
            timestamp = row["timestamp"]

            # Get country for this IP (from geolocation enrichment)
            country = None
            if isinstance(row["metadata"], dict):
                country = row["metadata"].get("country", None)

            if user in user_state and country and country != "Unknown":
                prev_time, prev_ip, prev_country = user_state[user]
                time_delta = timestamp - prev_time

                # Check if different country and within time threshold
                if (
                    prev_country != country
                    and prev_country != "Unknown"
                    and time_delta < self.IMPOSSIBLE_TRAVEL_TIME_THRESHOLD
                ):
                    # Generate alert
                    alert = {
                        "timestamp": timestamp.isoformat(),
                        "source_ip": source_ip,
                        "destination_ip": row.get("destination_ip"),
                        "event_type": "ALERT_IMPOSSIBLE_TRAVEL",
                        "severity": "HIGH",
                        "description": (
                            f"Impossible travel detected: User '{user}' logged in from "
                            f"{prev_country} ({prev_ip}) at {prev_time.isoformat()}, "
                            f"then from {country} ({source_ip}) at {timestamp.isoformat()} "
                            f"(only {time_delta.total_seconds():.0f} seconds apart)"
                        ),
                        "metadata": {
                            "user": user,
                            "prev_country": prev_country,
                            "prev_ip": prev_ip,
                            "curr_country": country,
                            "curr_ip": source_ip,
                            "time_delta_seconds": time_delta.total_seconds(),
                        },
                    }
                    self.alerts.append(alert)

                    # Mark this row in DataFrame as HIGH severity if it's a success
                    if row["event_type"] == "AUTH_SUCCESS":
                        df.at[idx, "severity"] = "HIGH"

            # Update user state if valid geolocation available
            if country and country != "Unknown":
                user_state[user] = (timestamp, source_ip, country)

        # Append impossible travel alerts to DataFrame
        impossible_travel_alerts = [
            a for a in self.alerts
            if a["event_type"] == "ALERT_IMPOSSIBLE_TRAVEL"
        ]
        
        if impossible_travel_alerts:
            alerts_df = pd.DataFrame(impossible_travel_alerts)
            alerts_df["timestamp"] = pd.to_datetime(alerts_df["timestamp"])
            df = pd.concat([df, alerts_df], ignore_index=True)

        return df

    def _enrich_geolocation(self, df: pd.DataFrame) -> pd.DataFrame:
        """Enrich events with geolocation data from IP addresses."""
        unique_ips = df["source_ip"].unique()

        for ip in unique_ips:
            # Check cache first
            geo_data = self.geo_cache.get(ip)

            if not geo_data:
                # Fetch from API
                geo_data = self._fetch_geolocation(ip)
                if geo_data:
                    self.geo_cache.set(ip, geo_data)

            # Update rows with this IP
            if geo_data:
                for idx, row in df[df["source_ip"] == ip].iterrows():
                    metadata = row["metadata"].copy() if row["metadata"] else {}
                    metadata.update(geo_data)
                    df.at[idx, "metadata"] = metadata

        return df

    def _fetch_geolocation(self, ip: str) -> Optional[Dict]:
        """Fetch geolocation data from ip-api.com."""
        try:
            response = requests.get(
                f"http://ip-api.com/json/{ip}",
                timeout=5,
                params={"fields": "country,city,isp,status"}
            )
            response.raise_for_status()
            data = response.json()

            if data.get("status") == "success":
                return {
                    "country": data.get("country", "Unknown"),
                    "city": data.get("city", "Unknown"),
                    "isp": data.get("isp", "Unknown"),
                }
            else:
                return {
                    "country": "Unknown",
                    "city": "Unknown",
                    "isp": "Unknown",
                }
        except (requests.RequestException, ValueError) as e:
            print(f"[GeolocationError] Failed to fetch geolocation for {ip}: {e}")
            return {
                "country": "Unknown",
                "city": "Unknown",
                "isp": "Unknown",
            }
