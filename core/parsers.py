import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Any, Optional


@dataclass
class LogEvent:
    """Unified security event schema."""
    timestamp: datetime
    source_ip: str
    destination_ip: Optional[str]
    event_type: str  # AUTH_SUCCESS, AUTH_FAILURE, ALERT_BRUTE_FORCE_SUCCESS, ALERT_IMPOSSIBLE_TRAVEL
    severity: str    # INFO, LOW, MEDIUM, HIGH, CRITICAL
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert event to dictionary for serialization."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "event_type": self.event_type,
            "severity": self.severity,
            "description": self.description,
            "metadata": self.metadata,
        }


class BaseParser(ABC):
    """Abstract base class for log parsers."""

    @abstractmethod
    def parse(self, lines: List[str]) -> List[LogEvent]:
        """Parse log lines and return list of LogEvent objects."""
        pass


class AuthLogParser(BaseParser):
    """Parser for Linux /var/log/auth.log files."""

    # Regex patterns for auth.log events
    FAILED_PASSWORD_PATTERN = re.compile(
        r"^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+"
        r"sshd\[\d+\]:\s+Failed password for\s+(?:invalid user\s+)?(?P<user>\S+)\s+"
        r"from\s+(?P<source_ip>[\d.]+)\s+port\s+(?P<port>\d+)"
    )

    ACCEPTED_PASSWORD_PATTERN = re.compile(
        r"^(?P<month>\w+)\s+(?P<day>\d+)\s+(?P<time>\d+:\d+:\d+)\s+(?P<hostname>\S+)\s+"
        r"sshd\[\d+\]:\s+Accepted password for\s+(?P<user>\S+)\s+"
        r"from\s+(?P<source_ip>[\d.]+)\s+port\s+(?P<port>\d+)"
    )

    def __init__(self, year: int = None):
        """Initialize parser. Default to current year if not provided."""
        self.year = year or datetime.now().year

    def parse(self, lines: List[str]) -> List[LogEvent]:
        """Parse auth.log lines into LogEvent objects."""
        events = []
        skipped = 0

        for line in lines:
            event = self._parse_line(line)
            if event:
                events.append(event)
            else:
                skipped += 1

        if skipped > 0:
            print(f"[AuthLogParser] Skipped {skipped} malformed lines")

        return events

    def _parse_line(self, line: str) -> Optional[LogEvent]:
        """Parse a single auth.log line."""
        # Try failed password pattern
        match = self.FAILED_PASSWORD_PATTERN.match(line)
        if match:
            return self._create_event(
                match, event_type="AUTH_FAILURE", severity="INFO"
            )

        # Try accepted password pattern
        match = self.ACCEPTED_PASSWORD_PATTERN.match(line)
        if match:
            return self._create_event(
                match, event_type="AUTH_SUCCESS", severity="LOW"
            )

        return None

    def _create_event(self, match, event_type: str, severity: str) -> LogEvent:
        """Create a LogEvent from a regex match."""
        month_str = match.group("month")
        day = int(match.group("day"))
        time_str = match.group("time")
        user = match.group("user")
        source_ip = match.group("source_ip")
        port = match.group("port")

        # Parse timestamp (assume current year)
        try:
            timestamp_str = f"{self.year} {month_str} {day:02d} {time_str}"
            timestamp = datetime.strptime(timestamp_str, "%Y %b %d %H:%M:%S")
        except ValueError:
            # Fallback: if parsing fails, use current time
            timestamp = datetime.now()

        description = (
            f"{'Failed' if event_type == 'AUTH_FAILURE' else 'Successful'} "
            f"SSH login attempt for user '{user}' from {source_ip}:{port}"
        )

        return LogEvent(
            timestamp=timestamp,
            source_ip=source_ip,
            destination_ip=None,  # auth.log doesn't typically have destination
            event_type=event_type,
            severity=severity,
            description=description,
            metadata={"user": user, "port": port},
        )
