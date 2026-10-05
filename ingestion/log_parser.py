from pathlib import Path

import pandas as pd


NORMALIZED_FIELDS = [
    "timestamp",
    "source_ip",
    "destination_ip",
    "username",
    "event_type",
    "action",
    "status",
    "message",
    "source",
    "source_type",
]

COLUMN_ALIASES = {
    "timestamp": ["timestamp", "time", "datetime"],
    "source_ip": ["source_ip", "src_ip", "ip"],
    "destination_ip": ["destination_ip", "dst_ip", "dest_ip"],
    "username": ["username", "user", "account"],
    "event_type": ["event_type", "type", "event"],
    "action": ["action", "method"],
    "status": ["status", "result", "outcome"],
    "message": ["message", "request", "details"],
    "source": ["source", "log_source", "service"],
    "source_type": ["source_type", "dataset"],
}


def _find_column(df: pd.DataFrame, aliases: list[str]) -> str | None:
    lowered = {column.lower(): column for column in df.columns}
    for alias in aliases:
        if alias in lowered:
            return lowered[alias]
    return None


def parse_log_file(file_path: str | Path, source_type: str = "sample") -> pd.DataFrame:
    df = pd.read_csv(file_path)
    normalized = pd.DataFrame()

    for normalized_field, aliases in COLUMN_ALIASES.items():
        source_column = _find_column(df, aliases)
        normalized[normalized_field] = df[source_column] if source_column else ""

    normalized["timestamp"] = pd.to_datetime(normalized["timestamp"], errors="coerce")
    normalized = normalized.dropna(subset=["timestamp"])
    normalized["timestamp"] = normalized["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    for field in NORMALIZED_FIELDS:
        normalized[field] = normalized[field].fillna("").astype(str)

    if "destination_port" in df.columns:
        normalized["destination_port"] = pd.to_numeric(df["destination_port"], errors="coerce")

    if "source_type" not in df.columns:
        normalized["source_type"] = source_type

    return normalized


def parse_log_directory(directory_path: str | Path, source_type: str = "sample") -> pd.DataFrame:
    directory = Path(directory_path)
    parsed_frames = []

    for csv_file in sorted(directory.glob("*.csv")):
        frame = parse_log_file(csv_file, source_type=source_type)
        if not frame.empty:
            parsed_frames.append(frame)

    if not parsed_frames:
        return pd.DataFrame(columns=NORMALIZED_FIELDS)

    return pd.concat(parsed_frames, ignore_index=True)
