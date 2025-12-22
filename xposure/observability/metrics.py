"""Metrics collection for X-POSURE."""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from threading import Lock
from typing import Dict, List, Optional, Any
from contextlib import contextmanager


@dataclass
class Counter:
    """Simple counter metric."""

    name: str
    description: str
    labels: List[str] = field(default_factory=list)
    _values: Dict[tuple, float] = field(default_factory=lambda: defaultdict(float))
    _lock: Lock = field(default_factory=Lock)

    def inc(self, value: float = 1, **label_values):
        """Increment counter."""
        key = self._label_key(label_values)
        with self._lock:
            self._values[key] += value

    def _label_key(self, label_values: dict) -> tuple:
        """Generate label key tuple."""
        return tuple(label_values.get(l, '') for l in self.labels)

    def get(self, **label_values) -> float:
        """Get counter value."""
        key = self._label_key(label_values)
        return self._values.get(key, 0)

    def collect(self) -> List[dict]:
        """Collect all counter values."""
        results = []
        for key, value in self._values.items():
            labels = dict(zip(self.labels, key))
            results.append({
                'name': self.name,
                'type': 'counter',
                'value': value,
                'labels': labels,
            })
        return results


@dataclass
class Gauge:
    """Simple gauge metric."""

    name: str
    description: str
    labels: List[str] = field(default_factory=list)
    _values: Dict[tuple, float] = field(default_factory=lambda: defaultdict(float))
    _lock: Lock = field(default_factory=Lock)

    def set(self, value: float, **label_values):
        """Set gauge value."""
        key = self._label_key(label_values)
        with self._lock:
            self._values[key] = value

    def inc(self, value: float = 1, **label_values):
        """Increment gauge."""
        key = self._label_key(label_values)
        with self._lock:
            self._values[key] += value

    def dec(self, value: float = 1, **label_values):
        """Decrement gauge."""
        key = self._label_key(label_values)
        with self._lock:
            self._values[key] -= value

    def _label_key(self, label_values: dict) -> tuple:
        """Generate label key tuple."""
        return tuple(label_values.get(l, '') for l in self.labels)

    def get(self, **label_values) -> float:
        """Get gauge value."""
        key = self._label_key(label_values)
        return self._values.get(key, 0)

    def collect(self) -> List[dict]:
        """Collect all gauge values."""
        results = []
        for key, value in self._values.items():
            labels = dict(zip(self.labels, key))
            results.append({
                'name': self.name,
                'type': 'gauge',
                'value': value,
                'labels': labels,
            })
        return results


@dataclass
class Histogram:
    """Simple histogram metric with buckets."""

    name: str
    description: str
    labels: List[str] = field(default_factory=list)
    buckets: List[float] = field(default_factory=lambda: [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10])
    _values: Dict[tuple, List[float]] = field(default_factory=lambda: defaultdict(list))
    _lock: Lock = field(default_factory=Lock)

    def observe(self, value: float, **label_values):
        """Observe a value."""
        key = self._label_key(label_values)
        with self._lock:
            self._values[key].append(value)
            # Keep only last 10000 observations per label set
            if len(self._values[key]) > 10000:
                self._values[key] = self._values[key][-10000:]

    def _label_key(self, label_values: dict) -> tuple:
        """Generate label key tuple."""
        return tuple(label_values.get(l, '') for l in self.labels)

    @contextmanager
    def time(self, **label_values):
        """Context manager to time operations."""
        start = time.perf_counter()
        try:
            yield
        finally:
            duration = time.perf_counter() - start
            self.observe(duration, **label_values)

    def get_stats(self, **label_values) -> dict:
        """Get histogram statistics."""
        key = self._label_key(label_values)
        values = self._values.get(key, [])

        if not values:
            return {'count': 0, 'sum': 0, 'avg': 0, 'min': 0, 'max': 0, 'p50': 0, 'p95': 0, 'p99': 0}

        sorted_values = sorted(values)
        count = len(values)

        return {
            'count': count,
            'sum': sum(values),
            'avg': sum(values) / count,
            'min': min(values),
            'max': max(values),
            'p50': sorted_values[int(count * 0.5)],
            'p95': sorted_values[int(count * 0.95)] if count >= 20 else sorted_values[-1],
            'p99': sorted_values[int(count * 0.99)] if count >= 100 else sorted_values[-1],
        }

    def collect(self) -> List[dict]:
        """Collect histogram data."""
        results = []
        for key, values in self._values.items():
            labels = dict(zip(self.labels, key))
            stats = self.get_stats(**labels)
            results.append({
                'name': self.name,
                'type': 'histogram',
                'labels': labels,
                'stats': stats,
            })
        return results


class Metrics:
    """Metrics registry and collector."""

    def __init__(self, prefix: str = 'xposure'):
        """
        Initialize metrics registry.

        Args:
            prefix: Metric name prefix
        """
        self.prefix = prefix
        self._metrics: Dict[str, Any] = {}
        self._lock = Lock()

        # Register default metrics
        self._register_defaults()

    def _register_defaults(self):
        """Register default X-POSURE metrics."""
        # Scan metrics
        self.register_counter(
            'scans_total',
            'Total number of scans',
            ['status'],
        )
        self.register_histogram(
            'scan_duration_seconds',
            'Scan duration in seconds',
            ['target_type'],
        )
        self.register_gauge(
            'scans_active',
            'Number of active scans',
        )

        # Finding metrics
        self.register_counter(
            'findings_total',
            'Total findings detected',
            ['type', 'severity'],
        )
        self.register_counter(
            'findings_verified',
            'Total verified findings',
            ['type', 'status'],
        )
        self.register_counter(
            'findings_suppressed',
            'Total suppressed findings',
            ['type'],
        )

        # Verification metrics
        self.register_counter(
            'verifications_total',
            'Total verifications performed',
            ['verifier', 'status'],
        )
        self.register_histogram(
            'verification_duration_seconds',
            'Verification duration in seconds',
            ['verifier'],
        )

        # Discovery metrics
        self.register_counter(
            'discovery_requests_total',
            'Total discovery requests',
            ['discoverer', 'status'],
        )
        self.register_histogram(
            'discovery_duration_seconds',
            'Discovery duration in seconds',
            ['discoverer'],
        )

        # API metrics
        self.register_counter(
            'api_requests_total',
            'Total API requests',
            ['method', 'endpoint', 'status'],
        )
        self.register_histogram(
            'api_request_duration_seconds',
            'API request duration in seconds',
            ['method', 'endpoint'],
        )

        # Webhook metrics
        self.register_counter(
            'webhooks_sent_total',
            'Total webhooks sent',
            ['event', 'status'],
        )

    def register_counter(self, name: str, description: str, labels: List[str] = None) -> Counter:
        """Register a counter metric."""
        full_name = f'{self.prefix}_{name}'
        counter = Counter(name=full_name, description=description, labels=labels or [])
        with self._lock:
            self._metrics[full_name] = counter
        return counter

    def register_gauge(self, name: str, description: str, labels: List[str] = None) -> Gauge:
        """Register a gauge metric."""
        full_name = f'{self.prefix}_{name}'
        gauge = Gauge(name=full_name, description=description, labels=labels or [])
        with self._lock:
            self._metrics[full_name] = gauge
        return gauge

    def register_histogram(
        self,
        name: str,
        description: str,
        labels: List[str] = None,
        buckets: List[float] = None,
    ) -> Histogram:
        """Register a histogram metric."""
        full_name = f'{self.prefix}_{name}'
        histogram = Histogram(
            name=full_name,
            description=description,
            labels=labels or [],
            buckets=buckets or [0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10],
        )
        with self._lock:
            self._metrics[full_name] = histogram
        return histogram

    def get(self, name: str) -> Optional[Any]:
        """Get a metric by name."""
        full_name = f'{self.prefix}_{name}'
        return self._metrics.get(full_name)

    def counter(self, name: str) -> Counter:
        """Get counter, creating if needed."""
        metric = self.get(name)
        if metric is None:
            metric = self.register_counter(name, name)
        return metric

    def gauge(self, name: str) -> Gauge:
        """Get gauge, creating if needed."""
        metric = self.get(name)
        if metric is None:
            metric = self.register_gauge(name, name)
        return metric

    def histogram(self, name: str) -> Histogram:
        """Get histogram, creating if needed."""
        metric = self.get(name)
        if metric is None:
            metric = self.register_histogram(name, name)
        return metric

    def collect_all(self) -> List[dict]:
        """Collect all metrics."""
        results = []
        for metric in self._metrics.values():
            results.extend(metric.collect())
        return results

    def to_prometheus(self) -> str:
        """Export metrics in Prometheus text format."""
        lines = []

        for name, metric in self._metrics.items():
            # Add help and type
            lines.append(f'# HELP {name} {metric.description}')

            if isinstance(metric, Counter):
                lines.append(f'# TYPE {name} counter')
                for item in metric.collect():
                    label_str = self._format_labels(item['labels'])
                    lines.append(f'{name}{label_str} {item["value"]}')

            elif isinstance(metric, Gauge):
                lines.append(f'# TYPE {name} gauge')
                for item in metric.collect():
                    label_str = self._format_labels(item['labels'])
                    lines.append(f'{name}{label_str} {item["value"]}')

            elif isinstance(metric, Histogram):
                lines.append(f'# TYPE {name} histogram')
                for item in metric.collect():
                    label_str = self._format_labels(item['labels'])
                    stats = item['stats']
                    lines.append(f'{name}_count{label_str} {stats["count"]}')
                    lines.append(f'{name}_sum{label_str} {stats["sum"]}')

            lines.append('')

        return '\n'.join(lines)

    def _format_labels(self, labels: dict) -> str:
        """Format labels for Prometheus."""
        if not labels:
            return ''
        parts = [f'{k}="{v}"' for k, v in labels.items() if v]
        return '{' + ','.join(parts) + '}' if parts else ''

    def to_json(self) -> dict:
        """Export metrics as JSON."""
        return {
            'metrics': self.collect_all(),
        }


# Global metrics instance
_metrics: Optional[Metrics] = None


def get_metrics() -> Metrics:
    """Get or create global metrics instance."""
    global _metrics
    if _metrics is None:
        _metrics = Metrics()
    return _metrics


# Convenience functions
def inc_findings(credential_type: str, severity: str, count: int = 1):
    """Increment findings counter."""
    get_metrics().counter('findings_total').inc(count, type=credential_type, severity=severity)


def inc_scans(status: str):
    """Increment scans counter."""
    get_metrics().counter('scans_total').inc(1, status=status)


def observe_scan_duration(duration: float, target_type: str = 'url'):
    """Record scan duration."""
    get_metrics().histogram('scan_duration_seconds').observe(duration, target_type=target_type)


def observe_verification_duration(duration: float, verifier: str):
    """Record verification duration."""
    get_metrics().histogram('verification_duration_seconds').observe(duration, verifier=verifier)
