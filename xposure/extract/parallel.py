"""Parallel extraction pipeline using ProcessPoolExecutor.

Offloads CPU-bound regex scanning, entropy analysis, and decode chains
to separate processes to bypass the GIL. The async engine feeds content
in, and collects Candidate results back.
"""

import math
import re
from concurrent.futures import ProcessPoolExecutor
from typing import Optional

from ..core.models import Candidate, Source


# ── Module-level functions (must be picklable for multiprocessing) ──


def _shannon_entropy(s: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not s:
        return 0.0
    prob = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * math.log2(p) for p in prob if p > 0)


def _scan_content_in_process(
    content: str,
    source_type: str,
    source_url: str,
    source_path: str,
    label: str,
    source_type_hint: str,
    rules_dir: Optional[str],
    max_decode_depth: int,
    verbose: bool,
) -> dict:
    """Run CPU-bound extraction in a worker process.

    This function is called in a subprocess via ProcessPoolExecutor.
    It must be a module-level function (not a method) so it's picklable.

    Returns a plain dict (not model objects) since results cross process
    boundaries via pickle.
    """
    from ..rules.engine import RuleEngine
    from ..extract.decode import DecodeChain
    from ..extract.entropy import FalsePositiveDetector, EntropyAnalyzer
    from ..extract.jwt_prescan import JWTPreScanner

    rule_engine = RuleEngine(rules_dir)
    decoder = DecodeChain(max_depth=max_decode_depth)
    fp_detector = FalsePositiveDetector()
    jwt_prescanner = JWTPreScanner()
    entropy_analyzer = EntropyAnalyzer()

    source = Source(type=source_type, url=source_url, path=source_path)

    candidates = []
    filtered_count = 0
    decoded_blobs = 0

    if not content or len(content) < 10:
        return {
            'candidates': [],
            'filtered_count': 0,
            'decoded_blobs': 0,
            'label': label,
        }

    # 0. JWT pre-extraction
    masked_content, extracted_jwts = jwt_prescanner.prescan(content)

    for jwt_token in extracted_jwts:
        candidates.append({
            'type': 'jwt_token',
            'value': jwt_token.raw,
            'source_type': source_type,
            'source_url': source_url,
            'source_path': source_path,
            'entropy': _shannon_entropy(jwt_token.raw),
            'context': content[max(0, jwt_token.start - 100):jwt_token.end + 100],
            'confidence': 0.8,
        })

    # 0b. Entropy pre-scan
    entropy_hits = entropy_analyzer.scan_for_high_entropy_strings(masked_content)
    for hit in entropy_hits:
        is_fp, _ = fp_detector.is_false_positive(hit['value'], hit['context'])
        if not is_fp:
            candidates.append({
                'type': 'high_entropy_string',
                'value': hit['value'],
                'source_type': source_type,
                'source_url': source_url,
                'source_path': source_path,
                'entropy': hit['entropy'],
                'context': hit['context'],
                'confidence': 0.4,
            })

    # 1. Rules-based scan on masked content
    raw_candidates = list(rule_engine.scan(masked_content, source))

    # 2. Filter false positives
    for candidate in raw_candidates:
        is_fp, reason = fp_detector.is_false_positive(
            candidate.value,
            candidate.context,
            source_type_hint or source.type,
        )
        if is_fp:
            filtered_count += 1
            continue

        adjustment = fp_detector.get_confidence_adjustment(
            candidate.value,
            candidate.context,
            source_type_hint or source.type,
        )
        adjusted_confidence = max(0.0, min(1.0, candidate.confidence + adjustment))

        candidates.append({
            'type': candidate.type,
            'value': candidate.value,
            'source_type': source_type,
            'source_url': source_url,
            'source_path': source_path,
            'entropy': candidate.entropy,
            'context': candidate.context,
            'confidence': adjusted_confidence,
        })

    # 3. Decode chains
    try:
        sample_size = min(len(content), 5000)
        decoded_variants = list(decoder.decode_all(content[:sample_size]))
        decoded_blobs = max(0, len(decoded_variants) - 1)

        for decoded_content, decode_path in decoded_variants[1:]:
            if decode_path and decoded_content:
                source_decoded = Source(
                    type='decoded',
                    url=source_url,
                    path=' -> '.join(decode_path),
                )
                decoded_candidates = list(rule_engine.scan(decoded_content, source_decoded))
                for dc in decoded_candidates:
                    is_fp, _ = fp_detector.is_false_positive(dc.value, dc.context)
                    if not is_fp:
                        candidates.append({
                            'type': dc.type,
                            'value': dc.value,
                            'source_type': 'decoded',
                            'source_url': source_url,
                            'source_path': ' -> '.join(decode_path),
                            'entropy': dc.entropy,
                            'context': dc.context,
                            'confidence': dc.confidence,
                        })
    except Exception:
        pass

    return {
        'candidates': candidates,
        'filtered_count': filtered_count,
        'decoded_blobs': decoded_blobs,
        'label': label,
    }


class ParallelExtractor:
    """Manages a ProcessPoolExecutor for parallel content extraction.

    Usage:
        extractor = ParallelExtractor(workers=4)
        futures = []
        for content, source, label in items:
            fut = extractor.submit(content, source, label)
            futures.append(fut)
        for result in extractor.collect(futures):
            # result is a dict with 'candidates', 'filtered_count', etc.
            ...
        extractor.shutdown()
    """

    def __init__(
        self,
        workers: Optional[int] = None,
        rules_dir: Optional[str] = None,
        max_decode_depth: int = 5,
        verbose: bool = False,
    ):
        self._workers = workers
        self._rules_dir = rules_dir
        self._max_decode_depth = max_decode_depth
        self._verbose = verbose
        self._pool = ProcessPoolExecutor(max_workers=workers)

    def submit(
        self,
        content: str,
        source: Source,
        label: str,
        source_type_hint: str = "",
    ):
        """Submit content for extraction in a worker process.

        Returns a Future that resolves to a result dict.
        """
        return self._pool.submit(
            _scan_content_in_process,
            content=content,
            source_type=source.type,
            source_url=source.url,
            source_path=source.path or "",
            label=label,
            source_type_hint=source_type_hint,
            rules_dir=self._rules_dir,
            max_decode_depth=self._max_decode_depth,
            verbose=self._verbose,
        )

    def collect(self, futures: list) -> list[dict]:
        """Wait for all futures and return results."""
        results = []
        for fut in futures:
            try:
                results.append(fut.result())
            except Exception:
                pass
        return results

    def shutdown(self):
        """Shut down the process pool."""
        self._pool.shutdown(wait=False)

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.shutdown()
