"""Content relationship graph for X-POSURE."""

from collections import defaultdict
from typing import Optional, Set, List
from dataclasses import dataclass, field

from .models import Finding, Source


@dataclass
class Node:
    """Graph node representing content."""

    id: str
    type: str  # 'domain', 'subdomain', 'path', 'js_file', 'finding'
    url: str
    metadata: dict = field(default_factory=dict)
    parents: Set[str] = field(default_factory=set)
    children: Set[str] = field(default_factory=set)


@dataclass
class Edge:
    """Graph edge representing relationship."""

    source: str  # source node id
    target: str  # target node id
    type: str  # 'discovered_on', 'contains', 'paired_with', 'similar_to'
    metadata: dict = field(default_factory=dict)


class ContentGraph:
    """Graph tracking content relationships and evidence chains."""

    def __init__(self):
        """Initialize content graph."""
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []
        self.node_index: dict[str, Set[str]] = defaultdict(set)  # type -> node_ids

    def add_node(
        self,
        node_id: str,
        node_type: str,
        url: str,
        metadata: Optional[dict] = None,
    ) -> Node:
        """
        Add or update a node.

        Args:
            node_id: Unique node identifier
            node_type: Type of node
            url: URL associated with node
            metadata: Optional metadata

        Returns:
            The node
        """
        if node_id in self.nodes:
            # Update existing node
            node = self.nodes[node_id]
            if metadata:
                node.metadata.update(metadata)
            return node

        # Create new node
        node = Node(
            id=node_id,
            type=node_type,
            url=url,
            metadata=metadata or {},
        )

        self.nodes[node_id] = node
        self.node_index[node_type].add(node_id)

        return node

    def add_edge(
        self,
        source_id: str,
        target_id: str,
        edge_type: str,
        metadata: Optional[dict] = None,
    ) -> Edge:
        """
        Add relationship between nodes.

        Args:
            source_id: Source node ID
            target_id: Target node ID
            edge_type: Type of relationship
            metadata: Optional metadata

        Returns:
            The edge
        """
        # Create edge
        edge = Edge(
            source=source_id,
            target=target_id,
            type=edge_type,
            metadata=metadata or {},
        )

        self.edges.append(edge)

        # Update node relationships
        if source_id in self.nodes:
            self.nodes[source_id].children.add(target_id)
        if target_id in self.nodes:
            self.nodes[target_id].parents.add(source_id)

        return edge

    def track_discovery(self, source: Source, discovered_url: str, discovered_type: str):
        """
        Track that URL was discovered from source.

        Args:
            source: Source where discovery happened
            discovered_url: URL that was discovered
            discovered_type: Type of discovered content
        """
        # Create source node
        source_id = self._create_node_id(source.url)
        self.add_node(
            node_id=source_id,
            node_type=source.type,
            url=source.url,
        )

        # Create discovered node
        discovered_id = self._create_node_id(discovered_url)
        self.add_node(
            node_id=discovered_id,
            node_type=discovered_type,
            url=discovered_url,
        )

        # Link them
        self.add_edge(
            source_id=source_id,
            target_id=discovered_id,
            edge_type='discovered_on',
        )

    def track_finding(self, finding: Finding):
        """
        Track finding and link to all sources.

        Args:
            finding: Finding to track
        """
        # Create finding node
        finding_id = f"finding:{finding.id}"
        self.add_node(
            node_id=finding_id,
            node_type='finding',
            url='',
            metadata={
                'credential_type': finding.credential_type,
                'severity': finding.severity.value if finding.severity else 'unknown',
                'confidence': finding.confidence,
            },
        )

        # Link to all sources
        for source in finding.sources:
            source_id = self._create_node_id(source.url)

            # Ensure source node exists
            self.add_node(
                node_id=source_id,
                node_type=source.type,
                url=source.url,
            )

            # Link finding to source
            self.add_edge(
                source_id=source_id,
                target_id=finding_id,
                edge_type='contains',
                metadata={'source_type': source.type},
            )

    def link_pair(self, finding1: Finding, finding2: Finding):
        """
        Link two paired findings.

        Args:
            finding1: First finding
            finding2: Second finding
        """
        finding1_id = f"finding:{finding1.id}"
        finding2_id = f"finding:{finding2.id}"

        self.add_edge(
            source_id=finding1_id,
            target_id=finding2_id,
            edge_type='paired_with',
            metadata={
                'type1': finding1.credential_type,
                'type2': finding2.credential_type,
            },
        )

    def get_evidence_chain(self, finding_id: str) -> list[Node]:
        """
        Get full evidence chain for a finding.

        Args:
            finding_id: Finding ID to trace

        Returns:
            List of nodes in evidence chain (from root to finding)
        """
        chain = []
        current_id = f"finding:{finding_id}"

        # Traverse up the graph
        visited = set()
        stack = [current_id]

        while stack:
            node_id = stack.pop()

            if node_id in visited:
                continue
            visited.add(node_id)

            if node_id in self.nodes:
                node = self.nodes[node_id]
                chain.append(node)

                # Add parents to stack
                stack.extend(node.parents)

        return list(reversed(chain))

    def get_related_findings(self, finding_id: str, max_depth: int = 2) -> Set[str]:
        """
        Get related findings within max depth.

        Args:
            finding_id: Finding ID
            max_depth: Maximum graph distance

        Returns:
            Set of related finding IDs
        """
        related = set()
        current_id = f"finding:{finding_id}"

        # BFS to find related findings
        visited = set()
        queue = [(current_id, 0)]

        while queue:
            node_id, depth = queue.pop(0)

            if node_id in visited or depth > max_depth:
                continue
            visited.add(node_id)

            if node_id in self.nodes:
                node = self.nodes[node_id]

                # If this is a finding, add it
                if node.type == 'finding' and node_id != current_id:
                    related.add(node.id.replace('finding:', ''))

                # Add neighbors to queue
                if depth < max_depth:
                    for neighbor_id in node.parents | node.children:
                        queue.append((neighbor_id, depth + 1))

        return related

    def get_source_findings(self, source_url: str) -> list[str]:
        """
        Get all findings from a specific source.

        Args:
            source_url: Source URL

        Returns:
            List of finding IDs
        """
        source_id = self._create_node_id(source_url)

        if source_id not in self.nodes:
            return []

        findings = []
        for child_id in self.nodes[source_id].children:
            if child_id.startswith('finding:'):
                findings.append(child_id.replace('finding:', ''))

        return findings

    def get_paired_findings(self, finding_id: str) -> list[str]:
        """
        Get all findings paired with this one.

        Args:
            finding_id: Finding ID

        Returns:
            List of paired finding IDs
        """
        paired = []
        current_id = f"finding:{finding_id}"

        for edge in self.edges:
            if edge.type != 'paired_with':
                continue

            if edge.source == current_id:
                paired.append(edge.target.replace('finding:', ''))
            elif edge.target == current_id:
                paired.append(edge.source.replace('finding:', ''))

        return paired

    def _create_node_id(self, url: str) -> str:
        """
        Create consistent node ID from URL.

        Args:
            url: URL string

        Returns:
            Node ID
        """
        # Simple hash-based ID
        import hashlib
        return hashlib.md5(url.encode()).hexdigest()[:12]

    def get_stats(self) -> dict:
        """
        Get graph statistics.

        Returns:
            Statistics dictionary
        """
        node_types = defaultdict(int)
        for node in self.nodes.values():
            node_types[node.type] += 1

        edge_types = defaultdict(int)
        for edge in self.edges:
            edge_types[edge.type] += 1

        return {
            'total_nodes': len(self.nodes),
            'total_edges': len(self.edges),
            'node_types': dict(node_types),
            'edge_types': dict(edge_types),
            'avg_node_degree': (
                sum(len(n.parents) + len(n.children) for n in self.nodes.values()) / len(self.nodes)
                if self.nodes else 0
            ),
        }
