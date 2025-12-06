from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, cast

import yaml  # type: ignore[import]

ENV_VAR_MAPPING_PATHS = "UEBA_MAPPING_PATHS"
DEFAULT_MAPPING_PATH = Path("config/mappings/default.yml")
CANONICAL_FIELDS = ("entity_id", "entity_type", "severity", "timestamp")


class MappingLoaderError(Exception):
    """Base exception for mapping loader issues."""


class MappingValidationError(MappingLoaderError):
    """Raised when a mapping file fails validation."""

    def __init__(self, message: str, file_path: Path, line: Optional[int] = None):
        location = f"{file_path}:{line}" if line is not None else str(file_path)
        super().__init__(f"{location} - {message}")
        self.file_path = file_path
        self.line = line


class MappingPriority(str, Enum):
    GLOBAL = "global"
    INTEGRATION = "integration"
    EMERGENCY_OVERRIDE = "emergency_override"

    @property
    def order(self) -> int:
        return {
            MappingPriority.GLOBAL: 0,
            MappingPriority.INTEGRATION: 1,
            MappingPriority.EMERGENCY_OVERRIDE: 2,
        }[self]


class LineLoader(yaml.SafeLoader):
    """YAML loader that annotates nodes with line numbers."""


class _LineDict(dict):
    __slots__ = ("_line",)


class _LineList(list):
    __slots__ = ("_line",)


def _construct_mapping(loader, node, deep=False):
    mapping = _LineDict()
    mapping._line = node.start_mark.line + 1  # type: ignore[attr-defined]
    loader.flatten_mapping(node)
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        value = loader.construct_object(value_node, deep=deep)
        mapping[key] = value
    return mapping


def _construct_sequence(loader, node, deep=False):
    seq = _LineList()
    seq._line = node.start_mark.line + 1  # type: ignore[attr-defined]
    for child in node.value:
        seq.append(loader.construct_object(child, deep=deep))
    return seq


LineLoader.add_constructor(  # type: ignore[attr-defined]
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, _construct_mapping
)
LineLoader.add_constructor(  # type: ignore[attr-defined]
    yaml.resolver.BaseResolver.DEFAULT_SEQUENCE_TAG, _construct_sequence
)


def _get_line(value: object) -> Optional[int]:
    return getattr(value, "_line", None)


@dataclass
class ResolvedMapping:
    entity_id: Optional[str] = None
    entity_type: Optional[str] = None
    severity: Optional[str] = None
    timestamp: Optional[str] = None
    enrichment: Dict[str, str] = field(default_factory=dict)

    def copy(self) -> "ResolvedMapping":
        return ResolvedMapping(
            entity_id=self.entity_id,
            entity_type=self.entity_type,
            severity=self.severity,
            timestamp=self.timestamp,
            enrichment=dict(self.enrichment),
        )

    def as_dict(self) -> Dict[str, object]:
        data: Dict[str, object] = {
            "entity_id": self.entity_id,
            "entity_type": self.entity_type,
            "severity": self.severity,
            "timestamp": self.timestamp,
            "enrichment": dict(self.enrichment),
        }
        return data


@dataclass
class PartialFieldSet:
    entity_id: Optional[str] = None
    entity_type: Optional[str] = None
    severity: Optional[str] = None
    timestamp: Optional[str] = None
    enrichment: Optional[Dict[str, Optional[str]]] = None
    provided_fields: set[str] = field(default_factory=set)
    file_path: Optional[Path] = None
    line: Optional[int] = None

    def apply_to(self, resolved: ResolvedMapping) -> ResolvedMapping:
        updated = resolved.copy()
        for field_name in CANONICAL_FIELDS:
            if field_name in self.provided_fields:
                setattr(updated, field_name, getattr(self, field_name))
        if "enrichment" in self.provided_fields:
            if self.enrichment is None:
                updated.enrichment.clear()
            else:
                for key, value in self.enrichment.items():
                    if value is None:
                        updated.enrichment.pop(key, None)
                    else:
                        updated.enrichment[key] = value
        return updated

    def ensure_fields(self, required: Iterable[str], context: str) -> None:
        missing = [field for field in required if field not in self.provided_fields]
        if missing:
            file_path = self.file_path or Path("<unknown>")
            raise MappingValidationError(
                f"Missing required field(s) for {context}: {', '.join(missing)}",
                file_path=file_path,
                line=self.line,
            )


@dataclass
class SelectorMatch:
    source: Optional[str] = None
    rule_id: Optional[str] = None
    group: Optional[str] = None
    custom: Dict[str, str] = field(default_factory=dict)

    def matches(self, ctx: "MappingContext") -> bool:
        if self.source and self.source != ctx.source:
            return False
        if self.rule_id and self.rule_id != ctx.rule_id:
            return False
        if self.group and self.group not in ctx.groups:
            return False
        for key, value in self.custom.items():
            if ctx.custom.get(key) != value:
                return False
        return True

    def rank(self) -> int:
        if self.rule_id:
            return 3
        if self.group:
            return 2
        if self.custom:
            return 1
        return 0


@dataclass
class MappingSelector:
    name: str
    match: SelectorMatch
    fields: PartialFieldSet
    file_path: Path
    line: Optional[int]


@dataclass
class SourceMapping:
    name: str
    defaults: Optional[PartialFieldSet]
    selectors: List[MappingSelector]
    file_path: Path
    line: Optional[int]

    def apply(self, ctx: "MappingContext", resolved: ResolvedMapping) -> ResolvedMapping:
        updated = resolved
        if self.defaults:
            updated = self.defaults.apply_to(updated)
        selector = _select_best_selector(self.selectors, ctx)
        if selector:
            updated = selector.fields.apply_to(updated)
        return updated


@dataclass
class MappingLayer:
    name: str
    priority: MappingPriority
    defaults: PartialFieldSet
    selectors: List[MappingSelector]
    sources: Dict[str, SourceMapping]
    file_path: Path
    excluded_entities: List[str] = field(default_factory=list)

    def apply(self, ctx: "MappingContext", resolved: ResolvedMapping) -> ResolvedMapping:
        updated = self.defaults.apply_to(resolved)
        selector = _select_best_selector(self.selectors, ctx)
        if selector:
            updated = selector.fields.apply_to(updated)
        if ctx.source and ctx.source in self.sources:
            updated = self.sources[ctx.source].apply(ctx, updated)
        return updated


@dataclass(frozen=True)
class MappingContext:
    source: Optional[str]
    rule_id: Optional[str]
    groups: tuple[str, ...]
    custom: Dict[str, str]

    @classmethod
    def from_inputs(
        cls,
        source: Optional[str] = None,
        rule_id: Optional[str] = None,
        groups: Optional[Iterable[str]] = None,
        custom: Optional[Dict[str, str]] = None,
    ) -> "MappingContext":
        normalized_rule = str(rule_id) if rule_id is not None else None
        normalized_groups = tuple(str(group) for group in (groups or ()))
        normalized_custom = {str(k): str(v) for k, v in (custom or {}).items()}
        normalized_source = str(source) if source is not None else None
        return cls(
            source=normalized_source,
            rule_id=normalized_rule,
            groups=normalized_groups,
            custom=normalized_custom,
        )


class MappingResolver:
    def __init__(self, layers: Sequence[MappingLayer]):
        indexed = list(enumerate(layers))
        indexed.sort(key=lambda item: (item[1].priority.order, item[0]))
        self._layers = [layer for _, layer in indexed]
        self._validate_baseline()
        self._excluded_entities = self._collect_excluded_entities()

    def _validate_baseline(self) -> None:
        ctx = MappingContext.from_inputs()
        resolved = ResolvedMapping()
        for layer in self._layers:
            resolved = layer.apply(ctx, resolved)
        missing = [field for field in CANONICAL_FIELDS if getattr(resolved, field) is None]
        if missing:
            last_layer = self._layers[-1] if self._layers else None
            file_path = last_layer.file_path if last_layer else Path("<unknown>")
            line = last_layer.defaults.line if last_layer else None
            raise MappingValidationError(
                f"Canonical field(s) missing after applying baseline mappings: {', '.join(missing)}",
                file_path=file_path,
                line=line,
            )

    def lookup(
        self,
        source: Optional[str] = None,
        rule_id: Optional[str] = None,
        groups: Optional[Iterable[str]] = None,
        custom: Optional[Dict[str, str]] = None,
    ) -> ResolvedMapping:
        ctx = MappingContext.from_inputs(
            source=source, rule_id=rule_id, groups=groups, custom=custom
        )
        resolved = ResolvedMapping()
        for layer in self._layers:
            resolved = layer.apply(ctx, resolved)
        return resolved

    def _collect_excluded_entities(self) -> List[str]:
        """Collect all excluded entity patterns from all layers."""
        all_patterns: List[str] = []
        for layer in self._layers:
            all_patterns.extend(layer.excluded_entities)
        # Remove duplicates while preserving order
        seen = set()
        unique_patterns = []
        for pattern in all_patterns:
            if pattern not in seen:
                seen.add(pattern)
                unique_patterns.append(pattern)
        return unique_patterns

    def get_excluded_entities(self) -> List[str]:
        """Get all excluded entity patterns."""
        return list(self._excluded_entities)


def load(paths: Optional[Sequence[os.PathLike[str] | str]] = None) -> MappingResolver:
    resolved_paths = _resolve_paths(paths)
    layers = [_parse_mapping_file(path) for path in resolved_paths]
    if not layers:
        raise MappingLoaderError("No mapping files were provided")
    return MappingResolver(layers)


def _resolve_paths(paths: Optional[Sequence[os.PathLike[str] | str]]) -> List[Path]:
    if paths is not None:
        candidates = [Path(p).expanduser() for p in paths]
    else:
        env_override = os.getenv(ENV_VAR_MAPPING_PATHS)
        if env_override:
            tokens = [token.strip() for token in env_override.split(os.pathsep) if token.strip()]
            candidates = [Path(token).expanduser() for token in tokens]
        else:
            candidates = [DEFAULT_MAPPING_PATH]
    resolved: List[Path] = []
    for candidate in candidates:
        path = candidate if candidate.is_absolute() else (Path.cwd() / candidate)
        if not path.exists():
            raise MappingLoaderError(f"Mapping file not found: {path}")
        resolved.append(path)
    return resolved


def _parse_mapping_file(path: Path) -> MappingLayer:
    try:
        with path.open("r", encoding="utf-8") as handle:
            raw = yaml.load(handle, Loader=LineLoader) or {}
    except yaml.YAMLError as exc:  # pragma: no cover - exercised in validation tests
        line = getattr(getattr(exc, "problem_mark", None), "line", None)
        if line is not None:
            line += 1
        raise MappingValidationError(f"Invalid YAML: {exc}", file_path=path, line=line)

    if not isinstance(raw, dict):
        raise MappingValidationError("Mapping file must define a dictionary", file_path=path)

    metadata = raw.get("metadata") or {}
    if metadata and not isinstance(metadata, dict):
        raise MappingValidationError(
            "metadata section must be a dictionary", file_path=path, line=_get_line(metadata)
        )
    name = metadata.get("name") if isinstance(metadata, dict) else None
    layer_name = str(name) if name else path.stem

    priority_value = raw.get("priority", MappingPriority.GLOBAL.value)
    try:
        priority = MappingPriority(str(priority_value))
    except ValueError as exc:
        raise MappingValidationError(
            f"Invalid priority '{priority_value}'", file_path=path, line=_get_line(priority_value)
        ) from exc

    defaults_node = raw.get("defaults")
    if defaults_node is None:
        raise MappingValidationError("defaults section is required", file_path=path)
    defaults = _parse_field_set(defaults_node, path, "defaults")
    if priority == MappingPriority.GLOBAL:
        defaults.ensure_fields(CANONICAL_FIELDS, "global defaults")

    selectors = _parse_selectors(raw.get("selectors"), path, forced_source=None)
    sources = _parse_sources(raw.get("sources"), path)
    excluded_entities = _parse_excluded_entities(raw.get("excluded_entities"), path)

    return MappingLayer(
        name=layer_name,
        priority=priority,
        defaults=defaults,
        selectors=selectors,
        sources=sources,
        file_path=path,
        excluded_entities=excluded_entities,
    )


def _parse_excluded_entities(value: object, path: Path) -> List[str]:
    """Parse excluded_entities section from YAML."""
    if value is None:
        return []
    if not isinstance(value, list):
        raise MappingValidationError(
            "excluded_entities must be a list",
            file_path=path,
            line=_get_line(value),
        )

    patterns: List[str] = []
    for item in value:
        if not isinstance(item, str):
            raise MappingValidationError(
                f"excluded_entities items must be strings, got {type(item).__name__}",
                file_path=path,
                line=_get_line(value),
            )
        patterns.append(item)
    return patterns


def _parse_sources(value: object, path: Path) -> Dict[str, SourceMapping]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise MappingValidationError(
            "sources section must be a dictionary", file_path=path, line=_get_line(value)
        )

    sources: Dict[str, SourceMapping] = {}
    for source_name, source_body in value.items():
        if not isinstance(source_body, dict):
            raise MappingValidationError(
                f"Source '{source_name}' must be a dictionary",
                file_path=path,
                line=_get_line(source_body),
            )
        defaults_node = source_body.get("defaults")
        defaults = (
            _parse_field_set(defaults_node, path, f"source '{source_name}' defaults")
            if defaults_node is not None
            else None
        )
        selectors = _parse_selectors(source_body.get("selectors"), path, forced_source=source_name)
        sources[source_name] = SourceMapping(
            name=str(source_name),
            defaults=defaults,
            selectors=selectors,
            file_path=path,
            line=_get_line(source_body),
        )
    return sources


def _parse_selectors(
    value: object, path: Path, forced_source: Optional[str]
) -> List[MappingSelector]:
    if value is None:
        return []
    if not isinstance(value, list):
        raise MappingValidationError(
            "selectors section must be a list",
            file_path=path,
            line=_get_line(value),
        )
    selectors: List[MappingSelector] = []
    for entry in value:
        if not isinstance(entry, dict):
            raise MappingValidationError(
                "Each selector entry must be a dictionary",
                file_path=path,
                line=_get_line(entry),
            )
        name = entry.get("name")
        if not name:
            raise MappingValidationError(
                "Selector entries require a 'name' field",
                file_path=path,
                line=_get_line(entry),
            )
        match_node = entry.get("match")
        if match_node is None:
            raise MappingValidationError(
                f"Selector '{name}' is missing a match block",
                file_path=path,
                line=_get_line(entry),
            )
        match = _parse_match(match_node, path, forced_source)
        fields_node = entry.get("fields")
        if fields_node is None:
            raise MappingValidationError(
                f"Selector '{name}' must define fields",
                file_path=path,
                line=_get_line(entry),
            )
        fields = _parse_field_set(fields_node, path, f"selector '{name}'")
        selectors.append(
            MappingSelector(
                name=str(name),
                match=match,
                fields=fields,
                file_path=path,
                line=_get_line(entry),
            )
        )
    return selectors


def _parse_match(value: object, path: Path, forced_source: Optional[str]) -> SelectorMatch:
    if not isinstance(value, dict):
        raise MappingValidationError(
            "match block must be a dictionary", file_path=path, line=_get_line(value)
        )
    source = value.get("source")
    if forced_source:
        source = forced_source
    rule_id = value.get("rule_id")
    group = value.get("group")
    custom_raw = value.get("custom")
    custom: Dict[str, str] = {}
    if custom_raw is not None:
        if not isinstance(custom_raw, dict):
            raise MappingValidationError(
                "match.custom must be a dictionary",
                file_path=path,
                line=_get_line(custom_raw),
            )
        custom = {str(k): str(v) for k, v in custom_raw.items()}
    if not any([source and not forced_source, rule_id, group, custom]):
        raise MappingValidationError(
            "match block must specify at least one selector field",
            file_path=path,
            line=_get_line(value),
        )
    return SelectorMatch(
        source=str(source) if source else forced_source,
        rule_id=str(rule_id) if rule_id is not None else None,
        group=str(group) if group is not None else None,
        custom=custom,
    )


def _parse_field_set(value: object, path: Path, context: str) -> PartialFieldSet:
    if value is None:
        raise MappingValidationError(
            f"{context} section cannot be null",
            file_path=path,
            line=_get_line(value),
        )
    if not isinstance(value, dict):
        raise MappingValidationError(
            f"{context} must be a dictionary",
            file_path=path,
            line=_get_line(value),
        )

    provided_fields: set[str] = set()
    field_kwargs = {field: None for field in CANONICAL_FIELDS}

    for canonical_field in CANONICAL_FIELDS:
        if canonical_field in value:
            provided_fields.add(canonical_field)
            raw_value = value[canonical_field]
            if raw_value is not None and not isinstance(raw_value, (str, int, float)):
                raise MappingValidationError(
                    f"{context}.{canonical_field} must be a scalar",
                    file_path=path,
                    line=_get_line(value),
                )
            field_kwargs[canonical_field] = (
                str(raw_value) if isinstance(raw_value, (int, float)) else raw_value
            )

    enrichment_value = value.get("enrichment")
    enrichment: Optional[Dict[str, Optional[str]]] = None
    if "enrichment" in value:
        provided_fields.add("enrichment")
        if enrichment_value is None:
            enrichment = None
        elif not isinstance(enrichment_value, dict):
            raise MappingValidationError(
                f"{context}.enrichment must be a dictionary",
                file_path=path,
                line=_get_line(enrichment_value),
            )
        else:
            enrichment = {}
            for key, raw in enrichment_value.items():
                if raw is not None and not isinstance(raw, (str, int, float)):
                    raise MappingValidationError(
                        f"{context}.enrichment values must be scalar",
                        file_path=path,
                        line=_get_line(enrichment_value),
                    )
                enrichment[str(key)] = (
                    str(raw)
                    if isinstance(raw, (int, float))
                    else (raw if raw is not None else None)
                )

    allowed_keys = set(CANONICAL_FIELDS) | {"enrichment"}
    unknown = [key for key in value.keys() if key not in allowed_keys]
    if unknown:
        raise MappingValidationError(
            f"{context} contains unknown field(s): {', '.join(str(k) for k in unknown)}",
            file_path=path,
            line=_get_line(value),
        )

    return PartialFieldSet(
        entity_id=field_kwargs["entity_id"],
        entity_type=field_kwargs["entity_type"],
        severity=field_kwargs["severity"],
        timestamp=field_kwargs["timestamp"],
        enrichment=enrichment,
        provided_fields=provided_fields,
        file_path=path,
        line=_get_line(value),
    )


def _select_best_selector(
    selectors: Iterable[MappingSelector], ctx: MappingContext
) -> Optional[MappingSelector]:
    best: Optional[MappingSelector] = None
    best_rank = -1
    for selector in selectors:
        if not selector.match.matches(ctx):
            continue
        rank = selector.match.rank()
        if rank > best_rank:
            best = selector
            best_rank = rank
    return best


__all__ = [
    "load",
    "MappingLoaderError",
    "MappingResolver",
    "MappingValidationError",
    "ResolvedMapping",
]
