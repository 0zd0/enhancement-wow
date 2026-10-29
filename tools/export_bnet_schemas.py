"""Extract a FileDescriptorSet from TrinityCore's generated C++ (no C++ build)."""

import argparse
import ast
import re
from pathlib import Path

from google.protobuf import descriptor_pb2


STRING = r'"(?:[^"\\]|\\.)*"'
DESCRIPTOR = re.compile(
    rf"InternalAddGeneratedFile\(\s*((?:{STRING}\s*)+),\s*(\d+)\)"
)


def extract(path: Path) -> descriptor_pb2.FileDescriptorProto:
    match = DESCRIPTOR.search(path.read_text(encoding="utf-8"))
    if match is None:
        raise ValueError(f"Descriptor not found in {path}; check the C++ generator format")
    parts = []
    for literal in re.findall(STRING, match[1]):
        # C++ escapes '?' as '\?' to prevent trigraphs; Python does not.
        literal = re.sub(r"\\.", lambda m: "?" if m[0] == r"\?" else m[0], literal)
        parts.append(ast.literal_eval("b" + literal))
    data = b"".join(parts)
    if len(data) != int(match[2]):
        raise ValueError(f"Descriptor length mismatch in {path}")
    return descriptor_pb2.FileDescriptorProto.FromString(data)


def export(source: Path, roots: tuple[str, ...]) -> descriptor_pb2.FileDescriptorSet:
    result = descriptor_pb2.FileDescriptorSet()
    visited: set[str] = set()

    def visit(name: str) -> None:
        if name in visited:
            return
        visited.add(name)
        if name == "google/protobuf/descriptor.proto":
            schema = descriptor_pb2.FileDescriptorProto.FromString(
                descriptor_pb2.DESCRIPTOR.serialized_pb
            )
        else:
            relative = Path(name)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError(f"Invalid dependency path: {name}")
            schema = extract(source / relative.with_suffix(".pb.cc"))
            if schema.name != name:
                raise ValueError(f"Expected {name}, got {schema.name}")
        for dependency in schema.dependency:
            visit(dependency)
        result.file.add().CopyFrom(schema)

    for root in roots:
        visit(root)
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("source", type=Path, help="TrinityCore/src/server/proto/Client")
    parser.add_argument("--output", type=Path, default=Path("src/proxy/bnet/bnet.protoset"))
    args = parser.parse_args()
    roots = tuple(
        path.relative_to(args.source).as_posix().removesuffix(".pb.cc") + ".proto"
        for path in sorted(args.source.rglob("*.pb.cc"))
    )
    if not roots:
        parser.error(f"No .pb.cc schemas found in {args.source}")

    result = export(args.source, roots)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_bytes(result.SerializeToString())
    print(f"{args.output}: {len(result.file)} schemas")
    for schema in result.file:
        print(f"  {schema.name}")


if __name__ == "__main__":
    main()
