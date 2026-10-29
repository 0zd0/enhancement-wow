from dataclasses import dataclass
from pathlib import Path

from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf.descriptor import MethodDescriptor
from google.protobuf.json_format import MessageToDict
from google.protobuf.message import Message


def fnv1a(value: str) -> int:
    result = 0x811C9DC5
    for byte in value.encode("utf-8"):
        result = ((result ^ byte) * 0x01000193) & 0xFFFFFFFF
    return result


@dataclass(frozen=True)
class Method:
    name: str
    request: type[Message]
    response: type[Message]

    @classmethod
    def from_descriptor(cls, descriptor: MethodDescriptor) -> "Method":
        return cls(
            descriptor.full_name,
            message_factory.GetMessageClass(descriptor.input_type),
            message_factory.GetMessageClass(descriptor.output_type),
        )


class Schemas:
    def __init__(self, path: Path):
        schemas = descriptor_pb2.FileDescriptorSet.FromString(path.read_bytes())
        self.pool = descriptor_pool.DescriptorPool()
        pending = {schema.name: schema for schema in schemas.file}
        loaded: set[str] = set()
        while pending:
            ready = [schema for schema in pending.values() if set(schema.dependency) <= loaded]
            if not ready:
                raise ValueError(f"Missing or cyclic schema dependencies: {list(pending)}")
            for schema in ready:
                self.pool.AddSerializedFile(schema.SerializeToString())
                loaded.add(schema.name)
                del pending[schema.name]
        self.header_type = self.message_type("bgs.protocol.Header")
        self.methods: dict[tuple[int, int], Method] = {}
        for schema in schemas.file:
            descriptor = self.pool.FindFileByName(schema.name)
            for service in descriptor.services_by_name.values():
                options = self._options("ServiceOptions", service.GetOptions(), "service_options")
                names = {service.full_name}
                if options.descriptor_name:
                    names.add(options.descriptor_name)
                for method in service.methods:
                    method_options = self._options("MethodOptions", method.GetOptions(), "method_options")
                    if not method_options.HasField("id"):
                        continue
                    decoded_method = Method.from_descriptor(method)
                    for name in names:
                        key = (fnv1a(name), method_options.id & 0x3FFFFFFF)
                        if key in self.methods and self.methods[key] != decoded_method:
                            raise ValueError(f"Ambiguous RPC method {key}")
                        self.methods[key] = decoded_method

    def message_type(self, name: str) -> type[Message]:
        return message_factory.GetMessageClass(self.pool.FindMessageTypeByName(name))

    def _options(self, name: str, options: Message, extension_name: str) -> Message:
        # Reparse with this pool so custom options become visible to Python.
        parsed = self.message_type(f"google.protobuf.{name}")()
        parsed.ParseFromString(options.SerializeToString())
        extension = self.pool.FindExtensionByName(f"bgs.protocol.{extension_name}")
        return parsed.Extensions[extension]

    def to_dict(self, message: Message) -> dict:
        return MessageToDict(message, preserving_proto_field_name=True, descriptor_pool=self.pool)
