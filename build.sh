# 仍然在项目根目录运行
PROTOS_DIR="src/runtime/containerd-shim-peernode/protos"

# 注意 --go_out 参数变得更长了
protoc \
  --proto_path="${PROTOS_DIR}" \
  --experimental_allow_proto3_optional \
  --go_out="paths=source_relative,Mgoogle/protobuf/empty.proto=google.golang.org/protobuf/types/known/emptypb,Mgoogle/protobuf/wrappers.proto=google.golang.org/protobuf/types/known/wrapperspb,Mgoogle/protobuf/descriptor.proto=google.golang.org/protobuf/types/descriptorpb:${PROTOS_DIR}" \
  $(find "${PROTOS_DIR}" -name "*.proto")