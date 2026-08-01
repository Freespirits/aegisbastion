# bin/ — vendored tooling (never installed system-wide)

Binaries here are gitignored (`bin/*.exe`). To restore:

```bash
# buf (contract toolchain)
curl -L -o bin/buf.exe \
  https://github.com/bufbuild/buf/releases/download/v1.72.0/buf-Windows-x86_64.exe

# codegen plugins (or: make tools)
GOBIN="$PWD/bin" go install google.golang.org/protobuf/cmd/protoc-gen-go@v1.36.6
GOBIN="$PWD/bin" go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@v1.5.1
```

Currently vendored: `buf.exe` v1.72.0, `protoc-gen-go.exe` v1.36.6,
`protoc-gen-go-grpc.exe` v1.5.1.
