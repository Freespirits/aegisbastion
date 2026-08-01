module github.com/aegisbastion/aegisbastion/adapters

go 1.25.0

replace github.com/aegisbastion/aegisbastion/gen/go => ../gen/go

require (
	github.com/aegisbastion/aegisbastion/gen/go v0.0.0-00010101000000-000000000000
	google.golang.org/grpc v1.71.0
	google.golang.org/protobuf v1.36.6
)

require (
	golang.org/x/net v0.55.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
	golang.org/x/text v0.37.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250115164207-1a7da9e5054f // indirect
)
