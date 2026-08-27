// swift-tools-version: 6.1
import PackageDescription

let package = Package(
  name: "Hecatia",
  platforms: [.macOS(.v14)],
  products: [
    .executable(name: "Hecatia", targets: ["Hecatia"]),
  ],
  dependencies: [
    .package(url: "https://github.com/grpc/grpc-swift.git", exact: "1.27.5"),
    .package(url: "https://github.com/apple/swift-protobuf.git", exact: "1.38.1"),
  ],
  targets: [
    .executableTarget(
      name: "Hecatia",
      dependencies: [
        .product(name: "GRPC", package: "grpc-swift"),
        .product(name: "SwiftProtobuf", package: "swift-protobuf"),
      ],
      // The two *-config.json files beside the sources are the protoc plugins'
      // configuration. SwiftPM warns that it does not know what they are, and
      // they cannot be excluded to silence it — the plugins refuse to run when
      // their config is not a declared file of the target.
      plugins: [
        .plugin(name: "SwiftProtobufPlugin", package: "swift-protobuf"),
        .plugin(name: "GRPCSwiftPlugin", package: "grpc-swift"),
      ]
    ),
    .testTarget(
      name: "HecatiaTests",
      dependencies: ["Hecatia"]
    ),
  ]
)
