import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // etcd3 loads .proto files at runtime using __dirname — it must not be bundled.
  serverExternalPackages: ["etcd3", "@grpc/grpc-js", "@grpc/proto-loader"],
};

export default nextConfig;
