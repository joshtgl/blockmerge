variable "PLATFORM" {
  default = "linux/amd64"
}

group "default" {
  targets = ["cli-debian", "web-debian", "cli-alpine", "web-alpine"]
}

group "debian" {
  targets = ["cli-debian", "web-debian"]
}

group "alpine" {
  targets = ["cli-alpine", "web-alpine"]
}

target "common" {
  context   = "."
  platforms = [PLATFORM]
}

target "cli-debian" {
  inherits   = ["common"]
  dockerfile = "Dockerfile.debian"
  target     = "cli"
  tags       = ["blockmerge:debian"]
}

target "web-debian" {
  inherits   = ["common"]
  dockerfile = "Dockerfile.debian"
  target     = "web"
  tags       = ["blockmerge-web:debian"]
}

target "cli-alpine" {
  inherits   = ["common"]
  dockerfile = "Dockerfile.alpine"
  target     = "cli"
  tags       = ["blockmerge:alpine"]
}

target "web-alpine" {
  inherits   = ["common"]
  dockerfile = "Dockerfile.alpine"
  target     = "web"
  tags       = ["blockmerge-web:alpine"]
}
