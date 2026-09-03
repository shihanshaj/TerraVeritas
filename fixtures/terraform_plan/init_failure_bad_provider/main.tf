# References a provider source that does not exist on the public registry.
# Deterministic, fast (~1s) init failure regardless of network bandwidth —
# unlike a real provider download timing out, this fails the same way in
# any environment with basic registry connectivity.

terraform {
  required_providers {
    nonexistent = {
      source  = "terraveritas-test/this-provider-does-not-exist-xyz"
      version = "1.0.0"
    }
  }
}
