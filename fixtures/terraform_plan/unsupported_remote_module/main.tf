# A module sourced from the public registry. Deliberately never fetched —
# the planner detects and rejects this before touching the network, rather
# than discovering it via a slow/failed init.

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.0.0"
}
