# Syntactically valid HCL (a real HCL parser accepts it fine) but
# semantically invalid: terraform_data has no argument named
# nonexistent_argument. Distinguishes the "validate catches a schema
# violation" path from the "hcl2 catches broken syntax before init" path —
# both produce PLAN_INVALID_CONFIGURATION, but via different stages.

resource "terraform_data" "x" {
  nonexistent_argument = "y"
}
