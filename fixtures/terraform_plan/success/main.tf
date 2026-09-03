# Uses Terraform's builtin terraform_data resource (terraform.io/builtin,
# ships with the CLI, zero network/provider download needed) so this
# fixture exercises the full init -> validate -> plan -> show pipeline
# genuinely, without depending on registry/network availability.

resource "terraform_data" "example" {
  input = "hello"
}
