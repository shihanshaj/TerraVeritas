# A required variable with no default and no supplied value. Config is
# syntactically and semantically valid on its own (validate passes) — only
# planning fails, because a required input is unresolved.

variable "required_input" {
  type = string
}

resource "terraform_data" "example" {
  input = var.required_input
}
