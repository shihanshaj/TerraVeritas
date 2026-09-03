# Deliberately invalid HCL (unterminated string) so `terraform validate`
# fails before init would even matter for a real provider.

resource "terraform_data" "broken" {
  input = "unclosed
