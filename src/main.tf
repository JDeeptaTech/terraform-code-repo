output "file_data" {
  value = <<-EOT
    Deploying VM for user ${var.requestor} in
      vSphere Datacenter: ${local.dc_informaiton.name}
      datastore: ${local.dc_informaiton.datastore}
  EOT
}
