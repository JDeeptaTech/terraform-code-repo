output "file_data" {
  value = <<-EOF
    Deploying VM for user ${var.requestor} in
      vSphere Datacenter: ${local.dc_informaiton.name}
      datastore: ${local.dc_informaiton.datastore}
  EOF
}
