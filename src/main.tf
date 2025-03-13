output "file_data" {
  value = <<-EOT
    Deploying VM for user ${var.requestor} in
      Datacenter: ${local.dc_informaiton.name}
      Datastore: ${local.dc_informaiton.datastore}
      Cluster: ${local.dc_informaiton.cluster}
      Network: ${local.dc_informaiton.network}
  EOT
}
