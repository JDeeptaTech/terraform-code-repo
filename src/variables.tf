variable "requestor" {
  description = "Name of the Requestor"
  type        = string
  validation {
    condition     = length(var.requestor) > 0
    error_message = "Requestor name cannot be empty"
  }
}

variable "vsphere_datacenter" {
  description = "Name of the vSphere Datacenter"
  type        = string
  default     = "dc-01"
  validation {
    condition     = length(var.vsphere_datacenter) > 0
    error_message = "vSphere Datacenter name cannot be empty"
  }

}
