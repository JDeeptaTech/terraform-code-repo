variable "requestor" {
  description = "Name of the Requestor"
  type        = string
  validation {
    condition     = length(var.requestor) > 0
    error_message = "Requestor name cannot be empty"
  }
}

variable "vm_count" {
  description = "Number of VMs to deploy"
  type        = number
  default     = 1
  validation {
    condition     = var.vm_count > 0
    error_message = "VM count must be greater than 0"
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
