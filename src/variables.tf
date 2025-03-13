variable "requestor" {
    description = "Name of the Requestor"
    type        = string
    validation {
        condition     = length(var.requestor) > 0
        error_message = "Requestor name cannot be empty"
    }
}