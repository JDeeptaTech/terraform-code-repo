```python
from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
import ssl
import atexit
import time


def get_vm_by_name(content, vm_name):
    obj_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    for vm in obj_view.view:
        if vm.name == vm_name:
            obj_view.Destroy()
            return vm
    obj_view.Destroy()
    return None


def power_off_vm(vm):
    if vm.runtime.powerState == vim.VirtualMachinePowerState.poweredOn:
        print(f"Powering off VM: {vm.name}")
        task = vm.PowerOffVM_Task()
        wait_for_task(task)
        print("VM powered off.")


def delete_snapshots(vm):
    if vm.snapshot:
        print(f"Deleting snapshots for VM: {vm.name}")
        task = vm.RemoveAllSnapshots_Task()
        wait_for_task(task)
        print("Snapshots deleted.")


def remove_devices(vm, device_type, label):
    print(f"Removing {label} devices for VM: {vm.name}")
    device_specs = []
    for device in vm.config.hardware.device:
        if isinstance(device, device_type):
            dev_spec = vim.vm.device.VirtualDeviceSpec()
            dev_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
            dev_spec.device = device
            if isinstance(device, vim.vm.device.VirtualDisk):
                dev_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.destroy
            device_specs.append(dev_spec)

    if device_specs:
        spec = vim.vm.ConfigSpec()
        spec.deviceChange = device_specs
        task = vm.ReconfigVM_Task(spec=spec)
        wait_for_task(task)
        print(f"{label} devices removed.")


def delete_vm(vm):
    print(f"Destroying VM: {vm.name}")
    task = vm.Destroy_Task()
    wait_for_task(task)
    print(f"VM '{vm.name}' has been deleted.")


def wait_for_task(task):
    while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
        time.sleep(1)
    if task.info.state == vim.TaskInfo.State.error:
        raise task.info.error


def main(vm_name, vcenter_host, vcenter_user, vcenter_password):
    context = ssl._create_unverified_context()
    si = SmartConnect(host=vcenter_host, user=vcenter_user, pwd=vcenter_password, sslContext=context)
    atexit.register(Disconnect, si)

    content = si.RetrieveContent()
    vm = get_vm_by_name(content, vm_name)
    if not vm:
        print(f"VM '{vm_name}' not found.")
        return

    power_off_vm(vm)
    delete_snapshots(vm)
    remove_devices(vm, vim.vm.device.VirtualEthernetCard, "NIC")
    remove_devices(vm, vim.vm.device.VirtualCdrom, "CD/DVD")
    remove_devices(vm, vim.vm.device.VirtualDisk, "Disk")
    delete_vm(vm)


if __name__ == "__main__":
    # Replace these with your actual credentials and VM name
    vcenter_host = "vcenter.yourdomain.com"
    vcenter_user = "administrator@vsphere.local"
    vcenter_password = "your_password"
    vm_name = "MyTestVM"

    main(vm_name, vcenter_host, vcenter_user, vcenter_password)


```
