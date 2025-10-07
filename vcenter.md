```python

from pyVim.connect import SmartConnect, Disconnect
from pyVmomi import vim
import ssl
import atexit


def get_vm_by_name(content, vm_name):
    obj_view = content.viewManager.CreateContainerView(content.rootFolder, [vim.VirtualMachine], True)
    for vm in obj_view.view:
        if vm.name == vm_name:
            obj_view.Destroy()
            return vm
    obj_view.Destroy()
    return None


def delete_snapshots(vm):
    if vm.snapshot:
        print(f"Deleting snapshots for VM: {vm.name}")
        task = vm.RemoveAllSnapshots_Task()
        wait_for_task(task)
        print("Snapshots deleted.")


def remove_nics(vm):
    print(f"Removing NICs for VM: {vm.name}")
    nic_specs = []
    for device in vm.config.hardware.device:
        if isinstance(device, vim.vm.device.VirtualEthernetCard):
            nic_spec = vim.vm.device.VirtualDeviceSpec()
            nic_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
            nic_spec.device = device
            nic_specs.append(nic_spec)

    if nic_specs:
        spec = vim.vm.ConfigSpec()
        spec.deviceChange = nic_specs
        task = vm.ReconfigVM_Task(spec=spec)
        wait_for_task(task)
        print("NICs removed.")


def remove_cdroms(vm):
    print(f"Removing CD/DVD devices for VM: {vm.name}")
    cd_specs = []
    for device in vm.config.hardware.device:
        if isinstance(device, vim.vm.device.VirtualCdrom):
            cd_spec = vim.vm.device.VirtualDeviceSpec()
            cd_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
            cd_spec.device = device
            cd_specs.append(cd_spec)

    if cd_specs:
        spec = vim.vm.ConfigSpec()
        spec.deviceChange = cd_specs
        task = vm.ReconfigVM_Task(spec=spec)
        wait_for_task(task)
        print("CD/DVD devices removed.")


def remove_disks(vm):
    print(f"Removing disks for VM: {vm.name}")
    disk_specs = []
    for device in vm.config.hardware.device:
        if isinstance(device, vim.vm.device.VirtualDisk):
            disk_spec = vim.vm.device.VirtualDeviceSpec()
            disk_spec.operation = vim.vm.device.VirtualDeviceSpec.Operation.remove
            disk_spec.device = device
            disk_spec.fileOperation = vim.vm.device.VirtualDeviceSpec.FileOperation.destroy
            disk_specs.append(disk_spec)

    if disk_specs:
        spec = vim.vm.ConfigSpec()
        spec.deviceChange = disk_specs
        task = vm.ReconfigVM_Task(spec=spec)
        wait_for_task(task)
        print("Disks removed.")


def wait_for_task(task):
    from time import sleep
    while task.info.state not in [vim.TaskInfo.State.success, vim.TaskInfo.State.error]:
        sleep(1)
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

    delete_snapshots(vm)
    remove_nics(vm)
    remove_cdroms(vm)
    remove_disks(vm)
    print(f"All removable items deleted for VM: {vm.name}")


if __name__ == "__main__":
    # Replace these with your vCenter details and target VM name
    vcenter_host = "vcenter.yourdomain.com"
    vcenter_user = "administrator@vsphere.local"
    vcenter_password = "your_password"
    vm_name = "MyTestVM"

    main(vm_name, vcenter_host, vcenter_user, vcenter_password)

```
