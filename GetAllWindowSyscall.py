#https://github.com/Dump-GUY/Malware-analysis-and-Reverse-engineering/blob/main/APT29_C2-Client_Dropbox_Loader/Resolve_syscall_numbers_via_VA_ntdll.py

import lief

Syscalls = {}
ntdll = lief.parse(r"C:\Windows\System32\ntdll.dll")
for export in ntdll.exported_functions:
    if export.name.startswith("Zw"):
        Syscalls[export.name] = (export.address + ntdll.optional_header.imagebase)

#Sorting syscalls ascending via VA
sorted_syscalls = sorted(Syscalls.items(), key=lambda x: x[1], reverse=False)
#printing sorted syscalls with syscall numbers
for i, syscall in enumerate(sorted_syscalls):
	print("[Syscall Name]:",syscall[0],"  [Syscall VA]:",hex(syscall[1]),"  [Syscall Number]:",hex(i))
