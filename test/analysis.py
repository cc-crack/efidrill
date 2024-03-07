print("### Script running!")
import ida_loader
import idaapi
import idc

idaapi.auto_wait()

print("### auto analysis complete!")
ida_loader.load_and_run_plugin("Efidrill", 0)
print("### Efidrill complete!")
idc.qexit(0)
