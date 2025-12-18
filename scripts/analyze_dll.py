"""Analyze Neewer Control Center DLLs to find exported functions."""

import pefile
from pathlib import Path

NEEWER_DIR = Path(r"C:\Neewer Control Center\Neewer")

DLLS_TO_ANALYZE = [
    "Set_Dongle_RF_API_x64.dll",
    "Set_Dongle_RF_API.dll", 
    "BLE_USB_LIB_API_x64.dll",
    "hidapi.dll",
]


def analyze_dll(dll_path: Path) -> None:
    """Print exported functions from a DLL."""
    print(f"\n{'='*60}")
    print(f"DLL: {dll_path.name}")
    print('='*60)
    
    if not dll_path.exists():
        print(f"  File not found: {dll_path}")
        return
    
    try:
        pe = pefile.PE(str(dll_path))
        
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
            print(f"  Exports ({len(pe.DIRECTORY_ENTRY_EXPORT.symbols)} functions):")
            for exp in pe.DIRECTORY_ENTRY_EXPORT.symbols:
                name = exp.name.decode() if exp.name else f"Ordinal_{exp.ordinal}"
                print(f"    {exp.ordinal:4d}: {name}")
        else:
            print("  No exports found")
            
        pe.close()
    except Exception as e:
        print(f"  Error analyzing: {e}")


def main() -> None:
    print("Neewer Control Center DLL Analysis")
    print("="*60)
    
    for dll_name in DLLS_TO_ANALYZE:
        dll_path = NEEWER_DIR / dll_name
        analyze_dll(dll_path)


if __name__ == "__main__":
    main()

