import ctypes
from ctypes import *
from ctypes import wintypes

'''
Source: https://github.com/trustedsec/CS_COFFLoader
'''

class COFF_FILE_HEADER(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("Machine", ctypes.c_uint16),
        ("NumberOfSections", ctypes.c_uint16),
        ("TimeDateStamp", ctypes.c_uint32),
        ("PointerToSymbolTable", ctypes.c_uint32),
        ("NumberOfSymbols", ctypes.c_uint32),
        ("SizeOfOptionalHeader", ctypes.c_uint16),
        ("Characteristics", ctypes.c_uint16)
    ]

class COFF_SECT(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("Name", ctypes.c_uint8 * 8),
        ("VirtualSize", ctypes.c_uint32),
        ("VirtualAddress", ctypes.c_uint32),
        ("SizeOfRawData", ctypes.c_uint32),
        ("PointerToRawData", ctypes.c_uint32),
        ("PointerToRelocations", ctypes.c_uint32),
        ("PointerToLineNumbers", ctypes.c_uint32),
        ("NumberOfRelocations", ctypes.c_uint16),
        ("NumberOfLineNumbers", ctypes.c_uint16),
        ("Characteristics", ctypes.c_uint32)
    ]

class COFF_RELOC(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("VirtualAddress", ctypes.c_uint32),
        ("SymbolTableIndex", ctypes.c_uint32),
        ("Type", ctypes.c_uint16)
    ]

# class COFF_SYM(ctypes.Structure):
#     _fields_ = [
#         ("Name", ctypes.c_char * 8),
#         ("Value", ctypes.c_uint32),
#         ("SectionNumber", ctypes.c_int16),
#         ("Type", ctypes.c_uint16),
#         ("StorageClass", ctypes.c_uint8),
#         ("NumberOfAuxSymbols", ctypes.c_uint8),
#     ]

class COFF_SYM(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("Name", ctypes.c_uint8 * 8),
        ("Value", ctypes.c_uint32),
        ("SectionNumber", ctypes.c_int16),      # signed!
        ("Type", ctypes.c_uint16),
        ("StorageClass", ctypes.c_uint8),
        ("NumberOfAuxSymbols", ctypes.c_uint8)
    ]

class BEACON_FUNCTION(Structure):
    _fields_ = [
        ("hash", c_uint32),
        ("function", c_void_p),
    ]

class MEMORY_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BaseAddress",       ctypes.c_void_p),
        ("AllocationBase",    ctypes.c_void_p),
        ("AllocationProtect", ctypes.c_ulong),
        ("RegionSize",        ctypes.c_size_t),
        ("State",             ctypes.c_ulong),
        ("Protect",           ctypes.c_ulong),
        ("Type",              ctypes.c_ulong),
    ]

class StructHelper:
    def ConvertToString(arr):
        """
        Convert byte array to string
        arr: c_ubyte_Array or pointer to bytes
        """
        if isinstance(arr, ctypes.Array):
            # Convert ctypes array to bytes, then to string
            byte_string = bytes(arr)
            # Find null terminator and decode
            null_pos = byte_string.find(b'\x00')
            if null_pos != -1:
                byte_string = byte_string[:null_pos]
            return byte_string.decode('ascii', errors='ignore')
        else:
            # Handle pointer case
            return ctypes.string_at(arr)

class Win32:
    # alloc
    NULL = 0x0
    Commit = 0x1000
    Reserve = 0x2000
    Decommit = 0x4000
    Release = 0x8000
    Reset = 0x80000
    Physical = 0x400000
    TopDown = 0x100000
    WriteWatch = 0x200000
    LargePages = 0x20000000

    # mem prot
    PAGE_EXECUTE = 0x10
    PAGE_EXECUTE_READ = 0x20
    PAGE_EXECUTE_READWRITE = 0x40
    PAGE_EXECUTE_WRITECOPY = 0x80
    PAGE_NOACCESS = 0x00000001
    PAGE_READONLY = 0x00000002
    PAGE_READWRITE = 0x00000004
    PAGE_WRITECOPY = 0x00000008
    PAGE_GUARD = 0x00000100
    PAGE_NOCACHE = 0x00000200
    PAGE_WRITECOMBINE = 0x00000400

    # Constants
    IMAGE_REL_AMD64_ADDR64 = 0x0001
    IMAGE_REL_AMD64_ADDR32NB = 0x0003
    IMAGE_REL_AMD64_REL32 = 0x0004
    IMAGE_REL_AMD64_REL32_5 = 0x0009

    # Load DLLs
    kernel32 = ctypes.WinDLL("kernel32.dll")
    msvcrt = cdll.msvcrt

    # Setup function prototypes
    GetLastError = kernel32.GetLastError
    GetLastError.restype = wintypes.DWORD
    
    VirtualAlloc =  kernel32.VirtualAlloc
    VirtualAlloc.argtypes = [wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD, wintypes.DWORD]
    VirtualAlloc.restype = wintypes.LPVOID
    
    VirtualFreeEx = kernel32.VirtualFreeEx
    VirtualFreeEx.argtypes = [wintypes.HANDLE, wintypes.LPVOID, ctypes.c_size_t, wintypes.DWORD]
    VirtualFreeEx.restype = wintypes.BOOL
    
    GetModuleHandleW = kernel32.GetModuleHandleW
    GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    GetModuleHandleW.restype = wintypes.HMODULE
    
    GetProcAddress = kernel32.GetProcAddress
    GetProcAddress.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    GetProcAddress.restype  = ctypes.c_void_p

    
    LoadLibraryW = kernel32.LoadLibraryW
    LoadLibraryW.argtypes = [wintypes.LPCWSTR]
    LoadLibraryW.restype = wintypes.HMODULE

    memcpy = msvcrt.memcpy
    memcpy.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    memcpy.restype = ctypes.c_void_p


    VirtualFree   = kernel32.VirtualFree
    RtlMoveMemory = kernel32.RtlMoveMemory
    RtlMoveMemory.argtypes = [ctypes.c_void_p, ctypes.c_void_p, ctypes.c_size_t]
    RtlMoveMemory.restype  = None

    VirtualProtect = kernel32.VirtualProtect
    VirtualProtect.argtypes = [ctypes.c_void_p,ctypes.c_size_t,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    VirtualProtect.restype = wintypes.BOOL

    VirtualQuery = kernel32.VirtualQuery
    VirtualQuery.argtypes = [
        ctypes.c_void_p,
        ctypes.POINTER(MEMORY_BASIC_INFORMATION),
        ctypes.c_size_t
    ]
    VirtualQuery.restype = ctypes.c_size_t
