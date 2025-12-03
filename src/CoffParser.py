import ctypes
from ctypes import *
from ctypes.wintypes import *
from src.CoffStruct import *
TmpFuncDelegate = CFUNCTYPE(c_int, c_char_p, c_int)
FuncDelegate_GetOutput = CFUNCTYPE(c_char_p, POINTER(c_int))

'''
Source: https://github.com/trustedsec/CS_COFFLoader
'''

PAGE_FLAGS = {
    0x01: "PAGE_NOACCESS",
    0x02: "PAGE_READONLY",
    0x04: "PAGE_READWRITE",
    0x08: "PAGE_WRITECOPY",
    0x10: "PAGE_EXECUTE",
    0x20: "PAGE_EXECUTE_READ",
    0x40: "PAGE_EXECUTE_READWRITE",
    0x80: "PAGE_EXECUTE_WRITECOPY",
}

class CoffParser:

    def __init__(self):
        self.beaconFunctionMapping = []
        self.coffFunctionMapping = []
        self.beaconSectionMapping = []
        self.coffSectionMapping = []
        self.BeaconInternalMapping = []
    
    def hash_djb(self, data):
        if isinstance(data, str):
            data = data.encode('utf-8')

        h = 5381

        for c in data:
            h = ((h << 5) + h) + c   # h * 33 + c
            h &= 0xFFFFFFFF          # force 32-bit wrap

        return h

    
    def memset(self, dst: ctypes.c_void_p, src: c_ubyte, size: int):
        
        d = cast(dst, POINTER(c_ubyte))
        value = int(src)
        for i in range(size):
            d[i] = value

    def memcpy(self, dst, src, size: int):
        d = cast(dst, POINTER(c_ubyte))
        for i in range(size):
            d[i] = src[i]

    def memcmp(self, dst, src):
        size = len(src)
        d = bytearray(size)

        for i in range(size):
            d[i] = dst[i]

            if dst[i] == '\x00': # null byte
                break

        dd = d.decode()

        if dd == src:
            return 0
        
        return 1
    
    def get_memory_protection(self, addr):
        mbi = MEMORY_BASIC_INFORMATION()
        result = Win32.VirtualQuery(
            ctypes.c_void_p(addr),
            ctypes.byref(mbi),
            ctypes.sizeof(mbi)
        )

        if result == 0:
            err = ctypes.get_last_error()
            raise OSError(f"VirtualQuery failed: {err}")

        return mbi

    
    def process_symbol(self, symbol):
        PREPENDSYMBOLVALUELEN = 6
        functionaddress = c_void_p()
        localfunction = ''
        subs = []
        locallibrary = ''
        localfunction2 = ''

        if '__ms_' in symbol:
            PREPENDSYMBOLVALUELEN = 5
        if len(symbol) < PREPENDSYMBOLVALUELEN:
            return None
        
        if symbol.startswith('MSVCRT'):
            localfunction = symbol
        else:
            localfunction = symbol[PREPENDSYMBOLVALUELEN:]
        
        if symbol.startswith('__imp_'):
            beacon_func_name = symbol[6:]
            # print(f"[DEBUG] Detected Beacon function import: {beacon_func_name}")
            
            # Cari di BeaconInternalMapping
            for tmp in self.BeaconInternalMapping:
                # Hitung hash dari nama fungsi (tanpa __imp_)
                dhash = self.hash_djb(beacon_func_name.encode())
                
                if dhash == tmp.hash:
                    print(f'[+] Found Beacon function: {beacon_func_name}')
                    return tmp.function
        
        # Coba cari tanpa prefix
        for tmp in self.BeaconInternalMapping:
            dhash = self.hash_djb(localfunction.encode())
            if dhash == tmp.hash:
                print(f'[+] Found local Beacon function: {localfunction}')
                return tmp.function
        
        functionlist = ["Beacon", "toWideChar", "LoadLibraryA", "GetProcAddress", "FreeLibrary", "GetModuleHandleA"]
        
        if localfunction.startswith("Beacon"):
            # print(f"[DEBUG] Looking for Beacon function: {localfunction}")
            beacon_hash = self.hash_djb(localfunction.encode())
            
            for tmp in self.BeaconInternalMapping:
                if tmp.hash == beacon_hash:
                    print(f'[+] Found Beacon function in mapping: {localfunction}')
                    return tmp.function
            
            beacon_with_imp = f"__imp_{localfunction}"
            beacon_hash_imp = self.hash_djb(beacon_with_imp.encode())
            
            for tmp in self.BeaconInternalMapping:
                if tmp.hash == beacon_hash_imp:
                    print(f'[+] Found Beacon function (with __imp_): {beacon_with_imp}')
                    return tmp.function
        
        if localfunction in functionlist:
            hModule = Win32.LoadLibraryW("Kernel32.dll")
            funcA = localfunction.encode("ascii") + b"\x00"
            functionaddress = Win32.GetProcAddress(hModule, funcA)
            return ctypes.c_void_p(functionaddress)
        
        if '$' not in symbol:
            # print(f'Error: process_symbol, no library found - {localfunction}')
            return None
        
        subs = localfunction.split('$')
        locallibrary = subs[0] + ".dll"
        localfunction2 = subs[1].split('@')[0]

        hGetModule = Win32.GetModuleHandleW(locallibrary)
        hGetModule = c_void_p(hGetModule)
        hModule = Win32.LoadLibraryW(locallibrary)

        funcA = localfunction2.encode("ascii") + b"\x00"
        functionaddress = Win32.GetProcAddress(hModule, funcA)

        return functionaddress
    
    def parseCOFF(self, functionname, data, filesize, argumentData, argumentSize, coffDebug=False):

        coff_header = POINTER(COFF_FILE_HEADER)
        coff_section = POINTER(COFF_SECT)
        coff_relocation = POINTER(COFF_RELOC)
        coff_symbol = POINTER(COFF_SYM)

        functionMappingCount = 0
        retcode = 0
        counter = 0
        reloccount = 0
        tempcounter = 0
        symptr = 0
        offsetvalue = c_uint32(0)
        isBeaconObject = argumentData is None

        sectionMapping = []
        functionMapping = ctypes.c_void_p()
        unmanagedData = ctypes.c_void_p(0)

        try:
            unmanagedData = create_string_buffer(len(data))
        except Exception as e:
            print(f'Exception on unmanagedData - {e}')
            retcode = 1
            return 1
        
        if isBeaconObject == True:
            self.coffSectionMapping = []
            self.beaconSectionMapping = []
            self.BeaconInternalMapping = []
            sectionMapping = self.beaconSectionMapping

            self.beaconFunctionMapping = Win32.VirtualAlloc(
                ctypes.c_void_p(0),
                2048,
                Win32.Commit | Win32.Reserve | Win32.TopDown,
                Win32.PAGE_EXECUTE_READWRITE
            )
            self.beaconFunctionMapping = self.beaconFunctionMapping
            self.coffFunctionMapping =self.coffFunctionMapping
            functionMapping = self.beaconFunctionMapping

        else:
            self.coffFunctionMapping = Win32.VirtualAlloc(
                ctypes.c_void_p(0),
                2048,
                Win32.Commit | Win32.Reserve | Win32.TopDown,
                Win32.PAGE_EXECUTE_READWRITE
            )
            sectionMapping = self.coffSectionMapping
            functionMapping = self.coffFunctionMapping

        if data == None:
            print('Cannot Execut NONE')
            return
                
        ctypes.memmove(unmanagedData, data, len(data))
        coff_data = cast(unmanagedData, POINTER(c_ubyte))
        coff_header = cast(coff_data, POINTER(COFF_FILE_HEADER))

        if coffDebug:
            print(f'---------coff header---------')
            print("- Machine: 0x{0:X}".format(coff_header.contents.Machine))
            print("- Sections: {0}".format(coff_header.contents.NumberOfSections))
            print("- Symbols: {0}".format(coff_header.contents.NumberOfSymbols))
            print("- Symbol Table Offset: 0x{0:X}".format(coff_header.contents.PointerToSymbolTable))
            print("- Section Mapping Count: {0}".format(len(sectionMapping)))
            print(f'---------end of coff header---------')

        #parse coff header
        for counter in range(coff_header.contents.NumberOfSections):
            offset = sizeof(COFF_FILE_HEADER) + (counter * sizeof(COFF_SECT))
            coff_section = cast(
                addressof(unmanagedData) + offset,
                POINTER(COFF_SECT)
            )
            section_name = StructHelper.ConvertToString(coff_section.contents.Name)            
            rawSize = coff_section.contents.SizeOfRawData

            if coffDebug:
                print(f'testing parsing coff_data ke coff_section')
                print("=== SECTION MAPPING ===")
                print(f"[{counter}] {section_name}")
                print(f"  VirtualAddress     = 0x{coff_section.contents.VirtualAddress:08X}")
                print(f"  PointerToRawData   = 0x{coff_section.contents.PointerToRawData:08X}")
                print(f"  SizeOfRawData      = 0x{coff_section.contents.SizeOfRawData:08X}")
                print(f"  Characteristics    = 0x{coff_section.contents.Characteristics:08X}")

                print(f'size: 0x{rawSize}')

            tmpAddr = Win32.VirtualAlloc(
                None,
                rawSize,
                Win32.Commit | Win32.Reserve | Win32.TopDown,
                Win32.PAGE_EXECUTE_READWRITE
            )
            
            if tmpAddr == ctypes.c_void_p(0):
                print(f'TmpAddr is Null !')
                print(Win32.GetLastError())

            if coff_section.contents.PointerToRawData > 0:
                src_address = addressof(unmanagedData) + coff_section.contents.PointerToRawData
                src_ptr = ctypes.c_void_p(src_address)
                # destination pointer
                dst_ptr = ctypes.c_void_p(tmpAddr)
                ctypes.memmove(dst_ptr.value, src_ptr.value, rawSize)

            sectionMapping.append(tmpAddr)

        # /* Start parsing the relocations, and *hopefully* handle them correctly. */
        for counter in range(coff_header.contents.NumberOfSections):

            if coffDebug:
                print('relocation coff header')
                print(f'Processing section {counter}, NumberOfRelocations: {coff_section.contents.NumberOfRelocations}')
                # print(f'testing relocation coff_data ke coff_section')

            offset = sizeof(COFF_FILE_HEADER) + (counter * sizeof(COFF_SECT))
            coff_section = cast(addressof(unmanagedData) + offset, POINTER(COFF_SECT))

            for reloccount in range(coff_section.contents.NumberOfRelocations):
                # print(f'-------New Relocation---------')
                
                coff_relocation = cast(addressof(unmanagedData) + 
                                        coff_section.contents.PointerToRelocations + (reloccount * sizeof(COFF_RELOC)),
                                          POINTER(COFF_RELOC))
                
                if coffDebug:
                    # print(f'-------New Relocation---------')
                    print(f"\n  [RELOC DEBUG] Counter: {counter}, Reloc#: {reloccount}")
                    print(f"    VirtualAddress: 0x{coff_relocation.contents.VirtualAddress:X} <--> {coff_relocation.contents.VirtualAddress}")
                    print(f"    Type: {coff_relocation.contents.Type}")
                    print(f"    SymbolTableIndex: {coff_relocation.contents.SymbolTableIndex}")

                    print(f"  VirtualAddress: 0x{coff_relocation.contents.VirtualAddress:X}")
                    print(f"  SymbolTableIndex: {coff_relocation.contents.SymbolTableIndex}")
                    print(f"  Type: {coff_relocation.contents.Type}")
                
                # offsetSymbol = 

                coff_symbol = cast(addressof(unmanagedData) + coff_header.contents.PointerToSymbolTable + (coff_relocation.contents.SymbolTableIndex * sizeof(COFF_SYM)), POINTER(COFF_SYM))

                rawname = bytes(coff_symbol.contents.Name)
                zeroes = int.from_bytes(rawname[0:4], "little") # value_u[0]
                zerotwo = int.from_bytes(rawname[4:8], "little") # value_u[1]

                if zeroes != 0:
                    if coff_relocation.contents.Type == Win32.IMAGE_REL_AMD64_ADDR64:
                        address = sectionMapping[counter] + coff_relocation.contents.VirtualAddress
                        longoffsetvalue = ctypes.c_int64.from_address(address).value
                        kipak = sectionMapping[coff_symbol.contents.SectionNumber - 1]
                        longoffsetvalue = kipak + longoffsetvalue

                        if coffDebug:
                            print(f"ADDR64 relocation (type 1) - 64-bit VA")                            
                            print(f"Section Base: 0x{sectionMapping[counter]:X}")
                            print(f"VirtualAddress: 0x{coff_relocation.contents.VirtualAddress:X}")
                            print(f"Relocation Address: 0x{address:X}")
                            print(f"\tReadin longOffsetValue : 0x{longoffsetvalue:X }")
                            print(f'Modified longoffsetvalue: 0x{longoffsetvalue.value:X} - base addr 0x{sectionMapping[coff_symbol.contents.SectionNumber - 1]}')
                        
                        c_int64.from_address(address).value = longoffsetvalue

                    elif coff_relocation.contents.Type == Win32.IMAGE_REL_AMD64_ADDR32NB:
                        offsetvalue = c_int32.from_address(
                            sectionMapping[counter] + coff_relocation.contents.VirtualAddress
                        ).value

                        a = sectionMapping[coff_symbol.contents.SectionNumber -1 ] + offsetvalue
                        b = sectionMapping[counter] + coff_relocation.contents.VirtualAddress + 4

                        # print(f'Reading reloccount: 0x{counter:X}')
                        # print(f'OffsetValue: 0x{offsetvalue:X}')
                        # print(f'End of relocation bytes 0x{b:X}')

                        if (a - b) > 0xffffffff:
                            print("Relocations > 4 gigs away, exiting")
                            retcode = 1
                            return retcode

                        offsetvalue = a-b
                        # print(f'OffsetValue: 0x{offsetvalue}')
                        # print(f'Setting 0x{sectionMapping[counter] + coff_relocation.contents.VirtualAddress:X} to 0x{offsetvalue:X}')

                        c_int32.from_address((b - 4)).value = offsetvalue
                       
                    elif coff_relocation.contents.Type == Win32.IMAGE_REL_AMD64_REL32:
                        # print("masuk IMAGE_REL_AMD64_REL32 internal")
                        offsetvalue = ctypes.c_uint.from_address(sectionMapping[counter] + coff_relocation.contents.VirtualAddress)
                        # print(f'Reading offset value: 0x{offsetvalue.value:X}')
                        
                        # Hitung alamat tujuan
                        if coff_symbol.contents.SectionNumber > 0:
                            a = sectionMapping[coff_symbol.contents.SectionNumber - 1]
                            b = sectionMapping[counter] + coff_relocation.contents.VirtualAddress + 4

                            if (a - b) > 0xffffffff:
                                print("Relocations > 4 gigs away, exiting")
                                return 1
                            
                            offsetvalue = offsetvalue.value
                            offsetvalue += a - b
                            offsetvalue += coff_symbol.contents.Value
                            offsetvalue += coff_relocation.contents.Type - Win32.IMAGE_REL_AMD64_REL32

                            # print(f'\t\tRelative Address: 0x{offsetvalue:X}')
                            ctypes.c_int32.from_address(b - 4).value = offsetvalue
                        
                    else:
                        print(f'No Relocation found for {coff_relocation.contents.Type}')

                else:
                    symptr = zerotwo

                    offset = coff_header.contents.PointerToSymbolTable + (coff_header.contents.NumberOfSymbols * sizeof(COFF_SYM)) + symptr
                    char_ptr = cast(addressof(unmanagedData) + offset, POINTER(c_ubyte))

                    functionZerotwo = bytearray()
                    i = 0
                    while char_ptr[i] != 0:
                        functionZerotwo.append(char_ptr[i])
                        i += 1

                    functionZerotwo = functionZerotwo.decode('ascii')

                    # print(f"offset 0x{offset:X}, functionName {functionZerotwo}")
                    procsym = self.process_symbol(functionZerotwo)
                    funcptrlocation = ctypes.c_void_p(procsym)

                    if funcptrlocation == None and isBeaconObject == False:
                        print('failed to resolve symbol')
                        retcode=1
                        return retcode
                    
                    if coff_relocation.contents.Type == Win32.IMAGE_REL_AMD64_REL32:
                        tmp = functionMapping
                        a = tmp + functionMappingCount * 8
                        b = sectionMapping[counter] + coff_relocation.contents.VirtualAddress + 4

                        if (a - b) > 0xffffffff:
                            print("Relocations > 4 gigs away, exiting")
                            return 1
                        
                        func_ptr_value = ctypes.c_uint64(funcptrlocation.value).value
                        func_ptr_bytes = func_ptr_value.to_bytes(8, byteorder='little', signed=False)

                        ctypes.memmove(ctypes.c_void_p(a), func_ptr_bytes, 8)

                        offset_value = ctypes.c_uint32(a - b).value
                        offset_bytes = offset_value.to_bytes(4, byteorder='little', signed=False)
                        
                        ctypes.memmove(ctypes.c_void_p(b - 4), offset_bytes, 4)

                        functionMappingCount += 1

                    elif coff_relocation.contents.Type >= Win32.IMAGE_REL_AMD64_REL32 and coff_relocation.Type <= Win32.IMAGE_REL_AMD64_REL32_5:
                        print("coff_sym->value_u[0] == 0  <==> coff_reloc->type between 4 and 9")
                        '''
                        This shouldn't be needed here, but incase there's a defined symbol
                             * that somehow doesn't have a function, try to resolve it here.
                        '''
                        a = sectionMapping[coff_symbol.contents.SectionNumber - 1]
                        b = sectionMapping[counter] + coff_relocation.contents.VirtualAddress + 4
                        # c = ctypes.c_void_p(b - 4)
                        c = b - 4
                        offsetvalue1 = c_long.from_address(c).value

                        if (a - b) > 0xffffffff:
                            print("Relocation > 4GB away, fatal")
                            retcode = 1
                            return retcode
                        
                        print(f'Reading offset value 0x{offsetvalue1}')
                        
                        offsetvalue1 += sectionMapping[coff_symbol.contents.SectionNumber - 1] - b
                        offsetvalue1 += coff_symbol.contents.Value
                        offsetvalue1 += coff_relocation.contents.Type - Win32.IMAGE_REL_AMD64_REL32

                        print(f'Relative Addr - 0x{offsetvalue1.value}')

                        value64 = c_long(offsetvalue1.value)  # gunakan c_longlong jika ingin 64-bit
                        Win32.memcpy(c, byref(value64), sizeof(value64))
                    else:
                        pass
                        # print(f'NO CODE RELOCATION TYPE FOR ALLOC {coff_relocation.contents.Type}')

        # print('Symbols')
        # while tempcounter < coff_header.contents.NumberOfSymbols:
        for tempcounter in range(coff_header.contents.NumberOfSymbols):
            coff_symbol = cast(
                addressof(unmanagedData) + coff_header.contents.PointerToSymbolTable + (tempcounter * sizeof(COFF_SYM)), 
                POINTER(COFF_SYM))
            
            if isBeaconObject == False:
                if self.memcmp(coff_symbol.contents.Name, functionname.decode()) == 0:
                    entry_address = (
                        sectionMapping[coff_symbol.contents.SectionNumber - 1] +
                        coff_symbol.contents.Value
                    )
                    section_base = sectionMapping[coff_symbol.contents.SectionNumber - 1]
                    
                   
                    print(f"[+] Found entry {functionname.decode()}!")
                    print(f"    Address to execute: 0x{entry_address:X}")
                    if coffDebug:
                        print("=== SYMBOL VALIDATION ===")
                        print(f"Symbol: {functionname.decode()}")
                        print(f"Section Number: {coff_symbol.contents.SectionNumber}")
                        print(f"Section Base: 0x{section_base:X}")
                        print(f"Symbol Value (offset): 0x{coff_symbol.contents.Value:X}")
                        print(f"Calculated Address: 0x{entry_address:X}")
                        print(f"Section Mapping Count: {len(sectionMapping)}")
                        print('----------------------------------------')
                        buf = (ctypes.c_ubyte * 32).from_address(entry_address)
                        print([hex(b) for b in buf])
                        print('----------------------------------------')
                        print('DUMPING BYTES -----')
                        self.dump_bytes(entry_address, 64)

                        mbi = self.get_memory_protection(entry_address)

                        protect = PAGE_FLAGS.get(mbi.Protect, f"0x{mbi.Protect:X}")

                        print("\n=== MEMORY PERMISSION CHECK ===")
                        print(f"Address:          0x{entry_address:X}")
                        print(f"BaseAddress:      0x{mbi.BaseAddress:X}")
                        print(f"RegionSize:       0x{mbi.RegionSize:X}")
                        print(f"AllocationBase:   0x{mbi.AllocationBase:X}")
                        print(f"AllocationProtect:{mbi.AllocationProtect}")
                        print(f"Protect:          {protect}")
                        print("==============================\n")

                        print("\n=== VERIFYING RELOCATIONS ===")
                        a = '''
                        whoami.x64.o
                        970:   48 83 ec 28             sub    $0x28,%rsp
                        974:   e8 87 f6 ff ff          call   0 <bofstart>
                        979:   e8 78 fa ff ff          call   3f6 <WhoamiUser>
                        97e:   e8 3b fb ff ff          call   4be <WhoamiGroups>
                        983:   e8 e7 fd ff ff          call   76f <WhoamiPriv>
                        988:   b9 01 00 00 00          mov    $0x1,%ecx
                        98d:   48 83 c4 28             add    $0x28,%rsp
                        991:   e9 98 f6 ff ff          jmp    2e <printoutput>
                        '''
                        print(a)

                        go_address = entry_address
                        for i in range(0, 64, 8):
                            bytes_at_addr = (ctypes.c_ubyte * 8).from_address(go_address + i)
                            hex_str = " ".join(f"{b:02X}" for b in bytes_at_addr)
                            print(f"0x{go_address + i:016X}: {hex_str}")

                        # Cek khusus untuk instruksi call
                        print("\n=== CHECKING CALL INSTRUCTIONS ===")
                        for offset in [0x974 - 0x970, 0x979 - 0x970, 0x97E - 0x970, 0x983 - 0x970]:
                            addr = go_address + offset
                            bytes_at_addr = (ctypes.c_ubyte * 5).from_address(addr)
                            print(f"Call at 0x{addr:X}: {bytes_at_addr[0]:02X} {bytes_at_addr[1]:02X} {bytes_at_addr[2]:02X} {bytes_at_addr[3]:02X} {bytes_at_addr[4]:02X}")

                    '''
                    Siganture:
                    VOID go( 
                        IN PCHAR Buffer, 
                        IN ULONG Length 
                    ) 
                    '''
                    FUNC_PROTO = ctypes.CFUNCTYPE(
                        None,               # VOID
                        ctypes.c_void_p,    # PCHAR (raw pointer)
                        ctypes.c_ulong      # ULONG
                    )
                    argSize = len(argumentData)
                        
                    # print(f"[+] Argument buffer size: {argSize}")
                    foo = FUNC_PROTO(entry_address)

                    funcName = Win32.VirtualAlloc(
                        None,
                        argSize,
                        Win32.Commit | Win32.Reserve,
                        Win32.PAGE_EXECUTE_READWRITE
                    )

                    if not funcName:
                        raise RuntimeError("VirtualAlloc failed!")
                    
                    print(f"[+] Allocated RWX memory @ 0x{funcName:X}")
                    ctypes.memmove(funcName, argumentData, argSize)

                    print(f'[+] Executing BOF')

                    funcName_ptr = ctypes.c_void_p(funcName)
                    arg_ptr =  ctypes.c_ulong(argumentSize)
                    foo(funcName_ptr,arg_ptr)

                    print("[+] Beacon Object File Completed.")
                    
                    Win32.VirtualFreeEx(None, funcName, 0, Win32.Release)
                    print("[*] Memory released.\n")
                    break
            else:                
                if (
                    int.from_bytes(coff_symbol.contents.Name[0:4], "little") != 0 or
                    coff_symbol.contents.Type != 0x20 or
                    coff_symbol.contents.SectionNumber != 1
                ):
                    continue

                offset = int.from_bytes(coff_symbol.contents.Name[4:8], "little")

                string_table_start = (
                    coff_header.contents.PointerToSymbolTable +
                    coff_header.contents.NumberOfSymbols * sizeof(COFF_SYM)
                )
                str_offset = string_table_start + offset

                if str_offset >= len(data):
                    return

                # Marshal.PtrToStringAnsi( coff_data + ... )
                try:
                    name_ptr = ctypes.cast(
                        addressof(unmanagedData) + str_offset,
                        ctypes.c_char_p
                    )
                    function_name = name_ptr.value.decode("ascii", errors="ignore")
                except:
                    return

                if not function_name:
                    return

                hash_val = self.hash_djb(function_name)

                section_index = coff_symbol.contents.SectionNumber - 1
                if section_index >= len(sectionMapping):
                    return

                function_address = ctypes.c_void_p(
                    sectionMapping[section_index] + coff_symbol.contents.Value
                )

                self.BeaconInternalMapping.append(
                    BEACON_FUNCTION(hash_val, function_address)
                )                    

        if unmanagedData != ctypes.c_void_p(0):
            pass
        if isBeaconObject == False:
            self.CleanUpMemoryAllocations()

        return retcode
    
    def ZeroAndFree(self, ptr, size):
        try:            
            if size > 0:
                # self.memset(ptr, b'\x00', size)
                ctypes.memset(ptr, 0, size)

            Win32.VirtualFreeEx(
                None,
                ptr,
                0,
                Win32.Release
            )
        except Exception as e:
            # pass
            print(f'Exception di ZeroAndFree - {e}')
            
    def CleanUpMemoryAllocations(self):
        '''
        // TODO: Optionally, zero out or stomp memory of loaded object file, Would need to reparse the sectons or store the size somewhere
        '''
        for ptr in self.beaconSectionMapping:
            self.ZeroAndFree(ptr, 0)

        for ptr in self.coffSectionMapping:
            self.ZeroAndFree(ptr, 0)

        if self.beaconFunctionMapping != c_void_p(0):
            self.ZeroAndFree(self.beaconFunctionMapping, 2048)

        if self.coffFunctionMapping != c_void_p(0):
            self.ZeroAndFree(self.coffFunctionMapping, 2048)

        return 0
    
    def getBeaconOutputData(self):
        functionaddress = c_void_p()
        output_size = ctypes.c_int(0)

        local_hash = self.hash_djb('BeaconGetOutputData'.encode())
        for tmp in self.BeaconInternalMapping:
            # print(f'lokal hash - {local_hash}')
            # print(f'hash di BeaconInternalMapping - {tmp.hash}')
            # dhash = self.hash_djb(localfunction)

            if local_hash == tmp.hash:
                print(f'[+] Local Function: BeaconGetOutputData')
                functionaddress = tmp.function
                break

        if functionaddress == None:
            return
        
        print(f'[+] GetOutput Function 0x{functionaddress}')

        # int* as POINTER(c_int), return char*
        FuncDelegate_GetOutput = ctypes.CFUNCTYPE(
            ctypes.c_char_p,  # return char*
            ctypes.POINTER(ctypes.c_int)    # arg: int*
        )
        foo = FuncDelegate_GetOutput(functionaddress)

        output = foo(ctypes.byref(output_size))

        output_str = ctypes.cast(output, ctypes.c_char_p).value.decode('ascii')

        return output
    
    def dump_bytes(self, address, size=64):
        data = (ctypes.c_ubyte * size).from_address(address)
        hexstr = " ".join(f"{b:02X}" for b in data)
        print(f"[+] Dump {size} bytes @ 0x{address:X}")
        print(hexstr)
        return data
