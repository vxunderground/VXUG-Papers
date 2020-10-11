using System;
using System.IO;
using SharpHellsGate.Win32;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Linq;

namespace SharpHellsGate.Module {

    /// <summary>
    /// Wrapper around the NTDLL module.
    /// Used to extract structures and find system calls.
    /// </summary>
    public class SystemModule : MemoryUtil {

        /// <summary>
        /// IMAGE_DOS_HEADER structure of the NTDLL module.
        /// </summary>
        public Structures.IMAGE_DOS_HEADER ModuleDOSHeader { get; private set; }

        /// <summary>
        /// IMAGE_NT_HEADERS64 structure of the NTDLL module.
        /// </summary>
        public Structures.IMAGE_NT_HEADERS64 ModuleNTHeaders { get; private set; }

        /// <summary>
        /// IMAGE_SECTION_HEADER structure from the NTDLL module.
        /// </summary>
        public List<Structures.IMAGE_SECTION_HEADER> ModuleSectionHeaders { get; private set; }

        /// <summary>
        /// IMAGE_EXPORT_DIRECTORY structure from the NTDLL module.
        /// </summary>
        public Structures.IMAGE_EXPORT_DIRECTORY ModuleExportDirectory { get; private set; }

        /// <summary>
        /// Location in the memory stream of the IMAGE_EXPORT_DIRECTORY structure.
        /// </summary>
        public Int64 ModuleExportDirectoryOffset { get; private set; }

        /// <summary>
        /// Location in the memory stream of the exported functions' name.
        /// </summary>
        public Int64 ModuleExportDirectoryAddressNamesOffset { get; private set; }

        /// <summary>
        /// Location in the memory stream of the exported functions' address.
        /// </summary>
        public Int64 ModuleExportDirectoryAddressFunctionsOffset { get; private set; }

        /// <summary>
        /// Location in the memory stream of the exported functions' ordinal.
        /// </summary>
        public Int64 ModuleExportDirectoryAddressNameOrdinalesOffset { get; private set; }

        /// <summary>
        /// Name of the module. Will be NTDLL.
        /// </summary>
        public string ModuleName { get; private set; }

        /// <summary>
        /// Path of the module. Will be %WINDIR%\System32\ntdll.dll
        /// </summary>
        public string ModulePath { get; private set; }

        /// <summary>
        /// .ctor
        /// </summary>
        /// <param name="name">Name of the module</param>
        public SystemModule(string name) : base() {
            this.ModuleName = name;
            this.ModulePath = $"{Environment.SystemDirectory}\\{name}";
            this.ModuleSectionHeaders = new List<Structures.IMAGE_SECTION_HEADER>() { };

            this.LoadModule();
        }

        /// <summary>
        /// Load the module into a memory stream.
        /// </summary>
        /// <returns>Whether the loading process was a success.</returns>
        public bool LoadModule() {
            if (string.IsNullOrEmpty(this.ModuleName)) {
                Util.LogError("Module name not provided");
                return false;
            }

            if (!File.Exists(this.ModulePath)) {
                Util.LogError($"Unable to find module: {this.ModuleName}");
                return false;
            }

            ReadOnlySpan<byte> ModuleBlob = File.ReadAllBytes(this.ModulePath);
            if (ModuleBlob.Length == 0x00) {
                Util.LogError($"Empty module content: {this.ModuleName}");
                return false;
            }

            base.ModuleStream = new MemoryStream(ModuleBlob.ToArray());
            return true;
        }

        /// <summary>
        /// Reload all structures.
        /// </summary>
        /// <returns>Whether all structures were successfully reloaded.</returns>
        public bool LoadAllStructures() {
            if (this.GetModuleDOSHeader(true).Equals(default(Structures.IMAGE_DOS_HEADER)))
                return false;

            if (this.GetModuleNTHeaders(true).Equals(default(Structures.IMAGE_NT_HEADERS64)))
                return false;

            if (this.GetModuleSectionHeaders(true).Count != this.ModuleNTHeaders.FileHeader.NumberOfSections)
                return false;

            if (this.GetModuleExportDirectory(true).Equals(default(Structures.IMAGE_EXPORT_DIRECTORY)))
                return false;

            return true;
        }

        /// <summary>
        /// Get the _IMAGE_DOS_HEADERstructure from the module.
        /// </summary>
        /// <param name="ReloadCache">Whether the data has to re-processed if not already cached.</param>
        /// <returns>The IMAGE_NT_HEADERS64 structure of the module.</returns>
        public Structures.IMAGE_DOS_HEADER GetModuleDOSHeader(bool ReloadCache = false) {
            if (!this.ModuleDOSHeader.Equals(default(Structures.IMAGE_DOS_HEADER)) && !ReloadCache)
                return this.ModuleDOSHeader;

            if (!base.ModuleStream.CanRead || base.ModuleStream.Length == 0x00) {
                Util.LogError("Module not loaded");
                return default;
            }

            this.ModuleDOSHeader = base.GetStructureFromBlob<Structures.IMAGE_DOS_HEADER>(0);
            if (this.ModuleDOSHeader.e_magic != Macros.IMAGE_DOS_SIGNATURE) {
                Util.LogError("Invalid DOS header signature");
                return default;
            }

            return this.ModuleDOSHeader;
        }

        /// <summary>
        /// Get the IMAGE_NT_HEADERS64 structure from the module.
        /// </summary>
        /// <param name="ReloadCache">Whether the data has to re-processed if not already cached.</param>
        /// <returns>The IMAGE_NT_HEADERS64 structure of the module.</returns>
        public Structures.IMAGE_NT_HEADERS64 GetModuleNTHeaders(bool ReloadCache = false) {
            if (!this.ModuleNTHeaders.Equals(default(Structures.IMAGE_NT_HEADERS64)) && !ReloadCache)
                return this.ModuleNTHeaders;

            if (!base.ModuleStream.CanRead || base.ModuleStream.Length == 0x00) {
                Util.LogError("Module not loaded");
                return default;
            }

            if (this.ModuleDOSHeader.Equals(default(Structures.IMAGE_DOS_HEADER)))
                this.GetModuleDOSHeader();

            this.ModuleNTHeaders = base.GetStructureFromBlob<Structures.IMAGE_NT_HEADERS64>(this.ModuleDOSHeader.e_lfanew);
            if (this.ModuleNTHeaders.Signature != Macros.IMAGE_NT_SIGNATURE) {
                Util.LogError("Invalid NT headers signature");
                return default;
            }

            return this.ModuleNTHeaders;
        }

        /// <summary>
        /// Get list of _IMAGE_SECTION_HEADER structures from the module. 
        /// </summary>
        /// <param name="ReloadCache">Whether the data has to re-processed if not already cached.</param>
        /// <returns>The list of _IMAGE_SECTION_HEADER structures.</returns>
        public List<Structures.IMAGE_SECTION_HEADER> GetModuleSectionHeaders(bool ReloadCache = false) {
            if (this.ModuleSectionHeaders.Count == this.ModuleNTHeaders.FileHeader.NumberOfSections && !ReloadCache)
                return this.ModuleSectionHeaders;

            if (!base.ModuleStream.CanRead || base.ModuleStream.Length == 0x00) {
                Util.LogError("Module not loaded");
                return default;
            }

            if (this.ModuleNTHeaders.Equals(default(Structures.IMAGE_NT_HEADERS64)) || this.ModuleNTHeaders.FileHeader.Equals(default(Structures.IMAGE_FILE_HEADER)))
                this.GetModuleNTHeaders();

            for (Int16 cx = 0; cx < this.ModuleNTHeaders.FileHeader.NumberOfSections; cx++) {
                Int64 iSectionOffset = this.GetModuleSectionOffset(cx);

                Structures.IMAGE_SECTION_HEADER ImageSection = base.GetStructureFromBlob<Structures.IMAGE_SECTION_HEADER>(iSectionOffset);
                if (!ImageSection.Equals(default(Structures.IMAGE_SECTION_HEADER)))
                    this.ModuleSectionHeaders.Add(ImageSection);
            }

            return this.ModuleSectionHeaders;
        }

        /// <summary>
        /// Get a _IMAGE_SECTION_HEADER structure by name.
        /// </summary>
        /// <param name="name">The name of the section.</param>
        /// <returns>The _IMAGE_SECTION_HEADER structure if exists.</returns>
        public Structures.IMAGE_SECTION_HEADER GetModuleSectionHeaderByName(string name) {
            if (name.Length > 8) {
                Util.LogError("Invalid section name");
                return default;
            }

            if (!base.ModuleStream.CanRead || base.ModuleStream.Length == 0x00) {
                Util.LogError("Module not loaded");
                return default;
            }

            if (this.ModuleSectionHeaders.Count == 0x00)
                this.GetModuleSectionHeaders();

            return this.ModuleSectionHeaders.Where(x => x.Name.Equals(name, StringComparison.OrdinalIgnoreCase)).FirstOrDefault();
        }

        /// <summary>
        /// Get the Export Address Table (aka EAT) from the module.
        /// </summary>
        /// <param name="ReloadCache">Whether the data has to re-processed if not already cached.</param>
        /// <returns>the _IMAGE_EXPORT_DIRECTORY structure</returns>
        public Structures.IMAGE_EXPORT_DIRECTORY GetModuleExportDirectory(bool ReloadCache = false) {
            if (!this.ModuleExportDirectory.Equals(default(Structures.IMAGE_EXPORT_DIRECTORY)) && !ReloadCache)
                return this.ModuleExportDirectory;

            if (!base.ModuleStream.CanRead || base.ModuleStream.Length == 0x00) {
                Util.LogError("Module not loaded");
                return default;
            }

            if (this.ModuleNTHeaders.Equals(default(Structures.IMAGE_NT_HEADERS64)))
                this.GetModuleNTHeaders();
            
            if (this.ModuleSectionHeaders.Count == 0x00)
                this.GetModuleSectionHeaders();

            this.ModuleExportDirectoryOffset = this.ConvertRvaToOffset(this.ModuleNTHeaders.OptionalHeader.DataDirectory[0].VirtualAddress);
            this.ModuleExportDirectory = base.GetStructureFromBlob<Structures.IMAGE_EXPORT_DIRECTORY>(this.ModuleExportDirectoryOffset);
            if (this.ModuleExportDirectory.Equals(default(Structures.IMAGE_EXPORT_DIRECTORY))) {
                Util.LogError("Invalid export address table (EAT).");
                return default;
            }

            // Parse all functions
            this.ModuleExportDirectoryAddressNamesOffset = this.ConvertRvaToOffset(this.ModuleExportDirectory.AddressOfNames);
            this.ModuleExportDirectoryAddressFunctionsOffset = this.ConvertRvaToOffset(this.ModuleExportDirectory.AddressOfFunctions);
            this.ModuleExportDirectoryAddressNameOrdinalesOffset = this.ConvertRvaToOffset(this.ModuleExportDirectory.AddressOfNameOrdinals);
            return this.ModuleExportDirectory;
        }

        /// <summary>
        /// Get the address, name, system call for a given function hash.
        /// </summary>
        /// <param name="FunctionHash">DJB2 function hash.</param>
        /// <returns></returns>
        public Util.APITableEntry GetAPITableEntry(UInt64 FunctionHash) {
            if (this.ModuleExportDirectoryAddressNamesOffset == 0x00 || this.ModuleExportDirectoryAddressFunctionsOffset == 0x00|| this.ModuleExportDirectoryAddressNameOrdinalesOffset == 0x00)
                this.GetModuleExportDirectory();

            if (!base.ModuleStream.CanRead || base.ModuleStream.Length == 0x00) {
                Util.LogError("Module not loaded");
                return default;
            }

            Util.APITableEntry Entry = new Util.APITableEntry {
                Hash = FunctionHash
            };

            for (Int32 cx = 0; cx < this.ModuleExportDirectory.NumberOfNames; cx++) {
                UInt32 PtrFunctionName = base.ReadPtr32(this.ModuleExportDirectoryAddressNamesOffset + (sizeof(uint) * cx));
                string FunctionName = base.ReadAscii(this.ConvertRvaToOffset(PtrFunctionName));

                if (FunctionHash == Util.GetFunctionDJB2Hash(FunctionName)) {
                    UInt32 PtrFunctionAdddress = base.ReadPtr32(this.ModuleExportDirectoryAddressFunctionsOffset + (sizeof(uint) * (cx + 1)));
                    Span<byte> opcode = base.GetFunctionOpCode(this.ConvertRvaToOffset(PtrFunctionAdddress));

                    if (opcode[3] == 0xb8 && opcode[18] == 0x0f && opcode[19] == 0x05) {
                        Entry.Name = FunctionName;
                        Entry.Address = PtrFunctionAdddress;
                        Entry.Syscall = (Int16)(((byte)opcode[5] << 4) | (byte)opcode[4]);
                        return Entry;
                    }
                }
            }

            return default;
        }

        /// <summary>
        /// Get the offset of a _IMAGE_SECTION_HEADER structure. 
        /// </summary>
        /// <param name="cx">The section to get.</param>
        /// <returns>The _IMAGE_SECTION_HEADER structure.</returns>
        private Int64 GetModuleSectionOffset(Int16 cx)
            => this.ModuleDOSHeader.e_lfanew
            + Marshal.SizeOf<Structures.IMAGE_FILE_HEADER>()
            + this.ModuleNTHeaders.FileHeader.SizeOfOptionalHeader
            + sizeof(Int32) // sizeof(DWORD)
            + (Marshal.SizeOf<Structures.IMAGE_SECTION_HEADER>() * cx);

        /// <summary>
        /// Convert a relative virtual address (RVA) into an offset.
        /// </summary>
        /// <param name="rva">The RVA to convert into an offset in the iamge.</param>
        /// <param name="SectionHeader">The section in which the relative virtual address (RVA) points to.</param>
        /// <returns>The offset.</returns>
        private Int64 ConvertRvaToOffset(Int64 rva, Structures.IMAGE_SECTION_HEADER SectionHeader) => rva - SectionHeader.VirtualAddress + SectionHeader.PointerToRawData;

        /// <summary>
        /// Convert a relative virtual address (RVA) into an offset.
        /// </summary>
        /// <param name="rva">The RVA to convert into an offset in the iamge.</param>
        /// <returns>The offset.</returns>
        private Int64 ConvertRvaToOffset(Int64 rva) => this.ConvertRvaToOffset(rva, GetSectionByRVA(rva));

        /// <summary>
        /// Get which image section is which a relative virtual address (RVA) points to.
        /// </summary>
        /// <param name="rva">The RVA</param>
        /// <returns>The _IMAGE_SECTION_HEADER structure</returns>
        private Structures.IMAGE_SECTION_HEADER GetSectionByRVA(Int64 rva) => this.ModuleSectionHeaders.Where(x => rva > x.VirtualAddress && rva <= x.VirtualAddress + x.SizeOfRawData).First();
    }
}
