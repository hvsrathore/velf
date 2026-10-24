/* elf binary parser, virtual address mapper, and structural field editor */

use anyhow::{anyhow, Context, Result};
use goblin::elf::{
    header::{
        EM_386, EM_ARM, EM_X86_64, ET_CORE, ET_DYN, ET_EXEC, ET_NONE, ET_REL, Header,
    },
    program_header::{PF_R, PF_W, PF_X, PT_DYNAMIC, PT_INTERP, PT_LOAD, PT_NOTE, PT_PHDR, PT_TLS, ProgramHeader},
    section_header::{
        SHF_ALLOC, SHF_EXECINSTR, SHF_INFO_LINK, SHF_MERGE, SHF_STRINGS, SHF_WRITE, SectionHeader,
    },
    sym::{STT_FUNC, STT_OBJECT},
    Elf,
};
use std::fs;
use std::path::{Path, PathBuf};

/* field width descriptor for structural editing */
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FieldWidth {
    U8,
    U16,
    U32,
    U64,
}

/* field category for inspector rendering */
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldCategory {
    Ehdr,
    Phdr(usize),
    Shdr(usize),
}

/* metadata and physical byte offset for an editable ELF struct member */
#[derive(Debug, Clone)]
pub struct FieldDescriptor {
    pub category: FieldCategory,
    pub struct_name: String,
    pub field_name: String,
    pub file_offset: usize,
    pub width: FieldWidth,
    pub current_value: u64,
    pub is_flags: bool,
    pub description: String,
}

/* parsed section summary with flags and physical file bounds */
#[derive(Debug, Clone)]
pub struct SectionInfo {
    pub index: usize,
    pub name: String,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
    pub is_executable: bool,
}

/* parsed program header summary with segment bounds and memory permissions */
#[derive(Debug, Clone)]
pub struct SegmentInfo {
    pub index: usize,
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
    pub is_loadable: bool,
}

/* parsed symbol summary from .symtab or .dynsym */
#[derive(Debug, Clone)]
pub struct SymbolInfo {
    pub name: String,
    pub st_value: u64,
    pub st_size: u64,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: usize,
    pub is_function: bool,
    pub is_object: bool,
    pub is_dynamic: bool,
}

/* parsed relocation entry from PLT or GOT relocations */
#[derive(Debug, Clone)]
pub struct RelocInfo {
    pub r_offset: u64,
    pub r_addend: Option<i64>,
    pub r_sym: usize,
    pub sym_name: Option<String>,
    pub r_type: u32,
    pub is_plt: bool,
}

/* container holding raw binary bytes and parsed ELF data */
pub struct ElfBinary {
    pub bytes: Vec<u8>,
    pub filepath: Option<PathBuf>,
    pub is_64: bool,
    pub is_little_endian: bool,
    pub entry: u64,
    pub header: Header,
    pub sections: Vec<SectionInfo>,
    pub segments: Vec<SegmentInfo>,
    pub symbols: Vec<SymbolInfo>,
    pub relocations: Vec<RelocInfo>,
    pub fields: Vec<FieldDescriptor>,
}

impl ElfBinary {
    /* load an ELF binary from disk into a mutable byte buffer */
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path_buf = path.as_ref().to_path_buf();
        let bytes = fs::read(&path_buf)
            .with_context(|| format!("failed to read ELF binary from {:?}", path_buf))?;
        Self::parse_from_bytes(bytes, Some(path_buf))
    }

    /* parse ELF headers, sections, segments, symbols, and relocations from raw bytes */
    pub fn parse_from_bytes(bytes: Vec<u8>, filepath: Option<PathBuf>) -> Result<Self> {
        /* validate minimal ELF header size */
        if bytes.len() < 16 {
            return Err(anyhow!("file is too small to be a valid ELF binary"));
        }

        /* verify ELF magic: 0x7f, 'E', 'L', 'F' */
        if &bytes[0..4] != [0x7f, b'E', b'L', b'F'] {
            return Err(anyhow!("invalid ELF magic signature"));
        }

        /* determine bitness: EI_CLASS 1 = 32-bit, 2 = 64-bit */
        let is_64 = bytes[4] == 2;

        /* determine endianness: EI_DATA 1 = little-endian (Intel x86_64), 2 = big-endian */
        let is_little_endian = bytes[5] == 1;

        /* parse using goblin to inspect high-level structures */
        let elf = Elf::parse(&bytes).map_err(|e| anyhow!("goblin failed to parse ELF: {}", e))?;

        let entry = elf.entry;
        let header = elf.header;

        /* extract section headers with executable flag classification */
        let mut sections = Vec::with_capacity(elf.section_headers.len());
        for (i, sh) in elf.section_headers.iter().enumerate() {
            let name = elf
                .shdr_strtab
                .get_at(sh.sh_name)
                .unwrap_or("")
                .to_string();
            let is_executable = (sh.sh_flags & (SHF_EXECINSTR as u64)) != 0;
            sections.push(SectionInfo {
                index: i,
                name,
                sh_type: sh.sh_type,
                sh_flags: sh.sh_flags,
                sh_addr: sh.sh_addr,
                sh_offset: sh.sh_offset,
                sh_size: sh.sh_size,
                sh_link: sh.sh_link,
                sh_info: sh.sh_info,
                sh_addralign: sh.sh_addralign,
                sh_entsize: sh.sh_entsize,
                is_executable,
            });
        }

        /* extract program headers with loadable segment identification */
        let mut segments = Vec::with_capacity(elf.program_headers.len());
        for (i, ph) in elf.program_headers.iter().enumerate() {
            let is_loadable = ph.p_type == PT_LOAD;
            segments.push(SegmentInfo {
                index: i,
                p_type: ph.p_type,
                p_flags: ph.p_flags,
                p_offset: ph.p_offset,
                p_vaddr: ph.p_vaddr,
                p_paddr: ph.p_paddr,
                p_filesz: ph.p_filesz,
                p_memsz: ph.p_memsz,
                p_align: ph.p_align,
                is_loadable,
            });
        }

        /* extract symbol tables (.symtab and .dynsym) */
        let mut symbols = Vec::new();

        /* parse static symbols from .symtab */
        for sym in elf.syms.iter() {
            let name = elf.strtab.get_at(sym.st_name).unwrap_or("").to_string();
            let st_type = sym.st_type();
            let is_function = st_type == STT_FUNC;
            let is_object = st_type == STT_OBJECT;
            symbols.push(SymbolInfo {
                name,
                st_value: sym.st_value,
                st_size: sym.st_size,
                st_info: sym.st_info,
                st_other: sym.st_other,
                st_shndx: sym.st_shndx,
                is_function,
                is_object,
                is_dynamic: false,
            });
        }

        /* parse dynamic symbols from .dynsym */
        for sym in elf.dynsyms.iter() {
            let name = elf
                .dynstrtab
                .get_at(sym.st_name)
                .unwrap_or("")
                .to_string();
            let st_type = sym.st_type();
            let is_function = st_type == STT_FUNC;
            let is_object = st_type == STT_OBJECT;
            symbols.push(SymbolInfo {
                name,
                st_value: sym.st_value,
                st_size: sym.st_size,
                st_info: sym.st_info,
                st_other: sym.st_other,
                st_shndx: sym.st_shndx,
                is_function,
                is_object,
                is_dynamic: true,
            });
        }

        /* parse relocations from PLT and GOT */
        let mut relocations = Vec::new();
        for reloc in elf.pltrelocs.iter() {
            let sym_name = if reloc.r_sym < elf.dynsyms.len() {
                elf.dynsyms
                    .get(reloc.r_sym)
                    .and_then(|s| elf.dynstrtab.get_at(s.st_name).map(|st| st.to_string()))
            } else {
                None
            };
            relocations.push(RelocInfo {
                r_offset: reloc.r_offset,
                r_addend: reloc.r_addend,
                r_sym: reloc.r_sym,
                sym_name,
                r_type: reloc.r_type,
                is_plt: true,
            });
        }
        for reloc in elf.dynrelas.iter() {
            let sym_name = if reloc.r_sym < elf.dynsyms.len() {
                elf.dynsyms
                    .get(reloc.r_sym)
                    .and_then(|s| elf.dynstrtab.get_at(s.st_name).map(|st| st.to_string()))
            } else {
                None
            };
            relocations.push(RelocInfo {
                r_offset: reloc.r_offset,
                r_addend: reloc.r_addend,
                r_sym: reloc.r_sym,
                sym_name,
                r_type: reloc.r_type,
                is_plt: false,
            });
        }

        /* construct field descriptor table for interactive structural editing */
        let fields = Self::build_field_descriptors(
            &bytes,
            &header,
            &elf.program_headers,
            &elf.section_headers,
            &elf.shdr_strtab,
            is_little_endian,
        );

        Ok(Self {
            bytes,
            filepath,
            is_64,
            is_little_endian,
            entry,
            header,
            sections,
            segments,
            symbols,
            relocations,
            fields,
        })
    }

    /* re-parse the binary buffer following an in-place patch */
    pub fn reparse(&mut self) -> Result<()> {
        let parsed = Self::parse_from_bytes(self.bytes.clone(), self.filepath.clone())?;
        self.is_64 = parsed.is_64;
        self.is_little_endian = parsed.is_little_endian;
        self.entry = parsed.entry;
        self.header = parsed.header;
        self.sections = parsed.sections;
        self.segments = parsed.segments;
        self.symbols = parsed.symbols;
        self.relocations = parsed.relocations;
        self.fields = parsed.fields;
        Ok(())
    }

    /* build the structural field descriptor table mapping struct members to byte offsets */
    fn build_field_descriptors(
        bytes: &[u8],
        ehdr: &Header,
        phdrs: &[ProgramHeader],
        shdrs: &[SectionHeader],
        shdr_strtab: &goblin::strtab::Strtab,
        is_le: bool,
    ) -> Vec<FieldDescriptor> {
        let mut fields = Vec::new();

        /* read raw integer helper */
        let read_val = |offset: usize, width: FieldWidth| -> u64 {
            if offset + (width_to_bytes(width)) > bytes.len() {
                return 0;
            }
            match width {
                FieldWidth::U8 => bytes[offset] as u64,
                FieldWidth::U16 => {
                    let slice: [u8; 2] = bytes[offset..offset + 2].try_into().unwrap_or([0, 0]);
                    if is_le {
                        u16::from_le_bytes(slice) as u64
                    } else {
                        u16::from_be_bytes(slice) as u64
                    }
                }
                FieldWidth::U32 => {
                    let slice: [u8; 4] = bytes[offset..offset + 4].try_into().unwrap_or([0; 4]);
                    if is_le {
                        u32::from_le_bytes(slice) as u64
                    } else {
                        u32::from_be_bytes(slice) as u64
                    }
                }
                FieldWidth::U64 => {
                    let slice: [u8; 8] = bytes[offset..offset + 8].try_into().unwrap_or([0; 8]);
                    if is_le {
                        u64::from_le_bytes(slice)
                    } else {
                        u64::from_be_bytes(slice)
                    }
                }
            }
        };

        /* 1. Elf64_Ehdr member mapping */
        let ehdr_members: &[(&str, usize, FieldWidth, bool, &str)] = &[
            ("e_type", 16, FieldWidth::U16, false, "object file type (ET_EXEC, ET_DYN, ET_REL)"),
            ("e_machine", 18, FieldWidth::U16, false, "required architecture (EM_X86_64, EM_386)"),
            ("e_version", 20, FieldWidth::U32, false, "ELF specification version"),
            ("e_entry", 24, FieldWidth::U64, false, "Virtual Address (VA) entry point"),
            ("e_phoff", 32, FieldWidth::U64, false, "program header table file offset"),
            ("e_shoff", 40, FieldWidth::U64, false, "section header table file offset"),
            ("e_flags", 48, FieldWidth::U32, true, "processor-specific flags"),
            ("e_ehsize", 52, FieldWidth::U16, false, "ELF header size in bytes"),
            ("e_phentsize", 54, FieldWidth::U16, false, "program header entry size"),
            ("e_phnum", 56, FieldWidth::U16, false, "number of program header entries"),
            ("e_shentsize", 58, FieldWidth::U16, false, "section header entry size"),
            ("e_shnum", 60, FieldWidth::U16, false, "number of section header entries"),
            ("e_shstrndx", 62, FieldWidth::U16, false, "section header string table index"),
        ];

        for &(name, off, width, is_flags, desc) in ehdr_members {
            fields.push(FieldDescriptor {
                category: FieldCategory::Ehdr,
                struct_name: "Elf64_Ehdr".to_string(),
                field_name: name.to_string(),
                file_offset: off,
                width,
                current_value: read_val(off, width),
                is_flags,
                description: desc.to_string(),
            });
        }

        /* 2. Elf64_Phdr member mapping */
        let phoff = ehdr.e_phoff as usize;
        let phentsize = ehdr.e_phentsize as usize;
        for (i, ph) in phdrs.iter().enumerate() {
            let base = phoff + i * phentsize;
            let struct_name = format!("Elf64_Phdr[{}] ({})", i, format_pt_type(ph.p_type));

            let phdr_members: &[(&str, usize, FieldWidth, bool, &str)] = &[
                ("p_type", 0, FieldWidth::U32, false, "segment type (PT_LOAD, PT_DYNAMIC, PT_INTERP)"),
                ("p_flags", 4, FieldWidth::U32, true, "segment permissions (PF_R, PF_W, PF_X)"),
                ("p_offset", 8, FieldWidth::U64, false, "segment file offset"),
                ("p_vaddr", 16, FieldWidth::U64, false, "segment Virtual Address (VA)"),
                ("p_paddr", 24, FieldWidth::U64, false, "segment physical address"),
                ("p_filesz", 32, FieldWidth::U64, false, "segment size in file"),
                ("p_memsz", 40, FieldWidth::U64, false, "segment size in memory"),
                ("p_align", 48, FieldWidth::U64, false, "segment memory alignment boundary"),
            ];

            for &(name, rel_off, width, is_flags, desc) in phdr_members {
                let off = base + rel_off;
                fields.push(FieldDescriptor {
                    category: FieldCategory::Phdr(i),
                    struct_name: struct_name.clone(),
                    field_name: name.to_string(),
                    file_offset: off,
                    width,
                    current_value: read_val(off, width),
                    is_flags,
                    description: desc.to_string(),
                });
            }
        }

        /* 3. Elf64_Shdr member mapping */
        let shoff = ehdr.e_shoff as usize;
        let shentsize = ehdr.e_shentsize as usize;
        for (i, sh) in shdrs.iter().enumerate() {
            let base = shoff + i * shentsize;
            let sec_name = shdr_strtab.get_at(sh.sh_name).unwrap_or("");
            let struct_name = format!("Elf64_Shdr[{}] ({})", i, if sec_name.is_empty() { "NULL" } else { sec_name });

            let shdr_members: &[(&str, usize, FieldWidth, bool, &str)] = &[
                ("sh_name", 0, FieldWidth::U32, false, "section name string table offset"),
                ("sh_type", 4, FieldWidth::U32, false, "section type (SHT_PROGBITS, SHT_SYMTAB)"),
                ("sh_flags", 8, FieldWidth::U64, true, "section attributes (SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR)"),
                ("sh_addr", 16, FieldWidth::U64, false, "section Virtual Address (VA) in memory"),
                ("sh_offset", 24, FieldWidth::U64, false, "section physical offset in file"),
                ("sh_size", 32, FieldWidth::U64, false, "section size in bytes"),
                ("sh_link", 40, FieldWidth::U32, false, "section header table index link"),
                ("sh_info", 44, FieldWidth::U32, false, "extra section information"),
                ("sh_addralign", 48, FieldWidth::U64, false, "section address alignment constraint"),
                ("sh_entsize", 56, FieldWidth::U64, false, "fixed size of entry if section holds a table"),
            ];

            for &(name, rel_off, width, is_flags, desc) in shdr_members {
                let off = base + rel_off;
                fields.push(FieldDescriptor {
                    category: FieldCategory::Shdr(i),
                    struct_name: struct_name.clone(),
                    field_name: name.to_string(),
                    file_offset: off,
                    width,
                    current_value: read_val(off, width),
                    is_flags,
                    description: desc.to_string(),
                });
            }
        }

        fields
    }

    /*
     * translate a Virtual Address (VA) into its physical file offset.
     * In ELF executable binaries, PT_LOAD segments describe memory mappings.
     * The file offset is computed as: file_offset = p_offset + (va - p_vaddr).
     * If no PT_LOAD segment matches (e.g. In relocatable object files),
     * section headers are queried as a secondary fallback.
     */
    pub fn va_to_offset(&self, va: u64) -> Option<usize> {
        /* query PT_LOAD program headers */
        for ph in &self.segments {
            if ph.is_loadable {
                let start_va = ph.p_vaddr;
                let end_va = ph.p_vaddr + ph.p_filesz;
                if va >= start_va && va < end_va {
                    let offset = ph.p_offset + (va - start_va);
                    return Some(offset as usize);
                }
            }
        }

        /* query section headers */
        for sh in &self.sections {
            if sh.sh_addr > 0 {
                let start_va = sh.sh_addr;
                let end_va = sh.sh_addr + sh.sh_size;
                if va >= start_va && va < end_va {
                    let offset = sh.sh_offset + (va - start_va);
                    return Some(offset as usize);
                }
            }
        }

        None
    }

    /*
     * translate a physical raw file offset back into its memory Virtual Address (VA).
     * Maps through PT_LOAD segments: va = p_vaddr + (file_offset - p_offset).
     */
    pub fn offset_to_va(&self, offset: usize) -> Option<u64> {
        let off = offset as u64;

        /* query PT_LOAD program headers */
        for ph in &self.segments {
            if ph.is_loadable {
                let start_off = ph.p_offset;
                let end_off = ph.p_offset + ph.p_filesz;
                if off >= start_off && off < end_off {
                    let va = ph.p_vaddr + (off - start_off);
                    return Some(va);
                }
            }
        }

        /* query section headers */
        for sh in &self.sections {
            if sh.sh_addr > 0 {
                let start_off = sh.sh_offset;
                let end_off = sh.sh_offset + sh.sh_size;
                if off >= start_off && off < end_off {
                    let va = sh.sh_addr + (off - start_off);
                    return Some(va);
                }
            }
        }

        None
    }

    /* find section metadata containing a given physical file offset */
    pub fn find_section_at_offset(&self, offset: usize) -> Option<&SectionInfo> {
        let off = offset as u64;
        self.sections.iter().find(|s| off >= s.sh_offset && off < s.sh_offset + s.sh_size)
    }

    /* find section by exact name (e.g. .text, .plt, .got.plt) */
    pub fn find_section_by_name(&self, name: &str) -> Option<&SectionInfo> {
        self.sections.iter().find(|s| s.name == name)
    }

    /* find symbol by exact name */
    pub fn find_symbol_by_name(&self, name: &str) -> Option<&SymbolInfo> {
        self.symbols.iter().find(|s| s.name == name)
    }

    /* retrieve all function symbols (STT_FUNC) */
    pub fn find_function_symbols(&self) -> Vec<&SymbolInfo> {
        self.symbols.iter().filter(|s| s.is_function && s.st_size > 0).collect()
    }

    /*
     * write integer value to binary buffer at specified file offset with target endianness.
     * Returns a tuple of (old_bytes, new_bytes) for the undo/redo stack.
     */
    pub fn write_field_value(
        &mut self,
        file_offset: usize,
        width: FieldWidth,
        new_val: u64,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        let byte_len = width_to_bytes(width);
        if file_offset + byte_len > self.bytes.len() {
            return Err(anyhow!("target field offset out of binary file bounds"));
        }

        let old_bytes = self.bytes[file_offset..file_offset + byte_len].to_vec();
        let new_bytes = match width {
            FieldWidth::U8 => vec![new_val as u8],
            FieldWidth::U16 => {
                let v = new_val as u16;
                if self.is_little_endian {
                    v.to_le_bytes().to_vec()
                } else {
                    v.to_be_bytes().to_vec()
                }
            }
            FieldWidth::U32 => {
                let v = new_val as u32;
                if self.is_little_endian {
                    v.to_le_bytes().to_vec()
                } else {
                    v.to_be_bytes().to_vec()
                }
            }
            FieldWidth::U64 => {
                if self.is_little_endian {
                    new_val.to_le_bytes().to_vec()
                } else {
                    new_val.to_be_bytes().to_vec()
                }
            }
        };

        self.bytes[file_offset..file_offset + byte_len].copy_from_slice(&new_bytes);
        Ok((old_bytes, new_bytes))
    }

    /* save current byte buffer back to disk */
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<()> {
        fs::write(path.as_ref(), &self.bytes)
            .with_context(|| format!("failed to write binary to {:?}", path.as_ref()))
    }
}

/* convert FieldWidth enum to physical byte size */
pub fn width_to_bytes(w: FieldWidth) -> usize {
    match w {
        FieldWidth::U8 => 1,
        FieldWidth::U16 => 2,
        FieldWidth::U32 => 4,
        FieldWidth::U64 => 8,
    }
}

/* format PT_* segment type into human-readable string */
pub fn format_pt_type(pt: u32) -> &'static str {
    match pt {
        PT_LOAD => "PT_LOAD",
        PT_DYNAMIC => "PT_DYNAMIC",
        PT_INTERP => "PT_INTERP",
        PT_NOTE => "PT_NOTE",
        PT_PHDR => "PT_PHDR",
        PT_TLS => "PT_TLS",
        _ => "OTHER",
    }
}

/* format ET_* object type */
pub fn format_et_type(et: u16) -> &'static str {
    match et {
        ET_NONE => "ET_NONE",
        ET_REL => "ET_REL",
        ET_EXEC => "ET_EXEC",
        ET_DYN => "ET_DYN",
        ET_CORE => "ET_CORE",
        _ => "OTHER",
    }
}

/* format EM_* machine architecture */
pub fn format_em_machine(em: u16) -> &'static str {
    match em {
        EM_X86_64 => "EM_X86_64 (AMD x86-64)",
        EM_386 => "EM_386 (Intel 80386)",
        EM_ARM => "EM_ARM (ARM)",
        _ => "OTHER",
    }
}

/* format PF_* segment permission flags into symbolic string */
pub fn format_p_flags(flags: u32) -> String {
    let mut parts = Vec::new();
    if (flags & PF_R) != 0 {
        parts.push("PF_R");
    }
    if (flags & PF_W) != 0 {
        parts.push("PF_W");
    }
    if (flags & PF_X) != 0 {
        parts.push("PF_X");
    }
    if parts.is_empty() {
        "0".to_string()
    } else {
        parts.join(" | ")
    }
}

/* format SHF_* section attributes into symbolic string */
pub fn format_sh_flags(flags: u64) -> String {
    let mut parts = Vec::new();
    if (flags & (SHF_WRITE as u64)) != 0 {
        parts.push("SHF_WRITE");
    }
    if (flags & (SHF_ALLOC as u64)) != 0 {
        parts.push("SHF_ALLOC");
    }
    if (flags & (SHF_EXECINSTR as u64)) != 0 {
        parts.push("SHF_EXECINSTR");
    }
    if (flags & (SHF_MERGE as u64)) != 0 {
        parts.push("SHF_MERGE");
    }
    if (flags & (SHF_STRINGS as u64)) != 0 {
        parts.push("SHF_STRINGS");
    }
    if (flags & (SHF_INFO_LINK as u64)) != 0 {
        parts.push("SHF_INFO_LINK");
    }
    if parts.is_empty() {
        "0".to_string()
    } else {
        parts.join(" | ")
    }
}

/*
 * parse user input string into u64 value.
 * Supports:
 * 1. Hexadecimal numbers (e.g. 0x401000)
 * 2. Decimal numbers (e.g. 4096)
 * 3. Symbolic bitflag expressions:
 *    - Segment flags: PF_R, PF_W, PF_X, rwx, rw-, r-x, etc.
 *    - Section flags: SHF_WRITE, SHF_ALLOC, SHF_EXECINSTR, etc.
 */
pub fn parse_field_input(input: &str, is_flags: bool, field_name: &str) -> Result<u64> {
    let trimmed = input.trim();

    /* check symbolic bitflag expressions if flags field */
    if is_flags {
        if field_name == "p_flags" {
            /* support shorthand rwx syntax */
            let lower = trimmed.to_ascii_lowercase();
            if lower.contains('r') || lower.contains('w') || lower.contains('x') {
                let mut val = 0u32;
                if lower.contains('r') {
                    val |= PF_R;
                }
                if lower.contains('w') {
                    val |= PF_W;
                }
                if lower.contains('x') {
                    val |= PF_X;
                }
                return Ok(val as u64);
            }

            /* support standard pipe-separated symbolic tokens */
            let mut val = 0u32;
            for token in trimmed.split('|').map(|s| s.trim()) {
                match token {
                    "PF_R" => val |= PF_R,
                    "PF_W" => val |= PF_W,
                    "PF_X" => val |= PF_X,
                    "0" | "" => {}
                    _ => {
                        /* parse as integer if token is numeric */
                        if let Ok(num) = parse_integer_token(token) {
                            val |= num as u32;
                        } else {
                            return Err(anyhow!("unknown segment flag: {}", token));
                        }
                    }
                }
            }
            return Ok(val as u64);
        } else if field_name == "sh_flags" {
            /* support shorthand wa / wax / ax syntax */
            let lower = trimmed.to_ascii_lowercase();
            if lower == "wax" || lower == "wxa" || lower == "awx" {
                return Ok((SHF_WRITE | SHF_ALLOC | SHF_EXECINSTR) as u64);
            } else if lower == "wa" || lower == "aw" {
                return Ok((SHF_WRITE | SHF_ALLOC) as u64);
            } else if lower == "ax" || lower == "xa" {
                return Ok((SHF_ALLOC | SHF_EXECINSTR) as u64);
            } else if lower == "a" {
                return Ok(SHF_ALLOC as u64);
            } else if lower == "w" {
                return Ok(SHF_WRITE as u64);
            } else if lower == "x" {
                return Ok(SHF_EXECINSTR as u64);
            }

            let mut val = 0u64;
            for token in trimmed.split('|').map(|s| s.trim()) {
                match token {
                    "SHF_WRITE" => val |= SHF_WRITE as u64,
                    "SHF_ALLOC" => val |= SHF_ALLOC as u64,
                    "SHF_EXECINSTR" => val |= SHF_EXECINSTR as u64,
                    "SHF_MERGE" => val |= SHF_MERGE as u64,
                    "SHF_STRINGS" => val |= SHF_STRINGS as u64,
                    "SHF_INFO_LINK" => val |= SHF_INFO_LINK as u64,
                    "0" | "" => {}
                    _ => {
                        if let Ok(num) = parse_integer_token(token) {
                            val |= num;
                        } else {
                            return Err(anyhow!("unknown section flag: {}", token));
                        }
                    }
                }
            }
            return Ok(val);
        }
    }

    /* fallback to integer parser */
    parse_integer_token(trimmed)
}

/* parse a single numeric integer token in hex or decimal */
fn parse_integer_token(token: &str) -> Result<u64> {
    let t = token.trim();
    if t.starts_with("0x") || t.starts_with("0X") {
        u64::from_str_radix(&t[2..], 16)
            .map_err(|e| anyhow!("invalid hexadecimal number '{}': {}", t, e))
    } else {
        t.parse::<u64>()
            .map_err(|e| anyhow!("invalid decimal number '{}': {}", t, e))
    }
}
