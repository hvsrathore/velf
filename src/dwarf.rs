/* parse DWARF debug symbols and source line-number correlation index */

use gimli::{Dwarf, EndianSlice, RunTimeEndian, SectionId};
use object::{Object, ObjectSection};
use std::collections::BTreeMap;
use std::path::PathBuf;

/* source location mapped to an instruction Virtual Address (VA) */
#[derive(Debug, Clone)]
pub struct SourceLocation {
    pub file_path: String,
    pub line: u64,
    pub column: u64,
}

/* index mapping Virtual Addresses (VA) to source code locations */
#[derive(Debug, Clone, Default)]
pub struct DwarfIndex {
    pub va_to_loc: BTreeMap<u64, SourceLocation>,
    pub has_debug_info: bool,
}

impl DwarfIndex {
    /* lookup source file and line number corresponding to an instruction VA */
    pub fn lookup(&self, va: u64) -> Option<&SourceLocation> {
        self.va_to_loc.get(&va)
    }

    /* parse DWARF sections from binary bytes using object and gimli */
    pub fn parse_from_bytes(bytes: &[u8]) -> Self {
        let mut index = Self::default();

        let obj_file = match object::File::parse(bytes) {
            Ok(file) => file,
            Err(_) => return index,
        };

        let endian = if obj_file.is_little_endian() {
            RunTimeEndian::Little
        } else {
            RunTimeEndian::Big
        };

        /* load DWARF sections into EndianSlice readers */
        let load_section = |id: SectionId| -> Result<EndianSlice<'_, RunTimeEndian>, gimli::Error> {
            match obj_file.section_by_name(id.name()) {
                Some(section) => match section.data() {
                    Ok(data) => Ok(EndianSlice::new(data, endian)),
                    Err(_) => Ok(EndianSlice::new(&[], endian)),
                },
                None => Ok(EndianSlice::new(&[], endian)),
            }
        };

        let dwarf = match Dwarf::load(&load_section) {
            Ok(d) => d,
            Err(_) => return index,
        };

        /* iterate over compilation units to evaluate line number programs */
        let mut units = dwarf.units();
        while let Ok(Some(header)) = units.next() {
            let unit = match dwarf.unit(header) {
                Ok(u) => u,
                Err(_) => continue,
            };

            if let Some(program) = unit.line_program.clone() {
                let mut rows = program.rows();
                while let Ok(Some((header, row))) = rows.next_row() {
                    if row.end_sequence() {
                        continue;
                    }

                    let address = row.address();
                    if let Some(file_entry) = row.file(header) {
                        let mut file_path = PathBuf::new();
                        if let Some(dir) = file_entry.directory(header) {
                            if let Ok(dir_str) = dwarf.attr_string(&unit, dir) {
                                if let Ok(s) = dir_str.to_string() {
                                    file_path.push(s);
                                }
                            }
                        }

                        if let Ok(file_name) = dwarf.attr_string(&unit, file_entry.path_name()) {
                            if let Ok(s) = file_name.to_string() {
                                file_path.push(s);
                            }
                        }

                        let line_num = row.line().map(|l| l.get()).unwrap_or(0);
                        let column_num = match row.column() {
                            gimli::ColumnType::Column(c) => c.get(),
                            gimli::ColumnType::LeftEdge => 0,
                        };

                        if line_num > 0 {
                            index.va_to_loc.insert(
                                address,
                                SourceLocation {
                                    file_path: file_path.to_string_lossy().to_string(),
                                    line: line_num,
                                    column: column_num,
                                },
                            );
                        }
                    }
                }
            }
        }

        index.has_debug_info = !index.va_to_loc.is_empty();
        index
    }
}
