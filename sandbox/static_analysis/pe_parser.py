# static_analysis/pe_parser.py
import pefile

class PEParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.pe = None

    def load_file(self):
        try:
            self.pe = pefile.PE(self.file_path)
        except FileNotFoundError:
            raise FileNotFoundError("File not found!")
        except pefile.PEFormatError:
            raise ValueError("Invalid PE file!")

    def get_metadata(self):
        if not self.pe:
            raise ValueError("PE file not loaded!")
        metadata = {
            "Entry Point": hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "Image Base": hex(self.pe.OPTIONAL_HEADER.ImageBase),
            "Number of Sections": self.pe.FILE_HEADER.NumberOfSections,
            "Timestamp": self.pe.FILE_HEADER.TimeDateStamp,
        }
        return metadata

    def get_imports(self):
        if not self.pe:
            raise ValueError("PE file not loaded!")
        imports = {}
        for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
            imports[entry.dll.decode()] = [imp.name.decode() for imp in entry.imports if imp.name]
        return imports
