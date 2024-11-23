# gui/static_analysis_gui.py
import sys
import os

# Print current sys.path for debugging
print("Current sys.path:")
for path in sys.path:
    print(path)

project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "malware-sandbox"))
print(f"Adding project root to sys.path: {project_root}")

if project_root not in sys.path:
    sys.path.append(project_root)

import sys
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QVBoxLayout, QPushButton,
    QFileDialog, QTextEdit, QWidget, QLabel
)
from sandbox.static_analysis.pe_parser import PEParser


class StaticAnalysisGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Static Analysis Tool")
        self.setGeometry(100, 100, 600, 400)
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)

        # Layout
        layout = QVBoxLayout()

        # Widgets
        self.label = QLabel("Select a PE file for analysis:")
        self.file_button = QPushButton("Open File")
        self.file_button.clicked.connect(self.open_file)

        self.analyze_button = QPushButton("Analyze File")
        self.analyze_button.clicked.connect(self.analyze_file)
        self.analyze_button.setEnabled(False)

        self.result_area = QTextEdit()
        self.result_area.setReadOnly(True)

        # Add widgets to layout
        layout.addWidget(self.label)
        layout.addWidget(self.file_button)
        layout.addWidget(self.analyze_button)
        layout.addWidget(self.result_area)

        self.central_widget.setLayout(layout)

        # State
        self.file_path = None

    def open_file(self):
        file_dialog = QFileDialog(self)
        self.file_path, _ = file_dialog.getOpenFileName(self, "Select PE File", "", "Executable Files (*.exe)")
        if self.file_path:
            self.label.setText(f"Selected File: {self.file_path}")
            self.analyze_button.setEnabled(True)

    def analyze_file(self):
        if not self.file_path:
            self.result_area.setText("No file selected!")
            return

        try:
            parser = PEParser(self.file_path)
            parser.load_file()
            metadata = parser.get_metadata()
            imports = parser.get_imports()

            # Display results
            result = "Metadata:\n"
            for key, value in metadata.items():
                result += f"{key}: {value}\n"

            result += "\nImports:\n"
            for dll, functions in imports.items():
                result += f"{dll}:\n"
                for func in functions:
                    result += f"  - {func}\n"

            self.result_area.setText(result)
        except Exception as e:
            self.result_area.setText(f"Error: {e}")


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = StaticAnalysisGUI()
    window.show()
    sys.exit(app.exec())
