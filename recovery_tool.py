import sys
import os
import ctypes
import struct
import platform
from datetime import datetime
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QComboBox, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QProgressBar, QLabel, 
                             QMessageBox, QFileDialog, QAbstractItemView)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# -----------------------------------------------------------------------------
# CONSTANTS & SIGNATURES
# -----------------------------------------------------------------------------
# Common file signatures (Magic Numbers)
FILE_SIGNATURES = {
    'jpg':  (b'\xFF\xD8\xFF', b'\xFF\xD9'),
    'png':  (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', b'\x49\x45\x4E\x44\xAE\x42\x60\x82'),
    'pdf':  (b'\x25\x50\x44\x46', b'\x25\x25\x45\x4F\x46'), # %PDF- ... %%EOF
    'zip':  (b'\x50\x4B\x03\x04', None), # PK.. (Also covers DOCX, XLSX, JAR)
    'mp4':  (b'\x00\x00\x00\x18\x66\x74\x79\x70', None) # ftyp atom
}

# Block size for reading (optimized for performance)
CHUNK_SIZE = 1024 * 1024  # 1 MB
SECTOR_SIZE = 512

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------
def is_admin():
    """Check if the script is running with Admin privileges."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_drives():
    """
    Detect removable drives on Windows.
    Returns a list of tuples: (Letter, Path)
    """
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if bitmask & 1:
            drive_path = f"{letter}:\\"
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
            # DRIVE_REMOVABLE = 2, DRIVE_FIXED = 3. 
            # We allow both for testing, but in prod you might limit to removable.
            if drive_type == 2 or drive_type == 3: 
                drives.append((letter, f"\\\\.\\{letter}:"))
        bitmask >>= 1
    return drives

# -----------------------------------------------------------------------------
# RECOVERY ENGINE (WORKER THREAD)
# -----------------------------------------------------------------------------
class RecoveryWorker(QThread):
    progress_update = pyqtSignal(int)
    status_update = pyqtSignal(str)
    file_found = pyqtSignal(dict)
    finished_scan = pyqtSignal()
    error_occurred = pyqtSignal(str)

    def __init__(self, drive_path, save_dir):
        super().__init__()
        self.drive_path = drive_path
        self.save_dir = save_dir
        self.is_running = True

    def run(self):
        try:
            self.status_update.emit(f"Opening drive {self.drive_path} in READ-ONLY mode...")
            
            # Open device in binary read mode
            # On Windows, this requires Admin rights
            try:
                disk = open(self.drive_path, 'rb')
            except PermissionError:
                self.error_occurred.emit("Permission Denied. Please run as Administrator.")
                return
            except FileNotFoundError:
                self.error_occurred.emit("Drive not found or inaccessible.")
                return

            # Determine drive size (seek to end)
            disk.seek(0, os.SEEK_END)
            disk_size = disk.tell()
            disk.seek(0)
            
            self.status_update.emit(f"Drive Size: {disk_size / (1024*1024*1024):.2f} GB. Starting Deep Scan...")

            offset = 0
            files_found_count = 0
            
            # Dictionary to track open file handles during carving
            # Structure: { 'ext': {'start': offset, 'data': bytearray, 'max_size': int} }
            # Since this is a simple carver, we will process sequentially for simplicity.
            
            # Simple Carving Logic:
            # 1. Read chunks
            # 2. Search for signatures in the chunk
            # 3. If header found, start capturing bytes
            
            while offset < disk_size and self.is_running:
                # Update Progress
                if offset % (10 * CHUNK_SIZE) == 0:
                    percent = int((offset / disk_size) * 100)
                    self.progress_update.emit(percent)

                try:
                    data = disk.read(CHUNK_SIZE)
                    if not data:
                        break
                except OSError:
                    # Sector read error, skip block
                    offset += CHUNK_SIZE
                    disk.seek(offset)
                    continue

                # Scan the chunk for signatures
                for ext, (header, footer) in FILE_SIGNATURES.items():
                    pos = data.find(header)
                    
                    if pos != -1:
                        # Found a potential file start
                        global_pos = offset + pos
                        self.status_update.emit(f"Found {ext.upper()} header at offset {global_pos}")
                        
                        # Attempt to recover (Carve)
                        recovered_data = self.carve_file(disk, global_pos, header, footer)
                        
                        if recovered_data:
                            filename = f"recovered_{global_pos}.{ext}"
                            filepath = os.path.join(self.save_dir, filename)
                            
                            with open(filepath, 'wb') as f:
                                f.write(recovered_data)
                            
                            files_found_count += 1
                            self.file_found.emit({
                                'name': filename,
                                'size': f"{len(recovered_data)/1024:.2f} KB",
                                'type': ext.upper(),
                                'status': 'Recovered'
                            })

                offset += CHUNK_SIZE

            disk.close()
            self.progress_update.emit(100)
            self.status_update.emit(f"Scan Complete. {files_found_count} files recovered.")
            self.finished_scan.emit()

        except Exception as e:
            self.error_occurred.emit(str(e))

    def carve_file(self, disk_handle, start_pos, header, footer, max_size=10*1024*1024):
        """
        Reads from disk starting at header until footer is found or max_size reached.
        """
        current_pos = disk_handle.tell() # Save current scan position
        
        disk_handle.seek(start_pos)
        buffer = bytearray()
        
        # Read initial chunk
        chunk = disk_handle.read(min(4096, max_size))
        buffer.extend(chunk)
        
        # If we have a footer, keep reading until we find it
        if footer:
            search_window = 0
            while len(buffer) < max_size:
                # check for footer in the recently added bytes
                # We search from end of buffer back to search_window
                footer_pos = buffer.find(footer, search_window)
                
                if footer_pos != -1:
                    # Footer found! Trim buffer to include footer
                    buffer = buffer[:footer_pos + len(footer)]
                    break
                
                search_window = max(0, len(buffer) - len(footer) - 1)
                
                new_chunk = disk_handle.read(4096)
                if not new_chunk:
                    break
                buffer.extend(new_chunk)
        else:
            # If no footer (like ZIP sometimes), verify by header struct or just grab fixed size
            # For simplicity in this demo, we read a fixed 2MB for footerless files
            extra = disk_handle.read(2 * 1024 * 1024)
            buffer.extend(extra)

        # Restore position for main loop
        disk_handle.seek(current_pos)
        
        if len(buffer) > 0:
            return buffer
        return None

    def stop(self):
        self.is_running = False

# -----------------------------------------------------------------------------
# MAIN WINDOW (GUI)
# -----------------------------------------------------------------------------
class RecoveryApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Titan Recovery - USB Forensics Tool")
        self.resize(900, 600)
        self.setStyleSheet("""
            QMainWindow { background-color: #f0f0f0; }
            QLabel { font-size: 14px; }
            QTableWidget { background-color: white; border: 1px solid #ccc; }
            QPushButton { 
                background-color: #0078D7; color: white; 
                padding: 8px; border-radius: 4px; font-weight: bold;
            }
            QPushButton:hover { background-color: #005a9e; }
            QPushButton:disabled { background-color: #cccccc; }
            QProgressBar { border: 1px solid #bbb; border-radius: 4px; text-align: center; }
            QProgressBar::chunk { background-color: #00CC6A; }
        """)

        self.worker = None
        self.save_directory = ""

        self.init_ui()

    def init_ui(self):
        main_widget = QWidget()
        layout = QVBoxLayout()
        
        # Header
        header = QLabel("Deep Scan Recovery Tool")
        header.setStyleSheet("font-size: 20px; font-weight: bold; color: #333;")
        layout.addWidget(header)

        # Drive Selection
        drive_layout = QHBoxLayout()
        self.drive_combo = QComboBox()
        self.refresh_drives()
        
        refresh_btn = QPushButton("Refresh Drives")
        refresh_btn.clicked.connect(self.refresh_drives)
        
        drive_layout.addWidget(QLabel("Select Target Drive:"))
        drive_layout.addWidget(self.drive_combo)
        drive_layout.addWidget(refresh_btn)
        layout.addLayout(drive_layout)

        # Output Selection
        dest_layout = QHBoxLayout()
        self.lbl_dest = QLabel("No output folder selected")
        btn_dest = QPushButton("Select Output Folder")
        btn_dest.clicked.connect(self.select_output_folder)
        
        dest_layout.addWidget(btn_dest)
        dest_layout.addWidget(self.lbl_dest)
        dest_layout.addStretch()
        layout.addLayout(dest_layout)

        # Controls
        self.btn_scan = QPushButton("Start Deep Scan")
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_scan.setEnabled(False)
        layout.addWidget(self.btn_scan)

        # Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        self.status_lbl = QLabel("Ready")
        layout.addWidget(self.status_lbl)

        # Results Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Filename", "Size", "Type", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        layout.addWidget(self.table)

        main_widget.setLayout(layout)
        self.setCentralWidget(main_widget)

    def refresh_drives(self):
        self.drive_combo.clear()
        drives = get_drives()
        if not drives:
            self.drive_combo.addItem("No Removable Drives Found")
            self.drive_combo.setEnabled(False)
        else:
            self.drive_combo.setEnabled(True)
            for letter, path in drives:
                self.drive_combo.addItem(f"Drive {letter} ({path})", path)

    def select_output_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Recovery Destination")
        if folder:
            self.save_directory = folder
            self.lbl_dest.setText(f"Output: {folder}")
            self.check_ready()

    def check_ready(self):
        if self.save_directory and self.drive_combo.isEnabled():
            self.btn_scan.setEnabled(True)

    def start_scan(self):
        drive_path = self.drive_combo.currentData()
        if not drive_path:
            return

        # Sanity Check: Don't save to the same drive being scanned
        if drive_path[4] == self.save_directory[0]: # Simple drive letter check (e.g. 'E' vs 'E')
            QMessageBox.warning(self, "Warning", "Don't save recovered files to the same drive you are scanning! Data overwriting will occur.")
            return

        self.table.setRowCount(0)
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("Scanning...")
        
        # Initialize Worker
        self.worker = RecoveryWorker(drive_path, self.save_directory)
        self.worker.progress_update.connect(self.progress_bar.setValue)
        self.worker.status_update.connect(self.status_lbl.setText)
        self.worker.file_found.connect(self.add_table_row)
        self.worker.finished_scan.connect(self.scan_finished)
        self.worker.error_occurred.connect(self.scan_error)
        
        self.worker.start()

    def add_table_row(self, file_data):
        row = self.table.rowCount()
        self.table.insertRow(row)
        self.table.setItem(row, 0, QTableWidgetItem(file_data['name']))
        self.table.setItem(row, 1, QTableWidgetItem(file_data['size']))
        self.table.setItem(row, 2, QTableWidgetItem(file_data['type']))
        self.table.setItem(row, 3, QTableWidgetItem(file_data['status']))

    def scan_finished(self):
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("Start Deep Scan")
        QMessageBox.information(self, "Success", "Scan completed successfully.")

    def scan_error(self, msg):
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("Start Deep Scan")
        QMessageBox.critical(self, "Error", msg)

# -----------------------------------------------------------------------------
# ENTRY POINT
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    if not is_admin():
        # Re-run the program with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        app = QApplication(sys.argv)
        window = RecoveryApp()
        window.show()
        sys.exit(app.exec())
