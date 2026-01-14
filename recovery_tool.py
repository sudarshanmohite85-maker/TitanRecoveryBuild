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
# CONSTANTS & SIGNATURES (UPDATED FOR VIDEO)
# -----------------------------------------------------------------------------
FILE_SIGNATURES = {
    'jpg':  (b'\xFF\xD8\xFF', b'\xFF\xD9'),
    'png':  (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', b'\x49\x45\x4E\x44\xAE\x42\x60\x82'),
    'pdf':  (b'\x25\x50\x44\x46', b'\x25\x25\x45\x4F\x46'), 
    'zip':  (b'\x50\x4B\x03\x04', None),
    
    # VIDEO FORMATS
    'mp4':  (b'\x66\x74\x79\x70', None), # Generic 'ftyp' signature (works for MOV too)
    'avi':  (b'\x52\x49\x46\x46', None), # 'RIFF'
    'mkv':  (b'\x1A\x45\xDF\xA3', None)  # Matroska
}

# INCREASED CHUNK SIZE FOR SPEED
CHUNK_SIZE = 2 * 1024 * 1024  # 2 MB read speed
SECTOR_SIZE = 512

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------
def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def get_drives():
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if bitmask & 1:
            drive_path = f"{letter}:\\"
            drive_type = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
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
            
            try:
                disk = open(self.drive_path, 'rb')
            except PermissionError:
                self.error_occurred.emit("Permission Denied. Please run as Administrator.")
                return
            except FileNotFoundError:
                self.error_occurred.emit("Drive not found or inaccessible.")
                return

            # Manual Drive Size (250GB Limit)
            disk_size = 250 * 1024 * 1024 * 1024 
            
            self.status_update.emit(f"Scanning... (Looking for Videos & Images)")

            offset = 0
            files_found_count = 0
            
            while offset < disk_size and self.is_running:
                if offset % (20 * CHUNK_SIZE) == 0:
                    percent = int((offset / disk_size) * 100)
                    if percent > 100: percent = 99
                    self.progress_update.emit(percent)

                try:
                    data = disk.read(CHUNK_SIZE)
                    if not data:
                        break
                except OSError:
                    offset += CHUNK_SIZE
                    continue

                for ext, (header, footer) in FILE_SIGNATURES.items():
                    pos = data.find(header)
                    
                    if pos != -1:
                        global_pos = offset + pos
                        self.status_update.emit(f"Found {ext.upper()} header at offset {global_pos}")
                        
                        # LOGIC: If it's a video, allow 1GB size. If image, allow 20MB.
                        current_limit = 1024 * 1024 * 1024 # 1 GB for videos
                        if ext in ['jpg', 'png', 'pdf']:
                            current_limit = 20 * 1024 * 1024 # 20 MB for images

                        recovered_data = self.safe_carve(disk, global_pos, header, footer, current_limit)
                        
                        if recovered_data:
                            filename = f"recovered_{global_pos}.{ext}"
                            filepath = os.path.join(self.save_dir, filename)
                            
                            with open(filepath, 'wb') as f:
                                f.write(recovered_data)
                            
                            files_found_count += 1
                            self.file_found.emit({
                                'name': filename,
                                'size': f"{len(recovered_data)/(1024*1024):.2f} MB",
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

    def safe_carve(self, disk_handle, start_pos, header, footer, max_size):
        saved_scan_pos = disk_handle.tell()
        
        # Windows Alignment Logic
        aligned_start = (start_pos // SECTOR_SIZE) * SECTOR_SIZE
        diff = start_pos - aligned_start 
        
        try:
            disk_handle.seek(aligned_start)
            
            buffer = bytearray()
            # Read first chunk
            chunk = disk_handle.read(min(1024*1024, max_size + diff)) 
            buffer.extend(chunk)
            
            # If footer exists, look for it. If not, read until max_size (Blind Carving)
            if footer:
                while len(buffer) < max_size:
                    footer_pos = buffer.find(footer)
                    if footer_pos != -1:
                        buffer = buffer[:footer_pos + len(footer)]
                        break
                    
                    new_chunk = disk_handle.read(1024*1024) # Read 1MB at a time
                    if not new_chunk: break
                    buffer.extend(new_chunk)
            else:
                # For MP4/AVI without explicit footer, just read the max limit
                # This is "Blind Carving" - simplistic but effective for raw recovery
                remaining = max_size - len(buffer)
                if remaining > 0:
                   extra = disk_handle.read(remaining)
                   buffer.extend(extra)

            disk_handle.seek(saved_scan_pos)

            valid_data = buffer[diff:]
            if len(valid_data) > 0:
                return valid_data
            return None

        except OSError:
            try:
                disk_handle.seek(saved_scan_pos)
            except:
                pass
            return None

    def stop(self):
        self.is_running = False

# -----------------------------------------------------------------------------
# GUI CLASS (Standard)
# -----------------------------------------------------------------------------
class RecoveryApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Titan Recovery - USB Forensics Tool (Video Edition)")
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
            QProgressBar { border: 1px solid #bbb; border-radius: 4px; text-align: center; }
            QProgressBar::chunk { background-color: #00CC6A; }
        """)

        self.worker = None
        self.save_directory = ""
        self.init_ui()

    def init_ui(self):
        main_widget = QWidget()
        layout = QVBoxLayout()
        
        header = QLabel("Titan Deep Scan (Video Support Enabled)")
        header.setStyleSheet("font-size: 20px; font-weight: bold; color: #333;")
        layout.addWidget(header)

        drive_layout = QHBoxLayout()
        self.drive_combo = QComboBox()
        self.refresh_drives()
        
        refresh_btn = QPushButton("Refresh Drives")
        refresh_btn.clicked.connect(self.refresh_drives)
        
        drive_layout.addWidget(QLabel("Select Target Drive:"))
        drive_layout.addWidget(self.drive_combo)
        drive_layout.addWidget(refresh_btn)
        layout.addLayout(drive_layout)

        dest_layout = QHBoxLayout()
        self.lbl_dest = QLabel("No output folder selected")
        btn_dest = QPushButton("Select Output Folder")
        btn_dest.clicked.connect(self.select_output_folder)
        
        dest_layout.addWidget(btn_dest)
        dest_layout.addWidget(self.lbl_dest)
        dest_layout.addStretch()
        layout.addLayout(dest_layout)

        self.btn_scan = QPushButton("Start Deep Scan")
        self.btn_scan.clicked.connect(self.start_scan)
        self.btn_scan.setEnabled(False)
        layout.addWidget(self.btn_scan)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        layout.addWidget(self.progress_bar)
        
        self.status_lbl = QLabel("Ready")
        layout.addWidget(self.status_lbl)

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
        if not drive_path: return
        if drive_path[4] == self.save_directory[0]:
            QMessageBox.warning(self, "Warning", "Don't save to the same drive!")
            return

        self.table.setRowCount(0)
        self.btn_scan.setEnabled(False)
        self.btn_scan.setText("Scanning...")
        
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
        QMessageBox.information(self, "Success", "Scan completed.")

    def scan_error(self, msg):
        self.btn_scan.setEnabled(True)
        self.btn_scan.setText("Start Deep Scan")
        QMessageBox.critical(self, "Error", msg)

if __name__ == "__main__":
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        app = QApplication(sys.argv)
        window = RecoveryApp()
        window.show()
        sys.exit(app.exec())
