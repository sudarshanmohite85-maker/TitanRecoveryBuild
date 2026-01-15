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
FILE_SIGNATURES = {
    'jpg':  (b'\xFF\xD8\xFF', b'\xFF\xD9'),
    'png':  (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', b'\x49\x45\x4E\x44\xAE\x42\x60\x82'),
    'pdf':  (b'\x25\x50\x44\x46', b'\x25\x25\x45\x4F\x46'), 
    'zip':  (b'\x50\x4B\x03\x04', None), # Covers ZIP, DOCX, XLSX
    'mp4':  (b'\x66\x74\x79\x70', None),
    'avi':  (b'\x52\x49\x46\x46', None),
    'mkv':  (b'\x1A\x45\xDF\xA3', None)
}

CHUNK_SIZE = 2 * 1024 * 1024  
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
# RECOVERY ENGINE
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
            self.status_update.emit(f"Opening drive {self.drive_path}...")
            
            try:
                disk = open(self.drive_path, 'rb')
            except PermissionError:
                self.error_occurred.emit("Permission Denied. Run as Administrator.")
                return
            except FileNotFoundError:
                self.error_occurred.emit("Drive not found.")
                return

            disk_size = 250 * 1024 * 1024 * 1024 
            
            self.status_update.emit(f"Scanning... (Smart Size Limits Active)")

            offset = 0
            files_found_count = 0
            
            while offset < disk_size and self.is_running:
                if offset % (20 * CHUNK_SIZE) == 0:
                    percent = int((offset / disk_size) * 100)
                    if percent > 100: percent = 99
                    self.progress_update.emit(percent)

                try:
                    data = disk.read(CHUNK_SIZE)
                    if not data: break
                except OSError:
                    offset += CHUNK_SIZE
                    continue

                for ext, (header, footer) in FILE_SIGNATURES.items():
                    pos = data.find(header)
                    
                    if pos != -1:
                        global_pos = offset + pos
                        self.status_update.emit(f"Found {ext.upper()} at {global_pos}")
                        
                        # --- SMART LIMITS ---
                        # Default large limit for Videos
                        limit = 1024 * 1024 * 1024 # 1 GB
                        
                        # Strict limit for ZIP/Office/Images to prevent "Junk Bloat"
                        if ext in ['zip', 'jpg', 'png', 'pdf']:
                            limit = 50 * 1024 * 1024 # Max 50 MB for non-video files

                        recovered_data = self.safe_carve(disk, global_pos, header, footer, limit)
                        
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
            self.status_update.emit(f"Scan Complete. {files_found_count} files.")
            self.finished_scan.emit()

        except Exception as e:
            self.error_occurred.emit(str(e))

    def safe_carve(self, disk_handle, start_pos, header, footer, max_size):
        saved_scan_pos = disk_handle.tell()
        aligned_start = (start_pos // SECTOR_SIZE) * SECTOR_SIZE
        diff = start_pos - aligned_start 
        
        try:
            disk_handle.seek(aligned_start)
            buffer = bytearray()
            
            # Read first chunk
            chunk = disk_handle.read(min(1024*1024, max_size + diff)) 
            buffer.extend(chunk)
            
            # Carving Loop
            if footer:
                while len(buffer) < max_size:
                    footer_pos = buffer.find(footer)
                    if footer_pos != -1:
                        buffer = buffer[:footer_pos + len(footer)]
                        break
                    new_chunk = disk_handle.read(1024*1024)
                    if not new_chunk: break
                    buffer.extend(new_chunk)
            else:
                # Blind carve until max_limit
                remaining = max_size - len(buffer)
                if remaining > 0:
                   extra = disk_handle.read(remaining)
                   buffer.extend(extra)

            disk_handle.seek(saved_scan_pos)

            valid_data = buffer[diff:]
            return valid_data if len(valid_data) > 0 else None

        except:
            try: disk_handle.seek(saved_scan_pos)
            except: pass
            return None

    def stop(self):
        self.is_running = False

# -----------------------------------------------------------------------------
# GUI CLASS
# -----------------------------------------------------------------------------
class RecoveryApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Titan Recovery - Smart Video Edition")
        self.resize(900, 600)
        self.setStyleSheet("""
            QMainWindow { background-color: #f0f0f0; }
            QLabel { font-size: 14px; }
            QTableWidget { background-color: white; }
            QPushButton { background-color: #0078D7; color: white; padding: 8px; }
        """)
        self.worker = None
        self.save_directory = ""
        self.init_ui()

    def init_ui(self):
        main = QWidget()
        layout = QVBoxLayout()
        
        layout.addWidget(QLabel("Titan Smart Recovery"))
        
        # Drives
        d_layout = QHBoxLayout()
        self.d_combo = QComboBox()
        self.refresh_drives()
        btn_r = QPushButton("Refresh")
        btn_r.clicked.connect(self.refresh_drives)
        d_layout.addWidget(self.d_combo)
        d_layout.addWidget(btn_r)
        layout.addLayout(d_layout)

        # Output
        o_layout = QHBoxLayout()
        self.l_out = QLabel("No output folder")
        btn_o = QPushButton("Select Output")
        btn_o.clicked.connect(self.select_output)
        o_layout.addWidget(btn_o)
        o_layout.addWidget(self.l_out)
        layout.addLayout(o_layout)

        # Scan
        self.btn_s = QPushButton("Start Scan")
        self.btn_s.clicked.connect(self.start_scan)
        self.btn_s.setEnabled(False)
        layout.addWidget(self.btn_s)

        # Progress
        self.p_bar = QProgressBar()
        layout.addWidget(self.p_bar)
        self.l_stat = QLabel("Ready")
        layout.addWidget(self.l_stat)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(4)
        self.table.setHorizontalHeaderLabels(["Name", "Size", "Type", "Status"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        layout.addWidget(self.table)

        main.setLayout(layout)
        self.setCentralWidget(main)

    def refresh_drives(self):
        self.d_combo.clear()
        drives = get_drives()
        if drives:
            self.d_combo.setEnabled(True)
            for l, p in drives: self.d_combo.addItem(f"Drive {l}", p)
        else:
            self.d_combo.setEnabled(False)

    def select_output(self):
        f = QFileDialog.getExistingDirectory(self, "Select Output")
        if f:
            self.save_directory = f
            self.l_out.setText(f)
            self.check_ready()

    def check_ready(self):
        if self.save_directory and self.d_combo.isEnabled():
            self.btn_s.setEnabled(True)

    def start_scan(self):
        path = self.d_combo.currentData()
        self.btn_s.setEnabled(False)
        self.worker = RecoveryWorker(path, self.save_directory)
        self.worker.progress_update.connect(self.p_bar.setValue)
        self.worker.status_update.connect(self.l_stat.setText)
        self.worker.file_found.connect(self.add_row)
        self.worker.finished_scan.connect(lambda: self.btn_s.setEnabled(True))
        self.worker.start()

    def add_row(self, data):
        r = self.table.rowCount()
        self.table.insertRow(r)
        self.table.setItem(r, 0, QTableWidgetItem(data['name']))
        self.table.setItem(r, 1, QTableWidgetItem(data['size']))
        self.table.setItem(r, 2, QTableWidgetItem(data['type']))
        self.table.setItem(r, 3, QTableWidgetItem(data['status']))

if __name__ == "__main__":
    if not is_admin():
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:
        app = QApplication(sys.argv)
        w = RecoveryApp()
        w.show()
        sys.exit(app.exec())
