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
# Note: For MP4, we detect 'ftyp' which is usually at offset 4. 
# The actual file starts 4 bytes before this signature.
FILE_SIGNATURES = {
    'jpg':  (b'\xFF\xD8\xFF', b'\xFF\xD9'),
    'png':  (b'\x89\x50\x4E\x47\x0D\x0A\x1A\x0A', b'\x49\x45\x4E\x44\xAE\x42\x60\x82'),
    'pdf':  (b'\x25\x50\x44\x46', b'\x25\x25\x45\x4F\x46'), 
    'zip':  (b'\x50\x4B\x03\x04', None),
    'mp4':  (b'\x66\x74\x79\x70', None), # 'ftyp'
    'avi':  (b'\x52\x49\x46\x46', None), # 'RIFF'
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
# ADVANCED VIDEO PARSERS (THE FIX)
# -----------------------------------------------------------------------------
def get_mp4_size(disk, start_offset):
    """
    Parses MP4 atoms to calculate EXACT file size.
    Returns: exact size in bytes, or None if invalid.
    """
    try:
        current_pos = start_offset
        total_size = 0
        
        # Max reasonable size to prevent loops (2GB)
        max_scan = 2 * 1024 * 1024 * 1024
        
        disk.seek(start_offset)
        
        while total_size < max_scan:
            # Read Atom Size (4 bytes Big Endian) and Name (4 bytes)
            header = disk.read(8)
            if len(header) < 8: break
            
            atom_size = struct.unpack('>I', header[0:4])[0]
            atom_name = header[4:8]
            
            # Validation: Atom size must be at least 8 bytes (header itself)
            if atom_size < 8: 
                # usually 0 or 1 means 'till end of file' or '64bit size', complex cases.
                # For basic recovery, we treat as end or invalid.
                if atom_size == 0: break 
                return None 

            total_size += atom_size
            
            # Common valid atoms. If we see garbage, stop.
            valid_atoms = [b'ftyp', b'moov', b'mdat', b'free', b'skip', b'wide', b'pnot', b'udta', b'uuid']
            if atom_name not in valid_atoms and total_size == atom_size:
                # First atom matches signature but isn't valid?
                return None

            # 'moov' or 'mdat' usually marks the end of data for recovery purposes
            # but we continue summing until we hit EOF logic or weird data
            
            # Jump to next atom
            current_pos += atom_size
            disk.seek(current_pos)
            
            # If we successfully parsed a few atoms and size looks real (e.g. > 1MB), good.
            # We break if we hit read errors or end of drive.

        if total_size > 1024: # Minimal valid video size
            return total_size
            
    except Exception:
        pass
    
    return None

def get_avi_size(disk, start_offset):
    """
    Parses AVI RIFF header for size.
    """
    try:
        disk.seek(start_offset + 4) # Skip 'RIFF'
        # Read Size (4 bytes Little Endian)
        size_bytes = disk.read(4)
        if len(size_bytes) < 4: return None
        
        # RIFF size = file size - 8 bytes
        riff_size = struct.unpack('<I', size_bytes)[0]
        return riff_size + 8
    except:
        return None

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
            self.status_update.emit(f"Scanning... (Smart Video Analysis Active)")

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
                        file_start_pos = global_pos
                        
                        # --- SPECIAL HANDLING FOR MP4 ---
                        # 'ftyp' is usually at offset 4. The file starts 4 bytes earlier.
                        if ext == 'mp4':
                            file_start_pos = global_pos - 4
                        
                        self.status_update.emit(f"Analyzing {ext.upper()} at {file_start_pos}")
                        
                        # --- SMART SIZE CALCULATION ---
                        exact_size = None
                        
                        # Save position to restore later
                        saved_pos = disk.tell()
                        
                        if ext == 'mp4':
                            exact_size = get_mp4_size(disk, file_start_pos)
                        elif ext == 'avi':
                            exact_size = get_avi_size(disk, file_start_pos)
                        
                        # Restore position
                        disk.seek(saved_pos)

                        # Set Limits based on analysis
                        if exact_size:
                            limit = exact_size
                            status_msg = "Exact Size"
                        else:
                            # Fallback limits if parsing failed
                            if ext in ['mp4', 'avi']:
                                limit = 500 * 1024 * 1024 # 500 MB fallback
                            elif ext in ['zip', 'jpg', 'png', 'pdf']:
                                limit = 50 * 1024 * 1024 # 50 MB limit
                            else:
                                limit = 10 * 1024 * 1024
                            status_msg = "Est. Size"

                        # Perform Extraction
                        recovered_data = self.safe_carve(disk, file_start_pos, header, footer, limit, ext)
                        
                        if recovered_data:
                            filename = f"recovered_{file_start_pos}.{ext}"
                            filepath = os.path.join(self.save_dir, filename)
                            
                            with open(filepath, 'wb') as f:
                                f.write(recovered_data)
                            
                            files_found_count += 1
                            self.file_found.emit({
                                'name': filename,
                                'size': f"{len(recovered_data)/(1024*1024):.2f} MB",
                                'type': ext.upper(),
                                'status': status_msg
                            })

                offset += CHUNK_SIZE

            disk.close()
            self.progress_update.emit(100)
            self.status_update.emit(f"Scan Complete. {files_found_count} files.")
            self.finished_scan.emit()

        except Exception as e:
            self.error_occurred.emit(str(e))

    def safe_carve(self, disk_handle, start_pos, header, footer, max_size, ext):
        saved_scan_pos = disk_handle.tell()
        
        # Alignment Logic
        aligned_start = (start_pos // SECTOR_SIZE) * SECTOR_SIZE
        diff = start_pos - aligned_start 
        
        try:
            disk_handle.seek(aligned_start)
            buffer = bytearray()
            
            # Read first chunk
            chunk = disk_handle.read(min(2*1024*1024, max_size + diff)) 
            buffer.extend(chunk)
            
            # If we have a footer (JPG/PNG), assume max_size is a safety limit
            # If NO footer (MP4/ZIP), assume max_size is the TARGET size.
            
            if footer:
                # Look for footer
                while len(buffer) < max_size:
                    footer_pos = buffer.find(footer)
                    if footer_pos != -1:
                        buffer = buffer[:footer_pos + len(footer)]
                        break
                    new_chunk = disk_handle.read(1024*1024)
                    if not new_chunk: break
                    buffer.extend(new_chunk)
            else:
                # Blind carve until EXACT max_size is reached
                # Calculate what we still need to reach 'max_size'
                # Buffer currently has 'len(buffer)' bytes.
                # Valid data starts at 'diff'.
                # So we have (len(buffer) - diff) valid bytes.
                current_valid_len = len(buffer) - diff
                remaining = max_size - current_valid_len
                
                if remaining > 0:
                    # Read the rest in blocks
                    while remaining > 0:
                        read_amt = min(2*1024*1024, remaining)
                        extra = disk_handle.read(read_amt)
                        if not extra: break
                        buffer.extend(extra)
                        remaining -= len(extra)

            disk_handle.seek(saved_scan_pos)

            valid_data = buffer[diff:]
            # Trim strictly to max_size if it was an exact calculation
            if len(valid_data) > max_size:
                valid_data = valid_data[:max_size]
                
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
        self.setWindowTitle("Titan Recovery - Smart Video Edition 2.0")
        self.resize(1000, 600)
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
        
        layout.addWidget(QLabel("Titan Smart Recovery (Auto-Detects Video Size)"))
        
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
