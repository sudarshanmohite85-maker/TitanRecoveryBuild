import sys
import os
import ctypes
import struct
import platform
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QComboBox, QTableWidget, 
                             QTableWidgetItem, QHeaderView, QProgressBar, QLabel, 
                             QMessageBox, QFileDialog, QAbstractItemView)
from PyQt6.QtCore import Qt, QThread, pyqtSignal

# -----------------------------------------------------------------------------
# CONSTANTS & SIGNATURES (ZIP GONE, VIDEO OPTIMIZED)
# -----------------------------------------------------------------------------
FILE_SIGNATURES = {
    'jpg':  b'\xFF\xD8\xFF',
    'png':  b'\x89\x50\x4E\x47',
    # MP4 Signature: 'ftyp' (we will look for this specifically)
    'mp4':  b'\x66\x74\x79\x70', 
    'avi':  b'\x52\x49\x46\x46',
    'mkv':  b'\x1A\x45\xDF\xA3'
}

# The "Next Header" list - we stop carving if we see these
STOP_MARKERS = list(FILE_SIGNATURES.values())

CHUNK_SIZE = 1024 * 1024  # 1 MB read speed
SECTOR_SIZE = 512

# -----------------------------------------------------------------------------
# HELPER FUNCTIONS
# -----------------------------------------------------------------------------
def is_admin():
    try: return ctypes.windll.shell32.IsUserAnAdmin()
    except: return False

def get_drives():
    drives = []
    bitmask = ctypes.windll.kernel32.GetLogicalDrives()
    for letter in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if bitmask & 1:
            drive_path = f"{letter}:\\"
            dtype = ctypes.windll.kernel32.GetDriveTypeW(drive_path)
            if dtype == 2 or dtype == 3: 
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
            except:
                self.error_occurred.emit("Access Denied. Run as Admin.")
                return

            # 250GB Limit to bypass Windows size check errors
            disk_size = 250 * 1024 * 1024 * 1024 
            
            self.status_update.emit(f"Scanning (Looking for 'Moov' Index)...")

            offset = 0
            found_count = 0
            
            while offset < disk_size and self.is_running:
                if offset % (20 * CHUNK_SIZE) == 0:
                    percent = int((offset / disk_size) * 100)
                    if percent > 100: percent = 99
                    self.progress_update.emit(percent)

                try:
                    data = disk.read(CHUNK_SIZE)
                    if not data: break
                except:
                    offset += CHUNK_SIZE
                    continue

                # Scan for signatures
                for ext, header in FILE_SIGNATURES.items():
                    pos = data.find(header)
                    
                    if pos != -1:
                        global_pos = offset + pos
                        file_start = global_pos
                        
                        # Adjust for MP4 'ftyp' (starts 4 bytes earlier)
                        if ext == 'mp4': file_start = global_pos - 4
                        
                        self.status_update.emit(f"Found {ext.upper()} at {file_start}")
                        
                        # --- CARVE UNTIL NEXT HEADER + MOOV CHECK ---
                        recovered_data, status_msg = self.smart_carve(disk, file_start, ext)
                        
                        if recovered_data:
                            filename = f"recovered_{file_start}.{ext}"
                            filepath = os.path.join(self.save_dir, filename)
                            
                            with open(filepath, 'wb') as f:
                                f.write(recovered_data)
                            
                            found_count += 1
                            size_mb = len(recovered_data) / (1024*1024)
                            self.file_found.emit({
                                'name': filename,
                                'size': f"{size_mb:.2f} MB",
                                'type': ext.upper(),
                                'status': status_msg
                            })
                            
                            # Skip the data we just recovered
                            if len(recovered_data) > CHUNK_SIZE:
                                skip = (len(recovered_data) // SECTOR_SIZE) * SECTOR_SIZE
                                offset += skip
                                disk.seek(offset)
                                break 

                offset += CHUNK_SIZE

            disk.close()
            self.progress_update.emit(100)
            self.status_update.emit(f"Done. {found_count} files found.")
            self.finished_scan.emit()

        except Exception as e:
            self.error_occurred.emit(str(e))

    def smart_carve(self, disk, start_pos, ext):
        """
        Reads until Next Header.
        For MP4, it specifically looks for the 'moov' atom (index).
        """
        saved = disk.tell()
        aligned = (start_pos // SECTOR_SIZE) * SECTOR_SIZE
        diff = start_pos - aligned
        
        buffer = bytearray()
        status = "Recovered"
        
        try:
            disk.seek(aligned)
            
            # 2.5 GB Limit (Larger for HD Movies)
            max_limit = 2500 * 1024 * 1024 
            read_so_far = 0
            
            # Initial Read
            chunk = disk.read(min(CHUNK_SIZE, max_limit))
            buffer.extend(chunk)
            read_so_far += len(chunk)

            scan_offset = diff + 16 # Skip own header
            moov_found = False
            
            while read_so_far < max_limit:
                # 1. Check for Next Header
                window = buffer[scan_offset:]
                
                nearest_stop = -1
                for sig in STOP_MARKERS:
                    s_pos = window.find(sig)
                    if s_pos != -1:
                        if nearest_stop == -1 or s_pos < nearest_stop:
                            nearest_stop = s_pos
                
                # SPECIAL LOGIC FOR MP4: Don't stop if we haven't found 'moov' yet?
                # Actually, simpler is: Stop at next header, BUT check if 'moov' is inside what we found.
                
                if nearest_stop != -1:
                    # We found another file starting here.
                    final_size = scan_offset + nearest_stop
                    
                    # Cut the buffer
                    buffer = buffer[:final_size]
                    break

                # 2. Check for Zeros (Empty Space)
                if len(window) > 4096:
                     tail = window[-4096:]
                     if tail == b'\x00' * 4096:
                         buffer = buffer[:scan_offset + len(window) - 4096]
                         break

                # Read More
                new_chunk = disk.read(CHUNK_SIZE)
                if not new_chunk: break
                buffer.extend(new_chunk)
                read_so_far += len(new_chunk)
                
                # Move scan pointer forward
                scan_offset = len(buffer) - len(new_chunk) - 100

            # --- VALIDATION ---
            valid_data = buffer[diff:]
            
            # Check for Moov Atom in MP4
            if ext == 'mp4':
                if b'moov' in valid_data:
                    status = "Playable (Index Found)"
                else:
                    status = "Likely Corrupt (No Index)"

            disk.seek(saved)
            return (valid_data, status) if len(valid_data) > 0 else (None, "")

        except:
            try: disk.seek(saved)
            except: pass
            return (None, "")

    def stop(self):
        self.is_running = False

# -----------------------------------------------------------------------------
# GUI CLASS
# -----------------------------------------------------------------------------
class RecoveryApp(QMainWindow):
    def __init__(self):
        super().__init__()
        # CHECK THIS TITLE BAR WHEN YOU RUN IT
        self.setWindowTitle("Titan Recovery - FINAL VERSION 4.0")
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
        
        layout.addWidget(QLabel("Titan Recovery v4.0 (Moov Hunter + No ZIPs)"))
        
        d_layout = QHBoxLayout()
        self.d_combo = QComboBox()
        self.refresh_drives()
        btn_r = QPushButton("Refresh")
        btn_r.clicked.connect(self.refresh_drives)
        d_layout.addWidget(self.d_combo)
        d_layout.addWidget(btn_r)
        layout.addLayout(d_layout)

        o_layout = QHBoxLayout()
        self.l_out = QLabel("No output folder")
        btn_o = QPushButton("Select Output")
        btn_o.clicked.connect(self.select_output)
        o_layout.addWidget(btn_o)
        o_layout.addWidget(self.l_out)
        layout.addLayout(o_layout)

        self.btn_s = QPushButton("Start Scan")
        self.btn_s.clicked.connect(self.start_scan)
        self.btn_s.setEnabled(False)
        layout.addWidget(self.btn_s)

        self.p_bar = QProgressBar()
        layout.addWidget(self.p_bar)
        self.l_stat = QLabel("Ready")
        layout.addWidget(self.l_stat)

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
