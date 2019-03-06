import os
import sys
import time
import math
import json
from io import BytesIO
from tempfile import mkdtemp

from nescient.packer import NescientPacker, PackingError
from nescient.timing import estimate_time, update_time
from nescient.archive import NescientArchive, SingleFileArchive
from nescient.qt_base import Ui_MainWindow

from PyQt5 import QtCore, QtGui, QtWidgets
from PIL import Image

IMAGE_FORMATS = ('.png', '.jpg', '.bmp', '.gif')
app = None


class ProgressThread(QtCore.QThread):
    signal = QtCore.pyqtSignal('float')

    def __init__(self, interval, tick, n):
        QtCore.QThread.__init__(self)
        self.interval, self.tick, self.n = interval, tick, n

    def run(self):
        self.running = True
        count = 0
        while self.running and count < self.n:
            self.signal.emit(self.tick)
            count += 1
            time.sleep(self.interval)


class PackingThread(QtCore.QThread):
    signal = QtCore.pyqtSignal('PyQt_PyObject')

    def __init__(self, archive, out_path):
        QtCore.QThread.__init__(self)
        self.archive, self.out_path = archive, out_path

    def run(self):
        try:
            with open(self.out_path, 'wb') as f:
                self.archive.unpack(f)
        except Exception as e:
            self.signal.emit(e)
        else:
            self.signal.emit(None)


class FileList:
    def __init__(self):
        self.inner = self
        self.files = []

    def open(self, *args, **kwargs):
        return open(*args, **kwargs)


class GuiWindow(Ui_MainWindow, QtWidgets.QMainWindow):
    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.nessieLock = QtGui.QPixmap(":/resources/nessie_lock.gif")
        self.folderIcon = QtGui.QIcon.fromTheme("folder")
        self.docIcon = QtGui.QIcon.fromTheme('text-x-generic')
        self.imageIcon = QtGui.QIcon.fromTheme('image-x-generic')
        self.temp_dir = None
        self.archive = None
        self.progress_thread = None
        self.packing_thread = None
        self.progress_value = 0
        self.start = None
        self.working = False

    def setupUi(self, MainWindow):
        Ui_MainWindow.setupUi(self, MainWindow)
        self.progressBar.hide()
        self.actionNew.triggered.connect(self.new_archive)
        self.actionOpen.triggered.connect(self.open_archive)
        self.treeWidget.itemSelectionChanged.connect(self.select_files)
        self.treeWidget.doubleClicked.connect(self.export_selected)
        self.exportButton.clicked.connect(self.export_selected)
        self.packButton.clicked.connect(self.pack_unpack_archive)

    def reset(self):
        self.archive = None
        self.treeWidget.clear()
        self.statusbar.clearMessage()
        self.packButton.setText('Pack')
        self.exportButton.setEnabled(False)
        self.fileName.setText('N/A')
        self.fileType.setText('N/A')
        self.fileSize.setText('0 MiB')
        self.packingMode.setText('N/A')
        self.filePreview.setPixmap(self.nessieLock)
        self.filePreviewName.setText('')

    def new_archive(self):
        self.archive = FileList()
        self.treeWidget.clear()
        self.statusbar.clearMessage()
        self.addButton.setEnabled(True)
        self.removeButton.setEnabled(True)
        self.exportButton.setEnabled(False)
        self.packButton.setText('Pack')
        self.packButton.setEnabled(True)

    def open_archive(self, filename=None):
        if not filename:
            options = QtWidgets.QFileDialog.Options()
            options |= QtWidgets.QFileDialog.DontUseNativeDialog
            filename, ok = QtWidgets.QFileDialog.getOpenFileName(None, 'Select Archive', '',
                                                                 'Nescient archives (*.nesc)', options=options)
            if not ok:
                return
            self.centralwidget.setEnabled(False)
            try:
                _ = NescientPacker.parse_nescient_header(filename)
                password, ok = QtWidgets.QInputDialog.getText(None, 'Decrypt archive', 'Enter password:',
                                                              echo=QtWidgets.QLineEdit.Password)
                if not ok:
                    return
                self.working = True
                self.statusbar.showMessage('Validating archive...')
                self.archive = NescientArchive(filename, password)
                self.statusbar.showMessage('Opened archive {}'.format(filename))
                self.show_archive()
            except Exception as e:
                QtWidgets.QMessageBox.warning(None, 'Error', str(e))
                self.reset()
            else:
                self.addButton.setEnabled(False)
                self.removeButton.setEnabled(False)
                self.exportButton.setEnabled(True)
                self.packButton.setEnabled(True)
                self.packButton.setText('Unpack')
            finally:
                self.working = False
                self.centralwidget.setEnabled(True)

    def show_archive(self):
        self.treeWidget.clear()
        self.fileName.setText(self.archive.name)
        self.fileSize.setText('{:.1f} MiB'.format(self.archive.file_size/2**20))
        self.packingMode.setText(self.archive.alg)
        inner = self.archive.inner
        if isinstance(inner, SingleFileArchive):
            self.fileType.setText('Nescient Container')
            node = QtWidgets.QTreeWidgetItem(self.treeWidget)
            node.filename = inner.filename
            node.setText(0, inner.filename)
            node.setIcon(0, self.docIcon)
            return
        self.fileType.setText('Zipped Archive')
        tree = {}
        for zipinfo in inner.infolist():
            parts = os.path.split(zipinfo.filename)
            for i in range(1, len(parts)+1 if parts[-1] else len(parts)):
                sub_parts = parts[:i]
                path = tuple(sub_parts)
                if path not in tree:
                    if len(sub_parts) == 1:
                        parent = self.treeWidget
                    else:
                        parent = tree[tuple(sub_parts[:-1])]
                    node = QtWidgets.QTreeWidgetItem(parent)
                    node.setText(0, sub_parts[-1])
                    if i == len(parts):  # Node is a file
                        node.filename = zipinfo.filename
                        if os.path.splitext(zipinfo.filename)[1].lower() in IMAGE_FORMATS:
                            node.setIcon(0, self.imageIcon)
                        else:
                            node.setIcon(0, self.docIcon)
                    else:
                        node.filename = None
                        node.setIcon(0, self.folderIcon)
                    tree[tuple(path)] = node

    def select_files(self, *args):
        items = self.treeWidget.selectedItems()
        if not items:
            self.filePreview.setPixmap(self.nessieLock)
            self.filePreviewName.setText('')
            return
        filename = items[-1].filename
        if filename is None:  # A folder was selected
            self.exportButton.setEnabled(False)
            self.filePreview.setPixmap(self.nessieLock)
            self.filePreviewName.setText('')
            return
        self.exportButton.setEnabled(True)
        self.filePreviewName.setText(filename)
        if os.path.splitext(filename)[1].lower() not in IMAGE_FORMATS:
            self.filePreview.setPixmap(self.nessieLock)
            return
        # Preview image
        with self.archive.inner.open(filename) as f:
            im = Image.open(f)
            im.thumbnail((256, 256))
            buffer = BytesIO()
            im = im.convert('RGB')
            im.save(buffer, format='JPEG', quality=95)
            qimg = QtGui.QImage.fromData(buffer.getbuffer())
            self.filePreview.setPixmap(QtGui.QPixmap.fromImage(qimg))
            buffer.close()

    def export_files(self, files):
        for filename in files:
            if self.temp_dir is None:
                self.temp_dir = mkdtemp()
            with self.archive.inner.open(filename) as f:
                with open(os.path.join(self.temp_dir, os.path.basename(filename)), 'wb') as f_out:
                    f_out.write(f.read())
        if len(files) == 1:
            self.statusbar.showMessage('{} exported to {}'.format(files[0], self.temp_dir))
        else:
            self.statusbar.showMessage('{} files exported to {}'.format(len(files), self.temp_dir))
        app.clipboard().setText(self.temp_dir)

    def export_selected(self, event):
        files = [item.filename for item in self.treeWidget.selectedItems() if item.filename is not None]
        if files:
            self.export_files(files)

    def pack_unpack_archive(self):  # Packs or unpacks the current archive
        if self.archive is None:
            return
        path = os.path.join(os.getcwd(), 'test.zip')
        self.statusbar.showMessage('Unpacking archive...')
        self.mainArea.setEnabled(False)
        self.start_progress(estimate_time(self.archive.file_size, self.archive.packing_mode))
        self.packing_thread = PackingThread(self.archive, path)
        self.packing_thread.signal.connect(self.finish_packing)
        self.working = True
        self.packing_thread.start()

    def start_progress(self, delta):  # Starts the progress bar
        interval = max(0.2, delta//100)
        n = max(1, math.ceil(delta/interval))
        tick = 100.0/n
        self.progress_value = 0
        self.progressBar.setValue(0)
        self.progress_thread = ProgressThread(interval, tick, n)
        self.progress_thread.signal.connect(self.update_progress)
        self.progress_thread.start()
        self.progressBar.show()
        self.start = time.time()

    def update_progress(self, tick):
        self.progress_value += tick
        self.progressBar.setValue(min(99, int(self.progress_value)))

    def stop_progress(self):
        if self.progress_thread:
            self.progress_thread.running = False
            self.progress_thread.signal.disconnect()
        if self.packing_thread:
            self.packing_thread.signal.disconnect()
        self.progressBar.hide()

    def finish_packing(self, e):
        if e is None:  # No exception occurred
            self.statusbar.showMessage('Unpacked %s' % self.archive.name)
            update_time(self.archive.file_size, self.archive.packing_mode, time.time() - self.start)
        else:
            QtWidgets.QMessageBox.warning(None, 'Error', str(e))
            self.statusbar.clearMessage()
        self.stop_progress()
        self.working = False
        self.mainArea.setEnabled(True)

    def closeEvent(self, event):
        if self.working:
            event.ignore()


def main():
    global app
    app = QtWidgets.QApplication(sys.argv)
    #MainWindow = QtWidgets.QMainWindow()
    ui = GuiWindow()
    ui.setupUi(ui)
    ui.show()
    #MainWindow.show()
    app.exec_()
    sys.exit()


if __name__ == '__main__':
    main()
