import math
import os
import shutil
import sys
import time
from io import BytesIO
from tempfile import mkdtemp

from PIL import Image
from PyQt5 import QtCore, QtGui, QtWidgets

from nescient.gui.about_dialog import AboutNescient
from nescient.archive import NescientArchive, SingleFileArchive
from nescient.packer import NescientPacker, DEFAULT_PACKING_MODE, PACKING_MODES
from nescient.gui.qt_base import Ui_MainWindow
from nescient.timing import estimate_time, update_time

IMAGE_FORMATS = ('.png', '.jpg', '.bmp', '.gif')
app = None


class ProgressThread(QtCore.QThread):
    signal = QtCore.pyqtSignal('float')

    def __init__(self, interval, tick, n):
        QtCore.QThread.__init__(self)
        self.interval, self.tick, self.n = interval, tick, n
        self.running = False

    def run(self):
        self.running = True
        count = 0
        while self.running and count < self.n:
            self.signal.emit(self.tick)
            count += 1
            time.sleep(self.interval)


class UnpackingThread(QtCore.QThread):
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
            self.signal.emit(self.out_path)


class PackingThread(QtCore.QThread):
    start_signal = QtCore.pyqtSignal('PyQt_PyObject')
    end_signal = QtCore.pyqtSignal('PyQt_PyObject')

    def __init__(self, file_list, packer):
        QtCore.QThread.__init__(self)
        self.file_list, self.packer = file_list, packer

    def run(self):
        for in_path in self.file_list:
            try:
                size = os.path.getsize(in_path)
                self.start_signal.emit(in_path)
                out_path = NescientPacker.fix_out_path(in_path, None, 'pack')
                self.packer.pack_or_unpack_file(in_path, out_path, 'pack')
            except Exception as e:
                self.end_signal.emit((in_path, e))
            else:
                self.end_signal.emit((in_path, size))
        self.end_signal.emit((None, True))


class FileList:
    def __init__(self, packing_mode):
        self.files = []
        self.packing_mode = packing_mode

    def open(self, *args, **kwargs):
        kwargs['mode'] = 'rb'
        return open(*args, **kwargs)

    def add(self, *files):
        self.files.extend(files)

    def remove(self, file):
        self.files.remove(file)

    def __contains__(self, item):
        return item in self.files

    def __iter__(self):
        return iter(self.files)


class FileTree:  # Handles the tree view
    def __init__(self, root, folderIcon, defaultIcon, imageIcon):
        self.root = root  # TreeWidget root
        self.tree = {}  # Maps tuple(path)->node
        self.children = {}
        self.folderIcon, self.defaultIcon, self.imageIcon = folderIcon, defaultIcon, imageIcon

    def clear(self):
        self.root.clear()
        self.tree = {}
        self.children = {}

    def add(self, paths):
        for filename in paths:
            parts = filename.split(os.sep)
            for i in range(1, len(parts) + 1 if parts[-1] else len(parts)):
                sub_parts = parts[:i]
                path = tuple(sub_parts)
                if path not in self.tree:
                    if len(sub_parts) == 1:
                        parent = self.root
                    else:
                        parent = self.tree[path[:-1]]
                    node = QtWidgets.QTreeWidgetItem(parent)
                    node.setText(0, sub_parts[-1])
                    if i == len(parts):  # Node is a file
                        node.filename = filename
                        if os.path.splitext(filename)[1].lower() in IMAGE_FORMATS:
                            node.setIcon(0, self.imageIcon)
                        else:
                            node.setIcon(0, self.defaultIcon)
                    else:
                        node.filename = None
                        node.setIcon(0, self.folderIcon)
                    self.tree[path] = node
        self.root.expandAll()

    def remove(self, paths):
        pass


class GuiWindow(Ui_MainWindow, QtWidgets.QMainWindow):
    def __init__(self):
        QtWidgets.QMainWindow.__init__(self)
        Ui_MainWindow.__init__(self)
        self.nessieLock = QtGui.QPixmap(":/resources/nessie_lock.gif")
        self.temp_dir = None
        self.packing_mode = DEFAULT_PACKING_MODE
        self.archive = FileList(self.packing_mode)
        self.progress_thread = None
        self.packing_thread = None
        self.unpacking_thread = None
        self.progress_value = 0
        self.start = None
        self.working = False

    def setupUi(self, MainWindow):
        Ui_MainWindow.setupUi(self, MainWindow)
        modeGroup = QtWidgets.QActionGroup(self)
        for mode in PACKING_MODES:
            ag = QtWidgets.QAction(mode, self, checkable=True)
            ag.packing_mode = mode
            ag.setChecked(mode == DEFAULT_PACKING_MODE)
            a = modeGroup.addAction(ag)
            self.menu_Default_Packing_Mode.addAction(a)
        modeGroup.triggered.connect(self.change_packing_mode)
        self.actionAbout = self.menubar.addAction('&About')
        self.progressBar.hide()
        self.actionNew.triggered.connect(self.reset)
        self.actionOpen.triggered.connect(self.open_archive)
        self.actionAbout.triggered.connect(self.show_about)
        self.treeWidget.itemSelectionChanged.connect(self.select_files)
        self.treeWidget.doubleClicked.connect(self.export_selected)
        folderIcon = QtGui.QIcon.fromTheme("folder")
        defaultIcon = QtGui.QIcon.fromTheme('text-x-generic')
        imageIcon = QtGui.QIcon.fromTheme('image-x-generic')
        self.file_tree = FileTree(self.treeWidget, folderIcon, defaultIcon, imageIcon)
        self.addButton.clicked.connect(self.add_files)
        self.exportButton.clicked.connect(self.export_selected)
        self.packButton.clicked.connect(self.pack_unpack_files)

    def change_packing_mode(self, action):
        self.packing_mode = action.packing_mode
        if isinstance(self.archive, FileList):
            self.archive.packing_mode = self.packing_mode

    def show_about(self):
        AboutNescient().exec()

    def reset(self):
        self.archive = FileList(self.packing_mode)
        self.file_tree.clear()
        self.statusbar.clearMessage()
        self.addButton.setEnabled(True)
        self.removeButton.setEnabled(True)
        self.exportButton.setEnabled(False)
        self.packButton.setText('Pack')
        self.packButton.setEnabled(True)
        self.exportButton.setEnabled(False)
        self.fileName.setText('N/A')
        self.fileType.setText('N/A')
        self.fileSize.setText('0 MiB')
        self.packingAlg.setText('N/A')
        self.filePreview.setPixmap(self.nessieLock)
        self.filePreviewName.setText('')

    def add_files(self):
        options = QtWidgets.QFileDialog.Options()
        options |= QtWidgets.QFileDialog.DontUseNativeDialog
        filenames, ok = QtWidgets.QFileDialog.getOpenFileNames(None, 'Add files', '', options=options)
        if not ok:
            return
        for filename in filenames:
            if filename not in self.archive:
                self.file_tree.add([filename])
                self.archive.add(filename)

    def remove_files(self):
        items = self.treeWidget.selectedItems()
        if not items:
            return

    def open_archive(self, filename=None):  # Open an existing archive
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

    def show_archive(self):  # Displays the contents of an opened archive
        self.file_tree.clear()
        self.fileName.setText(os.path.basename(self.archive.filename))
        self.fileSize.setText('{:.1f} MiB'.format(self.archive.file_size/2**20))
        self.packingAlg.setText(self.archive.alg)
        if isinstance(self.archive.inner, SingleFileArchive):
            self.file_tree.add([self.archive.inner.filename])
            self.fileType.setText('Single File')
        else:
            self.fileType.setText('Zipped Archive')
            self.file_tree.add([zinfo.filename for zinfo in self.archive.inner.infolist()])

    def select_files(self):  # Sets file preview
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
        with self.archive.open(filename) as f:
            im = Image.open(f)
            im.thumbnail((256, 256))
            buffer = BytesIO()
            im = im.convert('RGB')
            im.save(buffer, format='JPEG', quality=95)
            qimg = QtGui.QImage.fromData(buffer.getbuffer())
            self.filePreview.setPixmap(QtGui.QPixmap.fromImage(qimg))
            buffer.close()

    def export_files(self, files):  # Exports a list of files to a temporary directory
        if self.temp_dir is None:
            self.temp_dir = mkdtemp()
        for filename in files:
            with self.archive.open(filename) as f:
                with open(os.path.join(self.temp_dir, os.path.basename(filename)), 'wb') as f_out:
                    f_out.write(f.read())
        if len(files) == 1:
            self.statusbar.showMessage('Exported {} to {}'.format(files[0], self.temp_dir))
        else:
            self.statusbar.showMessage('Exported {} files to {}'.format(len(files), self.temp_dir))
        app.clipboard().setText(self.temp_dir)

    def export_selected(self, _unused):
        files = [item.filename for item in self.treeWidget.selectedItems() if item.filename is not None]
        if files:
            self.export_files(files)

    def pack_unpack_files(self):  # Packs or unpacks the archive
        if isinstance(self.archive, FileList):
            password, ok = QtWidgets.QInputDialog.getText(None, 'Encrypt files', 'Enter password:',
                                                          echo=QtWidgets.QLineEdit.Password)
            if not ok:
                return
            packer = NescientPacker(password)
            self.packing_thread = PackingThread(self.archive, packer)
            self.packing_thread.start_signal.connect(self.start_packing_file)
            self.packing_thread.end_signal.connect(self.finish_packing_file)
            self.packing_thread.start()
        else:
            out_path = NescientPacker.fix_out_path(self.archive.filename, None, 'unpack')
            self.statusbar.showMessage('Unpacking archive...')
            self.start_progress(estimate_time(self.archive.file_size, self.archive.packing_mode))
            self.unpacking_thread = UnpackingThread(self.archive, out_path)
            self.unpacking_thread.signal.connect(self.finish_unpacking)
            self.unpacking_thread.start()
        self.working = True
        self.mainArea.setEnabled(False)

    def start_progress(self, duration):  # Starts the progress bar
        interval = max(0.2, duration//100)
        n = max(1, math.ceil(duration/interval))
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

    def stop_progress(self, hide=True):
        if self.progress_thread:
            self.progress_thread.running = False
            self.progress_thread.signal.disconnect()
            self.progress_thread = None
        if self.unpacking_thread:
            self.unpacking_thread.signal.disconnect()
            self.unpacking_thread = None
        if hide:
            self.progressBar.hide()

    def finish_unpacking(self, e):
        if isinstance(e, Exception):
            QtWidgets.QMessageBox.warning(None, 'Error', str(e))
            self.statusbar.clearMessage()
        else:
            self.statusbar.showMessage('Unpacked archive to {}'.format(e))
            update_time(self.archive.file_size, self.archive.packing_mode, time.time() - self.start)
        self.stop_progress()
        self.working = False
        self.mainArea.setEnabled(True)

    def start_packing_file(self, file):
        try:
            size = os.path.getsize(file)
            self.start_progress(estimate_time(size, self.archive.packing_mode))
            self.statusbar.showMessage('Packing {}...'.format(file))
        except Exception:
            pass

    def finish_packing_file(self, tup):
        file, ex = tup
        if isinstance(ex, Exception):
            QtWidgets.QMessageBox.warning(None, 'Error', str(ex))
        elif ex is True:
            self.progressBar.hide()
            self.working = False
            self.mainArea.setEnabled(True)
            self.statusbar.showMessage('Packed {} file(s).'.format(len(self.archive.files)))
        else:  # Ex is file size
            update_time(ex, self.archive.packing_mode, time.time()-self.start)
            self.stop_progress(hide=False)

    def closeEvent(self, event):
        if self.working:
            event.ignore()
        else:
            if self.temp_dir:
                try:
                    shutil.rmtree(self.temp_dir)
                except Exception:
                    pass


def main():
    global app
    app = QtWidgets.QApplication(sys.argv)
    # MainWindow = QtWidgets.QMainWindow()
    ui = GuiWindow()
    ui.setupUi(ui)
    ui.show()
    # MainWindow.show()
    sys.exit(app.exec())


if __name__ == '__main__':
    main()
