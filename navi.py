# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'mainwindow.ui'
#
# Created by: PyQt5 UI code generator 5.11.2
#
# WARNING! All changes made in this file will be lost!
import os
import gc
import shutil
import subprocess
from zipfile import ZipFile
from io import BytesIO
from tempfile import mkdtemp

from archive_class import NescientArchive
from PIL import Image
from PyQt5 import QtCore, QtGui, QtWidgets

def read_archive(path):
    password, ok = QtWidgets.QInputDialog.getText(None, 'Decrypt archive', 'Enter password:', echo=QtWidgets.QLineEdit.Password)
    if not ok:
        return
##    packer = NescientPacker(password)
##    with open(path, 'rb') as f:
##        data = bytearray(f.read())
##        print('Unpacking...')
##        packer.unpack(data)
##        buffer = BytesIO(data)
##        print('Checking archive...')
##        archive = ZipFile(buffer, 'r')
##        return archive
    print('Validating archive')
    nesc = NescientArchive(path, password)
    print('Checking archive')
    archive = ZipFile(nesc, 'r')
    return archive

class Ui_MainWindow():
    def __init__(self):
        self.archive = None
        self.temp_dir = None
        

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(550, 500)
        self.centralWidget = QtWidgets.QWidget(MainWindow)
        self.centralWidget.setObjectName("centralWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.centralWidget)
        self.verticalLayout.setContentsMargins(11, 11, 11, 11)
        self.verticalLayout.setSpacing(6)
        self.verticalLayout.setObjectName("verticalLayout")
        self.horizontalLayout = QtWidgets.QHBoxLayout()
        self.horizontalLayout.setSpacing(6)
        self.horizontalLayout.setObjectName("horizontalLayout")
        self.treeWidget = QtWidgets.QTreeWidget(self.centralWidget)
        self.treeWidget.setSizeAdjustPolicy(QtWidgets.QAbstractScrollArea.AdjustToContents)
        self.treeWidget.setSelectionMode(QtWidgets.QAbstractItemView.ExtendedSelection)
        self.treeWidget.setObjectName("treeWidget")
        self.horizontalLayout.addWidget(self.treeWidget)
        self.label = QtWidgets.QLabel(self.centralWidget)
        sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Minimum, QtWidgets.QSizePolicy.Minimum)
        sizePolicy.setHorizontalStretch(0)
        sizePolicy.setVerticalStretch(0)
        sizePolicy.setHeightForWidth(self.label.sizePolicy().hasHeightForWidth())
        self.label.setSizePolicy(sizePolicy)
        self.label.setMinimumSize(QtCore.QSize(256, 256))
        self.label.setText("")
        self.label.setAlignment(QtCore.Qt.AlignCenter)
        self.label.setObjectName("label")
        self.horizontalLayout.addWidget(self.label)
        self.verticalLayout.addLayout(self.horizontalLayout)
        self.pushButton = QtWidgets.QPushButton(self.centralWidget)
        self.pushButton.setObjectName("pushButton")
        self.verticalLayout.addWidget(self.pushButton)
        self.pushButton.setText('Export')
        MainWindow.setCentralWidget(self.centralWidget)
        self.menuBar = QtWidgets.QMenuBar(MainWindow)
        self.menuBar.setGeometry(QtCore.QRect(0, 0, 500, 21))
        self.menuBar.setObjectName("menuBar")
        MainWindow.setMenuBar(self.menuBar)
        self.menuOpen = self.menuBar.addAction('Open')
        self.menuOpen.triggered.connect(self.open_archive)
        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)
        self.pushButton.clicked.connect(self.exportButton)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "Navi (Nescient Archive Viewer)"))
        self.treeWidget.headerItem().setText(0, _translate("MainWindow", "File"))
        __sortingEnabled = self.treeWidget.isSortingEnabled()
        self.treeWidget.setSortingEnabled(__sortingEnabled)

    def open_archive(self, filename=None):
        if not filename:
            self.treeWidget.clear()
            options = QtWidgets.QFileDialog.Options()
            options |= QtWidgets.QFileDialog.DontUseNativeDialog
            filename, ok = QtWidgets.QFileDialog.getOpenFileName(None, 'Select Archive', '', 'Nescient archives (*.nesc)')
            if not ok:
                return
        print('Archive: ', filename)
        self.archive = read_archive(filename)
        if self.archive is None:
            return
        print('Opening...')
        self.treeWidget.itemSelectionChanged.connect(self.select_files)
        self.treeWidget.itemDoubleClicked.connect(self.doubleclick_file)
        tree = {}
        for obj in self.archive.infolist():
            parts = obj.filename.split('/')
            #print('Parts:', parts)
            for i in range(1, len(parts)+1 if parts[-1] else len(parts)):
                sub_parts = parts[:i]
                path = tuple(sub_parts)
                #print('Sub path:', path)
                if path not in tree:
                    if len(sub_parts) == 1:
                        parent = self.treeWidget
                    else:
                        parent = tree[tuple(sub_parts[:-1])]
                    #print(parent)
                    node = QtWidgets.QTreeWidgetItem(parent)
                    node.setText(0, sub_parts[-1])
                    if i == len(parts):
                        node.filename = obj.filename
                        #print('Set filename')
                    else:
                        node.filename = None
                    tree[tuple(path)] = node
                    #print('Tree:', tree)
                    
##        for name in self.archive.namelist():
##            foo = QtWidgets.QTreeWidgetItem(self.treeWidget)
##            foo.setText(0, name)

    def select_files(self, *args):
        items = self.treeWidget.selectedItems()
        if not items:
            return
        #filename = items[0].data(0, QtCore.Qt.DisplayRole)
        filename = items[-1].filename
        print(filename)
        if filename is None or os.path.splitext(filename)[1].lower() not in ['.bmp', '.png', '.jpg', '.jpeg']:
            return
        with self.archive.open(filename) as f:
            im = Image.open(f)
            im.thumbnail((256, 256))
            buffer = BytesIO()
            im = im.convert('RGB')
            im.save(buffer, format='JPEG', quality=95)
            qimg = QtGui.QImage.fromData(buffer.getbuffer())
            self.label.setPixmap(QtGui.QPixmap.fromImage(qimg))
            buffer.close()
            gc.collect()

    def doubleclick_file(self, item):
        if item.filename is not None:
            self.export_files([item.filename])
        

    def export_files(self, files):
        for filename in files:
            if self.temp_dir is None:
                self.temp_dir = mkdtemp()
                try:
                    subprocess.Popen('explorer ' + '"' + self.temp_dir + '"')
                except Exception:
                    pass
            with self.archive.open(filename) as f:
                with open(os.path.join(self.temp_dir, os.path.split(filename)[1]), 'wb') as f_out:
                    f_out.write(f.read())
                print(os.path.join(self.temp_dir, os.path.split(filename)[1]))
        cb = app.clipboard()
        cb.setText(self.temp_dir)

    def exportButton(self, event):
        items = self.treeWidget.selectedItems()
        files = [item.filename for item in items if item.filename is not None]
        if files:
            self.export_files(files)
        
    


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    if len(sys.argv) == 2:
        ui.open_archive(filename=sys.argv[1])
    MainWindow.show()
    app.exec_()
    if ui.temp_dir is not None:
        shutil.rmtree(ui.temp_dir)
        print('Deleted')
    sys.exit()
    

