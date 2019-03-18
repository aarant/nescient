from nescient.gui.about_base import Ui_Dialog

from PyQt5 import QtWidgets


class AboutNescient(QtWidgets.QDialog):
    def __init__(self):
        QtWidgets.QDialog.__init__(self)
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.setFixedSize(self.size())
