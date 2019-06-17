from nescient.gui.about_base import Ui_Dialog
from nescient import __version__

from PyQt5 import QtWidgets


class AboutNescient(QtWidgets.QDialog):
    def __init__(self):
        QtWidgets.QDialog.__init__(self)
        self.ui = Ui_Dialog()
        self.ui.setupUi(self)
        self.ui.label_2.setText('Nescient v{}'.format(__version__))
        self.setFixedSize(self.size())
