# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file '/home/kali/Desktop/diploma/untitled8.ui'
#
# Created by: PyQt5 UI code generator 5.15.9
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.


from PyQt5 import QtCore, QtGui, QtWidgets


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(950, 600)
        MainWindow.setBaseSize(QtCore.QSize(1920, 1080))
        MainWindow.setLocale(QtCore.QLocale(QtCore.QLocale.Russian, QtCore.QLocale.Russia))
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.tabWidget = QtWidgets.QTabWidget(self.centralwidget)
        self.tabWidget.setGeometry(QtCore.QRect(0, 10, 1011, 651))
        self.tabWidget.setStyleSheet("font: 18pt \"PT Sans\";")
        self.tabWidget.setLocale(QtCore.QLocale(QtCore.QLocale.Russian, QtCore.QLocale.Russia))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.verticalLayoutWidget = QtWidgets.QWidget(self.tab)
        self.verticalLayoutWidget.setGeometry(QtCore.QRect(9, 9, 931, 381))
        self.verticalLayoutWidget.setObjectName("verticalLayoutWidget")
        self.verticalLayout = QtWidgets.QVBoxLayout(self.verticalLayoutWidget)
        self.verticalLayout.setContentsMargins(0, 0, 0, 0)
        self.verticalLayout.setObjectName("verticalLayout")
        self.stp_tableWidget = QtWidgets.QTableWidget(self.verticalLayoutWidget)
        self.stp_tableWidget.setObjectName("stp_tableWidget")
        self.stp_tableWidget.setColumnCount(4)
        self.stp_tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignJustify|QtCore.Qt.AlignVCenter)
        self.stp_tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.stp_tableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.stp_tableWidget.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.stp_tableWidget.setHorizontalHeaderItem(3, item)
        self.stp_tableWidget.horizontalHeader().setStretchLastSection(False)
        self.verticalLayout.addWidget(self.stp_tableWidget)
        self.horizontalLayoutWidget = QtWidgets.QWidget(self.tab)
        self.horizontalLayoutWidget.setGeometry(QtCore.QRect(10, 420, 931, 71))
        self.horizontalLayoutWidget.setObjectName("horizontalLayoutWidget")
        self.stp_buttonsLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget)
        self.stp_buttonsLayout.setContentsMargins(0, 0, 0, 0)
        self.stp_buttonsLayout.setObjectName("stp_buttonsLayout")
        self.stp_start_sendButton = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        self.stp_start_sendButton.setObjectName("stp_start_sendButton")
        self.stp_buttonsLayout.addWidget(self.stp_start_sendButton)
        self.stp_stop_sendButton = QtWidgets.QPushButton(self.horizontalLayoutWidget)
        self.stp_stop_sendButton.setObjectName("stp_stop_sendButton")
        self.stp_buttonsLayout.addWidget(self.stp_stop_sendButton)
        self.stp_start_sniffingButton = QtWidgets.QPushButton(self.tab)
        self.stp_start_sniffingButton.setEnabled(True)
        self.stp_start_sniffingButton.setGeometry(QtCore.QRect(263, 246, 412, 37))
        self.stp_start_sniffingButton.setAutoDefault(False)
        self.stp_start_sniffingButton.setDefault(False)
        self.stp_start_sniffingButton.setFlat(False)
        self.stp_start_sniffingButton.setObjectName("stp_start_sniffingButton")
        self.verticalLayoutWidget_4 = QtWidgets.QWidget(self.tab)
        self.verticalLayoutWidget_4.setGeometry(QtCore.QRect(260, 120, 436, 80))
        self.verticalLayoutWidget_4.setObjectName("verticalLayoutWidget_4")
        self.stp_no_traffic_label = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_4)
        self.stp_no_traffic_label.setContentsMargins(0, 0, 0, 0)
        self.stp_no_traffic_label.setObjectName("stp_no_traffic_label")
        self.label_5 = QtWidgets.QLabel(self.verticalLayoutWidget_4)
        self.label_5.setObjectName("label_5")
        self.stp_no_traffic_label.addWidget(self.label_5)
        self.label_6 = QtWidgets.QLabel(self.verticalLayoutWidget_4)
        self.label_6.setObjectName("label_6")
        self.stp_no_traffic_label.addWidget(self.label_6)
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.horizontalLayoutWidget_3 = QtWidgets.QWidget(self.tab_2)
        self.horizontalLayoutWidget_3.setGeometry(QtCore.QRect(10, 420, 931, 71))
        self.horizontalLayoutWidget_3.setObjectName("horizontalLayoutWidget_3")
        self.dtp_buttonsLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget_3)
        self.dtp_buttonsLayout.setContentsMargins(0, 0, 0, 0)
        self.dtp_buttonsLayout.setObjectName("dtp_buttonsLayout")
        self.dtp_start_sendButton = QtWidgets.QPushButton(self.horizontalLayoutWidget_3)
        self.dtp_start_sendButton.setObjectName("dtp_start_sendButton")
        self.dtp_buttonsLayout.addWidget(self.dtp_start_sendButton)
        self.dtp_stop_sendButton = QtWidgets.QPushButton(self.horizontalLayoutWidget_3)
        self.dtp_stop_sendButton.setObjectName("dtp_stop_sendButton")
        self.dtp_buttonsLayout.addWidget(self.dtp_stop_sendButton)
        self.dtp_tableWidget = QtWidgets.QTableWidget(self.tab_2)
        self.dtp_tableWidget.setGeometry(QtCore.QRect(10, 8, 929, 381))
        self.dtp_tableWidget.setObjectName("dtp_tableWidget")
        self.dtp_tableWidget.setColumnCount(3)
        self.dtp_tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignJustify|QtCore.Qt.AlignVCenter)
        self.dtp_tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.dtp_tableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.dtp_tableWidget.setHorizontalHeaderItem(2, item)
        self.dtp_tableWidget.horizontalHeader().setStretchLastSection(False)
        self.dtp_start_sniffingButton = QtWidgets.QPushButton(self.tab_2)
        self.dtp_start_sniffingButton.setEnabled(True)
        self.dtp_start_sniffingButton.setGeometry(QtCore.QRect(250, 240, 412, 37))
        self.dtp_start_sniffingButton.setAutoDefault(False)
        self.dtp_start_sniffingButton.setDefault(False)
        self.dtp_start_sniffingButton.setFlat(False)
        self.dtp_start_sniffingButton.setObjectName("dtp_start_sniffingButton")
        self.verticalLayoutWidget_5 = QtWidgets.QWidget(self.tab_2)
        self.verticalLayoutWidget_5.setGeometry(QtCore.QRect(247, 114, 436, 80))
        self.verticalLayoutWidget_5.setObjectName("verticalLayoutWidget_5")
        self.dtp_no_traffic_label = QtWidgets.QVBoxLayout(self.verticalLayoutWidget_5)
        self.dtp_no_traffic_label.setContentsMargins(0, 0, 0, 0)
        self.dtp_no_traffic_label.setObjectName("dtp_no_traffic_label")
        self.label_7 = QtWidgets.QLabel(self.verticalLayoutWidget_5)
        self.label_7.setObjectName("label_7")
        self.dtp_no_traffic_label.addWidget(self.label_7)
        self.label_8 = QtWidgets.QLabel(self.verticalLayoutWidget_5)
        self.label_8.setObjectName("label_8")
        self.dtp_no_traffic_label.addWidget(self.label_8)
        self.dtp_tableWidget.raise_()
        self.horizontalLayoutWidget_3.raise_()
        self.dtp_start_sniffingButton.raise_()
        self.verticalLayoutWidget_5.raise_()
        self.tabWidget.addTab(self.tab_2, "")
        self.tab_4 = QtWidgets.QWidget()
        self.tab_4.setObjectName("tab_4")
        self.horizontalLayoutWidget_4 = QtWidgets.QWidget(self.tab_4)
        self.horizontalLayoutWidget_4.setGeometry(QtCore.QRect(10, 422, 931, 71))
        self.horizontalLayoutWidget_4.setObjectName("horizontalLayoutWidget_4")
        self.cam_buttonsLayout = QtWidgets.QHBoxLayout(self.horizontalLayoutWidget_4)
        self.cam_buttonsLayout.setContentsMargins(0, 0, 0, 0)
        self.cam_buttonsLayout.setObjectName("cam_buttonsLayout")
        self.cam_start_sendButton = QtWidgets.QPushButton(self.horizontalLayoutWidget_4)
        self.cam_start_sendButton.setObjectName("cam_start_sendButton")
        self.cam_buttonsLayout.addWidget(self.cam_start_sendButton)
        self.cam_stop_sendButton = QtWidgets.QPushButton(self.horizontalLayoutWidget_4)
        self.cam_stop_sendButton.setObjectName("cam_stop_sendButton")
        self.cam_buttonsLayout.addWidget(self.cam_stop_sendButton)
        self.cam_tableWidget = QtWidgets.QTableWidget(self.tab_4)
        self.cam_tableWidget.setGeometry(QtCore.QRect(10, 10, 929, 381))
        self.cam_tableWidget.setObjectName("cam_tableWidget")
        self.cam_tableWidget.setColumnCount(4)
        self.cam_tableWidget.setRowCount(0)
        item = QtWidgets.QTableWidgetItem()
        item.setTextAlignment(QtCore.Qt.AlignJustify|QtCore.Qt.AlignVCenter)
        self.cam_tableWidget.setHorizontalHeaderItem(0, item)
        item = QtWidgets.QTableWidgetItem()
        self.cam_tableWidget.setHorizontalHeaderItem(1, item)
        item = QtWidgets.QTableWidgetItem()
        self.cam_tableWidget.setHorizontalHeaderItem(2, item)
        item = QtWidgets.QTableWidgetItem()
        self.cam_tableWidget.setHorizontalHeaderItem(3, item)
        self.cam_tableWidget.horizontalHeader().setStretchLastSection(False)
        self.tabWidget.addTab(self.tab_4, "")
        self.tab_6 = QtWidgets.QWidget()
        self.tab_6.setObjectName("tab_6")
        self.tabWidget.addTab(self.tab_6, "")
        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QtWidgets.QMenuBar(MainWindow)
        self.menubar.setGeometry(QtCore.QRect(0, 0, 950, 24))
        self.menubar.setObjectName("menubar")
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)
        self.action = QtWidgets.QAction(MainWindow)
        self.action.setObjectName("action")

        self.retranslateUi(MainWindow)
        self.tabWidget.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        item = self.stp_tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Sender MAC"))
        item = self.stp_tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Root ID"))
        item = self.stp_tableWidget.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Bridge ID"))
        item = self.stp_tableWidget.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "Время"))
        self.stp_start_sendButton.setText(_translate("MainWindow", "Начать генерацию пакетов"))
        self.stp_stop_sendButton.setText(_translate("MainWindow", "Остановка генерации пакетов"))
        self.stp_start_sniffingButton.setWhatsThis(_translate("MainWindow", "<html><head/><body><p><br/></p></body></html>"))
        self.stp_start_sniffingButton.setText(_translate("MainWindow", "Проверка наличия трафика STP"))
        self.label_5.setText(_translate("MainWindow", "Проверка наличия трафика STP... "))
        self.label_6.setText(_translate("MainWindow", "STP трафик не обнаружен"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("MainWindow", "STP"))
        self.dtp_start_sendButton.setText(_translate("MainWindow", "Начать генерацию пакетов"))
        self.dtp_stop_sendButton.setText(_translate("MainWindow", "Остановка генерации пакетов"))
        item = self.dtp_tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "Neighbor ID"))
        item = self.dtp_tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "Status"))
        item = self.dtp_tableWidget.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "Время"))
        self.dtp_start_sniffingButton.setWhatsThis(_translate("MainWindow", "<html><head/><body><p><br/></p></body></html>"))
        self.dtp_start_sniffingButton.setText(_translate("MainWindow", "Проверка наличия трафика DTP"))
        self.label_7.setText(_translate("MainWindow", "Проверка наличия трафика DTP... "))
        self.label_8.setText(_translate("MainWindow", "DTP трафик не обнаружен"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("MainWindow", "DTP"))
        self.cam_start_sendButton.setText(_translate("MainWindow", "Начать генерацию пакетов"))
        self.cam_stop_sendButton.setText(_translate("MainWindow", "Остановка генерации пакетов"))
        item = self.cam_tableWidget.horizontalHeaderItem(0)
        item.setText(_translate("MainWindow", "MAC отправителя"))
        item = self.cam_tableWidget.horizontalHeaderItem(1)
        item.setText(_translate("MainWindow", "IP отправителя"))
        item = self.cam_tableWidget.horizontalHeaderItem(2)
        item.setText(_translate("MainWindow", "MAC получателя"))
        item = self.cam_tableWidget.horizontalHeaderItem(3)
        item.setText(_translate("MainWindow", "IP получателя"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_4), _translate("MainWindow", "CAM"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_6), _translate("MainWindow", "RIP"))
        self.action.setText(_translate("MainWindow", "Сетевой интерфейс"))
