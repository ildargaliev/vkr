import sys

from PyQt5 import QtWidgets, QtCore

import design8 as design

from checks import STPCheck, DTPCheck, CAMCheck

from scapy.all import *

import datetime





class ExampleApp(QtWidgets.QMainWindow, design.Ui_MainWindow):

    

    def __init__(self):

        super().__init__()

        self.stp_check = STPCheck(self)

        self.dtp_check = DTPCheck(self)

        self.cam_check = CAMCheck(self)

        self.setupUi(self)



        self.verticalLayoutWidget.hide()

        self.horizontalLayoutWidget.hide()

        self.verticalLayoutWidget_4.hide()

        self.stp_stop_sendButton.setDisabled(True)

        self.stp_tableWidget.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)

        self.stp_tableWidget.verticalHeader().hide()

        self.stp_start_sniffingButton.clicked.connect(self.start_sniffing)

        self.stp_start_sendButton.clicked.connect(self.start_sending_packets)

        self.stp_stop_sendButton.clicked.connect(self.stop_sending_packets)





        self.verticalLayoutWidget_5.hide()

        self.horizontalLayoutWidget_3.hide()

        # self.dtp_tableWidget.hide()

        self.dtp_stop_sendButton.setDisabled(True)

        self.dtp_tableWidget.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)

        self.dtp_tableWidget.verticalHeader().hide()

        self.dtp_start_sniffingButton.clicked.connect(self.dtp_start_sniffing)

        self.dtp_start_sendButton.clicked.connect(self.dtp_start_sending_packets)

        self.dtp_stop_sendButton.clicked.connect(self.dtp_stop_sending_packets)        

        

        

        self.cam_start_sendButton.clicked.connect(self.cam_start_sending_packets)

        self.cam_stop_sendButton.clicked.connect(self.cam_stop_sending_packets)

        self.cam_tableWidget.horizontalHeader().setSectionResizeMode(QtWidgets.QHeaderView.ResizeToContents)

        self.cam_tableWidget.verticalHeader().hide()





    def start_sniffing(self):

        self.stp_start_sniffingButton.hide()

        self.verticalLayoutWidget.show()

        self.stp_check.start_sniffing()

        # 



    def add_row(self, pkt):

        # rowPosition = self.stp_tableWidget.rowCount()

        rowPosition = 0

        # print(rowPosition)

        # print(pkt)

        if not self.stp_check.hasTraffic:

            self.verticalLayoutWidget_4.hide()

            self.verticalLayoutWidget.show()

            self.horizontalLayoutWidget.show()

            self.stp_check.hasTraffic = True

    

        self.stp_tableWidget.insertRow(rowPosition)

        self.stp_tableWidget.setItem(rowPosition , 0, QtWidgets.QTableWidgetItem(pkt[Dot3].src))

        self.stp_tableWidget.setItem(rowPosition , 1, QtWidgets.QTableWidgetItem(str(pkt[STP].rootid)))

        self.stp_tableWidget.setItem(rowPosition , 2, QtWidgets.QTableWidgetItem(str(pkt[STP].bridgeid)))

        self.stp_tableWidget.setItem(rowPosition , 3, QtWidgets.QTableWidgetItem(datetime.datetime.fromtimestamp(pkt.time).isoformat()))



    def start_sending_packets(self):

        self.stp_start_sendButton.setDisabled(True)

        self.stp_stop_sendButton.setDisabled(False)

        self.stp_check.start_sending_packets()



    def stop_sending_packets(self):

        self.stp_stop_sendButton.setDisabled(True)

        self.stp_start_sendButton.setDisabled(False)

        self.stp_check.stop_sending_packets()







    def dtp_start_sniffing(self):

        self.dtp_start_sniffingButton.hide()

        self.verticalLayoutWidget_5.show()

        self.dtp_check.start_sniffing()

        # 



    def dtp_start_sending_packets(self):

        self.dtp_start_sendButton.setDisabled(True)

        self.dtp_stop_sendButton.setDisabled(False)

        self.dtp_check.start_sending_packets()



    def dtp_stop_sending_packets(self):

        self.dtp_stop_sendButton.setDisabled(True)

        self.dtp_start_sendButton.setDisabled(False)

        self.dtp_check.stop_sending_packets()



    def dtp_add_row(self, pkt):

        if DTP in pkt:

            if not self.dtp_check.hasTraffic:

                self.verticalLayoutWidget_5.hide()

                # self.verticalLayoutWidget_5.show()

                self.horizontalLayoutWidget_3.show()

                self.dtp_check.hasTraffic = True

            

            DTP_status = pkt[DTP].tlvlist[1].status

            DTP_status = DTPCheck.STATUS_MAP.get(DTP_status, str(DTP_status))

            if not DTP_status:

                DTP_status = str(DTP_status)



            self.dtp_tableWidget.insertRow(0)

            self.dtp_tableWidget.setItem(0 , 0, QtWidgets.QTableWidgetItem(pkt[DTP].tlvlist[3].neighbor))

            self.dtp_tableWidget.setItem(0 , 1, QtWidgets.QTableWidgetItem(DTP_status))

            self.dtp_tableWidget.setItem(0 , 2, QtWidgets.QTableWidgetItem(datetime.datetime.fromtimestamp(pkt.time).isoformat()))





    def cam_start_sending_packets(self):

        if not self.cam_check.hasTraffic:

            self.cam_check.start_sniffing()

        self.cam_start_sendButton.setDisabled(True)

        self.cam_stop_sendButton.setDisabled(False)

        self.cam_check.start_sending_packets()



    def cam_stop_sending_packets(self):

        self.cam_stop_sendButton.setDisabled(True)

        self.cam_start_sendButton.setDisabled(False)

        self.cam_check.stop_sending_packets()



    def cam_add_row(self, pkt):

        if not self.cam_check.hasTraffic:

            self.cam_check.hasTraffic = True

        

        self.cam_tableWidget.insertRow(0)

        self.cam_tableWidget.setItem(0 , 0, QtWidgets.QTableWidgetItem(pkt[Ether].src))

        self.cam_tableWidget.setItem(0 , 1, QtWidgets.QTableWidgetItem(pkt[IP].src))

        self.cam_tableWidget.setItem(0 , 2, QtWidgets.QTableWidgetItem(pkt[Ether].dst))

        self.cam_tableWidget.setItem(0 , 3, QtWidgets.QTableWidgetItem(pkt[IP].dst))





def main():

    app = QtWidgets.QApplication(sys.argv)

    window = ExampleApp()

    window.show()

    app.exec_()



if __name__ == '__main__':

    load_contrib('dtp')

    main()
