import os  # 用于生成随机序列
import base64  # 用于密文编码
import datetime # 用于计算加密时间

#以下是对Cryptography的引用，均为hazmat底层的对象
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes   #用于指定加密算法及模式
from cryptography.hazmat.backends import default_backend                       #这里的default_backend 为 None
from cryptography.hazmat.primitives import hashes, padding                     #用于分组的填充，以及解密后填充的移除
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC               #用于处理用户自定义的密钥
from PyQt5 import QtCore, QtGui, QtWidgets
from PyQt5.QtWidgets import QFileDialog

class Ui_MainWindow(object):
    key = ""
    salt = os.urandom(16)
    iv = os.urandom(16)
    backend = default_backend() # 默认后端
    cipherECB = None
    cipherCBC = None
    cipherCFB = None
    cipherOFB = None
    cipherCTR = None
    file = r'E:\time.txt' # 记录加密时间的路径
    fp = open(file, 'a+') # 追加的方式写入加密时间
    file2 = r'E:\cipher.txt'  # 记录以base64编码解密后的密文路径
    fp2 = open(file2, 'a+')  # 追加的方式写入以base64编码解密后的密文结果
    fp.write("\n")
    fp2.write("\n")

    def setupUi(self, MainWindow):
        MainWindow.setObjectName("MainWindow")
        MainWindow.resize(910, 592)
        self.centralwidget = QtWidgets.QWidget(MainWindow)
        self.centralwidget.setObjectName("centralwidget")
        self.label = QtWidgets.QLabel(self.centralwidget)
        self.label.setGeometry(QtCore.QRect(20, 70, 81, 21))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(self.centralwidget)
        self.label_2.setGeometry(QtCore.QRect(40, 140, 61, 16))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(self.centralwidget)
        self.label_3.setGeometry(QtCore.QRect(190, 10, 121, 39))
        font = QtGui.QFont()
        font.setFamily("Arial Unicode MS")
        font.setPointSize(22)
        font.setBold(False)
        font.setWeight(50)
        self.label_3.setFont(font)
        self.label_3.setObjectName("label_3")
        self.txtPlain = QtWidgets.QTextEdit(self.centralwidget)
        self.txtPlain.setGeometry(QtCore.QRect(30, 240, 181, 71))
        self.txtPlain.setObjectName("txtPlain")
        self.btnChooseEnFile = QtWidgets.QPushButton(self.centralwidget)
        self.btnChooseEnFile.setGeometry(QtCore.QRect(360, 70, 51, 21))
        self.btnChooseEnFile.setObjectName("btnChooseEnFile")
        self.txtEnFilePath = QtWidgets.QTextEdit(self.centralwidget)
        self.txtEnFilePath.setGeometry(QtCore.QRect(110, 60, 241, 41))
        self.txtEnFilePath.setObjectName("txtEnFilePath")
        self.txtEnKey = QtWidgets.QTextEdit(self.centralwidget)
        self.txtEnKey.setGeometry(QtCore.QRect(110, 130, 241, 31))
        self.txtEnKey.setObjectName("txtEnKey")
        self.btnChooseEnKey = QtWidgets.QPushButton(self.centralwidget)
        self.btnChooseEnKey.setGeometry(QtCore.QRect(360, 130, 51, 21))
        self.btnChooseEnKey.setObjectName("btnChooseEnKey")
        self.label_6 = QtWidgets.QLabel(self.centralwidget)
        self.label_6.setGeometry(QtCore.QRect(110, 220, 24, 12))
        self.label_6.setObjectName("label_6")
        self.btnChooseDeKey = QtWidgets.QPushButton(self.centralwidget)
        self.btnChooseDeKey.setGeometry(QtCore.QRect(810, 130, 51, 21))
        self.btnChooseDeKey.setObjectName("btnChooseDeKey")
        self.txtDeKey = QtWidgets.QTextEdit(self.centralwidget)
        self.txtDeKey.setGeometry(QtCore.QRect(560, 130, 241, 31))
        self.txtDeKey.setObjectName("txtDeKey")
        self.label_4 = QtWidgets.QLabel(self.centralwidget)
        self.label_4.setGeometry(QtCore.QRect(640, 10, 111, 39))
        font = QtGui.QFont()
        font.setFamily("Arial Unicode MS")
        font.setPointSize(22)
        font.setBold(False)
        font.setWeight(50)
        self.label_4.setFont(font)
        self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(self.centralwidget)
        self.label_5.setGeometry(QtCore.QRect(490, 140, 61, 20))
        self.label_5.setObjectName("label_5")
        self.txtDeFilePath = QtWidgets.QTextEdit(self.centralwidget)
        self.txtDeFilePath.setGeometry(QtCore.QRect(560, 60, 241, 41))
        self.txtDeFilePath.setObjectName("txtDeFilePath")
        self.label_8 = QtWidgets.QLabel(self.centralwidget)
        self.label_8.setGeometry(QtCore.QRect(470, 70, 81, 21))
        self.label_8.setObjectName("label_8")
        self.btnChooseDeFile = QtWidgets.QPushButton(self.centralwidget)
        self.btnChooseDeFile.setGeometry(QtCore.QRect(810, 70, 51, 21))
        self.btnChooseDeFile.setObjectName("btnChooseDeFile")
        self.btnEn = QtWidgets.QPushButton(self.centralwidget)
        self.btnEn.setGeometry(QtCore.QRect(180, 180, 81, 31))
        font = QtGui.QFont()
        font.setFamily("Agency FB")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.btnEn.setFont(font)
        self.btnEn.setObjectName("btnEn")
        self.btnDe = QtWidgets.QPushButton(self.centralwidget)
        self.btnDe.setGeometry(QtCore.QRect(640, 180, 81, 31))
        font = QtGui.QFont()
        font.setFamily("Agency FB")
        font.setPointSize(12)
        font.setBold(True)
        font.setWeight(75)
        self.btnDe.setFont(font)
        self.btnDe.setObjectName("btnDe")
        self.btnExport1 = QtWidgets.QPushButton(self.centralwidget)
        self.btnExport1.setGeometry(QtCore.QRect(320, 530, 75, 23))
        self.btnExport1.setObjectName("btnExport1")
        self.btnExport2 = QtWidgets.QPushButton(self.centralwidget)
        self.btnExport2.setGeometry(QtCore.QRect(760, 530, 75, 23))
        self.btnExport2.setObjectName("btnExport2")
        self.txtEnECB = QtWidgets.QTextEdit(self.centralwidget)
        self.txtEnECB.setGeometry(QtCore.QRect(230, 240, 181, 71))
        self.txtEnECB.setObjectName("txtEnECB")
        self.label_7 = QtWidgets.QLabel(self.centralwidget)
        self.label_7.setGeometry(QtCore.QRect(280, 220, 101, 16))
        self.label_7.setObjectName("label_7")
        self.txtEnCBC = QtWidgets.QTextEdit(self.centralwidget)
        self.txtEnCBC.setGeometry(QtCore.QRect(30, 340, 181, 71))
        self.txtEnCBC.setObjectName("txtEnCBC")
        self.txtEnCFB = QtWidgets.QTextEdit(self.centralwidget)
        self.txtEnCFB.setGeometry(QtCore.QRect(230, 340, 181, 71))
        self.txtEnCFB.setObjectName("txtEnCFB")
        self.txtEnOFB = QtWidgets.QTextEdit(self.centralwidget)
        self.txtEnOFB.setGeometry(QtCore.QRect(30, 440, 181, 71))
        self.txtEnOFB.setObjectName("txtEnOFB")
        self.txtEnCTR = QtWidgets.QTextEdit(self.centralwidget)
        self.txtEnCTR.setGeometry(QtCore.QRect(230, 440, 181, 71))
        self.txtEnCTR.setObjectName("txtEnCTR")
        self.label_9 = QtWidgets.QLabel(self.centralwidget)
        self.label_9.setGeometry(QtCore.QRect(80, 320, 101, 16))
        self.label_9.setObjectName("label_9")
        self.label_10 = QtWidgets.QLabel(self.centralwidget)
        self.label_10.setGeometry(QtCore.QRect(280, 320, 101, 16))
        self.label_10.setObjectName("label_10")
        self.label_11 = QtWidgets.QLabel(self.centralwidget)
        self.label_11.setGeometry(QtCore.QRect(80, 420, 101, 16))
        self.label_11.setObjectName("label_11")
        self.label_12 = QtWidgets.QLabel(self.centralwidget)
        self.label_12.setGeometry(QtCore.QRect(280, 420, 101, 16))
        self.label_12.setObjectName("label_12")
        self.txtDeCBC = QtWidgets.QTextEdit(self.centralwidget)
        self.txtDeCBC.setGeometry(QtCore.QRect(480, 340, 181, 71))
        self.txtDeCBC.setObjectName("txtDeCBC")
        self.label_13 = QtWidgets.QLabel(self.centralwidget)
        self.label_13.setGeometry(QtCore.QRect(530, 420, 101, 16))
        self.label_13.setObjectName("label_13")
        self.txtDeECB = QtWidgets.QTextEdit(self.centralwidget)
        self.txtDeECB.setGeometry(QtCore.QRect(680, 240, 181, 71))
        self.txtDeECB.setObjectName("txtDeECB")
        self.label_14 = QtWidgets.QLabel(self.centralwidget)
        self.label_14.setGeometry(QtCore.QRect(530, 320, 101, 16))
        self.label_14.setObjectName("label_14")
        self.txtDeCTR = QtWidgets.QTextEdit(self.centralwidget)
        self.txtDeCTR.setGeometry(QtCore.QRect(680, 440, 181, 71))
        self.txtDeCTR.setObjectName("txtDeCTR")
        self.label_15 = QtWidgets.QLabel(self.centralwidget)
        self.label_15.setGeometry(QtCore.QRect(730, 320, 101, 16))
        self.label_15.setObjectName("label_15")
        self.txtCipher = QtWidgets.QTextEdit(self.centralwidget)
        self.txtCipher.setGeometry(QtCore.QRect(480, 240, 181, 71))
        self.txtCipher.setObjectName("txtCipher")
        self.txtDeOFB = QtWidgets.QTextEdit(self.centralwidget)
        self.txtDeOFB.setGeometry(QtCore.QRect(480, 440, 181, 71))
        self.txtDeOFB.setObjectName("txtDeOFB")
        self.label_16 = QtWidgets.QLabel(self.centralwidget)
        self.label_16.setGeometry(QtCore.QRect(730, 220, 101, 16))
        self.label_16.setObjectName("label_16")
        self.label_17 = QtWidgets.QLabel(self.centralwidget)
        self.label_17.setGeometry(QtCore.QRect(730, 420, 101, 16))
        self.label_17.setObjectName("label_17")
        self.txtDeCFB = QtWidgets.QTextEdit(self.centralwidget)
        self.txtDeCFB.setGeometry(QtCore.QRect(680, 340, 181, 71))
        self.txtDeCFB.setObjectName("txtDeCFB")
        self.label_18 = QtWidgets.QLabel(self.centralwidget)
        self.label_18.setGeometry(QtCore.QRect(560, 220, 24, 12))
        self.label_18.setObjectName("label_18")
        MainWindow.setCentralWidget(self.centralwidget)
        self.statusbar = QtWidgets.QStatusBar(MainWindow)
        self.statusbar.setObjectName("statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)
        QtCore.QMetaObject.connectSlotsByName(MainWindow)

        self.btnChooseEnFile.clicked.connect(self.chooseEnFile)  # 选择明文文件
        self.btnChooseDeFile.clicked.connect(self.chooseDeFile)  # 选择密文文件
        self.btnChooseEnKey.clicked.connect(self.chooseEnKey)  # 选择加密密钥文件
        self.btnChooseDeKey.clicked.connect(self.chooseDeKey)  # 选择解密密钥文件
        self.btnEn.clicked.connect(self.encrypt)  # 加密
        self.btnDe.clicked.connect(self.decrypt)  # 解密
        self.btnExport1.clicked.connect(self.exportCipher)  # 导出加密后的明文
        self.btnExport2.clicked.connect(self.exportPlain)  # 导出解密后的密文

    def retranslateUi(self, MainWindow):
        _translate = QtCore.QCoreApplication.translate
        MainWindow.setWindowTitle(_translate("MainWindow", "MainWindow"))
        self.label.setText(_translate("MainWindow", "选择明文文件："))
        self.label_2.setText(_translate("MainWindow", "加密密钥："))
        self.label_3.setText(_translate("MainWindow", "加密"))
        self.btnChooseEnFile.setText(_translate("MainWindow", "浏览"))
        self.btnChooseEnKey.setText(_translate("MainWindow", "浏览"))
        self.label_6.setText(_translate("MainWindow", "明文"))
        self.btnChooseDeKey.setText(_translate("MainWindow", "浏览"))
        self.label_4.setText(_translate("MainWindow", "解密"))
        self.label_5.setText(_translate("MainWindow", "解密密钥："))
        self.label_8.setText(_translate("MainWindow", "选择密文文件："))
        self.btnChooseDeFile.setText(_translate("MainWindow", "浏览"))
        self.btnEn.setText(_translate("MainWindow", "加密"))
        self.btnDe.setText(_translate("MainWindow", "解密"))
        self.btnExport1.setText(_translate("MainWindow", "导出文件"))
        self.btnExport2.setText(_translate("MainWindow", "导出文件"))
        self.label_7.setText(_translate("MainWindow", "ECB加密后的明文"))
        self.label_9.setText(_translate("MainWindow", "CBC加密后的明文"))
        self.label_10.setText(_translate("MainWindow", "CFB加密后的明文"))
        self.label_11.setText(_translate("MainWindow", "OFB加密后的明文"))
        self.label_12.setText(_translate("MainWindow", "CTR加密后的明文"))
        self.label_13.setText(_translate("MainWindow", "OFB解密后的密文"))
        self.label_14.setText(_translate("MainWindow", "CBC解密后的密文"))
        self.label_15.setText(_translate("MainWindow", "CFB解密后的密文"))
        self.label_16.setText(_translate("MainWindow", "ECB解密后的密文"))
        self.label_17.setText(_translate("MainWindow", "CTR解密后的密文"))
        self.label_18.setText(_translate("MainWindow", "密文"))

    # 选择明文文件
    def chooseEnFile(self):
        # 打开获取文件路径对话框，该函数返回一个二元组，其中第一个对象为所选文件的绝对路径
        fname, ftype = QFileDialog.getOpenFileName(None, "选择文件")
        # 检测是否选中文件，即fname的长度
        if fname.__len__() != 0:
            self.txtEnFilePath.setText(str(fname))

    # 选择密文文件
    def chooseDeFile(self):
        # 打开获取文件路径对话框，该函数返回一个二元组，其中第一个对象为所选文件的绝对路径
        fname, ftype = QFileDialog.getOpenFileName(None, "选择文件")
        if fname.__len__() != 0:
            self.txtDeFilePath.setText(str(fname))

    # 选择加密密钥文件
    def chooseEnKey(self):
        # 打开获取文件路径对话框，该函数返回一个二元组，其中第一个对象为所选文件的绝对路径
        fname, ftype = QFileDialog.getOpenFileName(None, "选择文件")
        if fname.__len__() != 0:
            # 获取文件指针
            fp = open(str(fname))
            # 读取文件中的内容并返回password
            password = fp.read()
            # 将解密密钥显示在文本框内
            self.txtEnKey.setText(password)

    # 选择解密密钥文件
    def chooseDeKey(self):
        # 打开获取文件路径对话框，该函数返回一个二元组，其中第一个对象为所选文件的绝对路径
        fname, ftype = QFileDialog.getOpenFileName(None, "选择文件")
        if fname.__len__() != 0:
            fp = open(str(fname))
            # 获取解密密钥并显示在界面的文本框内
            password = fp.read()
            self.txtDeKey.setText(password)

    # 密钥生成
    def generateKey(self, password):
        # 密钥用PBKDF2算法处理，参数设置如下，计算后可以保证密钥（特别是弱口令）的安全性
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=self.salt,
            iterations=100000,  # 迭代次数
            backend=self.backend
        )
        key = kdf.derive(password.encode())
        return key

    # 5种模式加密
    def encrypt(self):
        fname = self.txtEnFilePath.toPlainText()
        if fname.__len__() != 0:
            #读取明文文件
            fp = open(str(fname))
            data = fp.read()
            #将明文显示在左侧文本框内
            self.txtPlain.setText(data)
            # 从文本框获取将密钥，并转为字节串
            password = self.txtEnKey.toPlainText()
            self.key = self.generateKey(password)
            # ECB
            beginECB = datetime.datetime.now()
            self.cipherECB = self.ECBinit()
            self.ctECB = self.ECBencrypt(data.encode(),self.cipherECB)
            endECB = datetime.datetime.now()
            kECB = endECB - beginECB
            self.fp.write('ECB:'+str(kECB.total_seconds()*1000)+'ms\n') # 加密时间转为以毫秒为单位
            # CBC
            beginCBC = datetime.datetime.now()
            self.cipherCBC = self.CBCinit()
            self.ctCBC = self.CBCencrypt(data.encode(), self.cipherCBC)
            endCBC = datetime.datetime.now()
            kCBC = endCBC - beginCBC
            self.fp.write('CBC:'+str(kCBC.total_seconds()*1000)+'ms\n')
            # CFB
            beginCFB = datetime.datetime.now()
            self.cipherCFB = self.CFBinit()
            self.ctCFB = self.CFBencrypt(data.encode(), self.cipherCFB)
            endCFB = datetime.datetime.now()
            kCFB = endCFB - beginCFB
            self.fp.write('CFB:'+str(kCFB.total_seconds()*1000)+'ms\n')
            # OFB
            beginOFB = datetime.datetime.now()
            self.cipherOFB = self.OFBinit()
            self.ctOFB = self.OFBencrypt(data.encode(), self.cipherOFB)
            endOFB = datetime.datetime.now()
            kOFB = endOFB - beginOFB
            self.fp.write('OFB:'+str(kOFB.total_seconds()*1000)+'ms\n')
            # CTR
            beginCTR = datetime.datetime.now()
            self.cipherCTR = self.CTRinit()
            self.ctCTR = self.CTRencrypt(data.encode(), self.cipherCTR)
            endCTR = datetime.datetime.now()
            kCTR = endCTR - beginCTR
            self.fp.write('CTR:'+str(kCTR.total_seconds()*1000)+'ms\n')

    # 5种模式解密
    def decrypt(self):
        #解密过程同加密类似
        fname = self.txtDeFilePath.toPlainText()
        if fname.__len__() != 0:
            #读取密文文件
            fp = open(str(fname))
            ct = fp.read()
            #将密文显示在右侧密文文本框内
            self.txtCipher.setText(ct)
            #获得密钥
            password = self.txtDeKey.toPlainText()
            plainECB = self.ECBdecrypt(base64.urlsafe_b64decode(ct.encode()), password, self.cipherECB)
            self.txtDeECB.setText(plainECB)
            plainCBC = self.CBCdecrypt(base64.urlsafe_b64decode(ct.encode()), password, self.cipherCBC)
            self.txtDeCBC.setText(plainCBC)
            plainCFB = self.CFBdecrypt(base64.urlsafe_b64decode(ct.encode()), password, self.cipherCFB)
            self.txtDeCFB.setText(plainCFB)
            plainOFB = self.OFBdecrypt(base64.urlsafe_b64decode(ct.encode()), password, self.cipherOFB)
            self.txtDeOFB.setText(plainOFB)
            plainCTR = self.CTRdecrypt(base64.urlsafe_b64decode(ct.encode()), password, self.cipherCTR)
            self.txtDeCTR.setText(plainCTR)

    # 导出加密后的明文
    def exportCipher(self):
        # 打开保存文件对话框，该函数返回一个二元组，其中第一个对象为文件的绝对路径
        fileName, ok = QFileDialog.getSaveFileName(None, "文件保存")
        result_ECB = self.txtEnECB.toPlainText()
        result_CBC = self.txtEnCBC.toPlainText()
        result_CFB = self.txtEnCFB.toPlainText()
        result_OFB = self.txtEnOFB.toPlainText()
        result_CTR = self.txtEnCTR.toPlainText()
        if str(fileName).__len__() != 0:
            # 打开文件，如果文件不存在则新建一个文件，'w'设置方式为write
            fp_ecb = open(fileName + '-ecb.txt', 'w')
            # 向文件写入
            fp_ecb.write(result_ECB)
            fp_ecb.close()
            fp_cbc = open(fileName + '-cbc.txt', 'w')
            fp_cbc.write(result_CBC)
            fp_cbc.close()
            fp_cfb = open(fileName + '-cfb.txt', 'w')
            fp_cfb.write(result_CFB)
            fp_cfb.close()
            fp_ofb = open(fileName + '-ofb.txt', 'w')
            fp_ofb.write(result_OFB)
            fp_ofb.close()
            fp_ctr = open(fileName + '-ctr.txt', 'w')
            fp_ctr.write(result_CTR)
            fp_ctr.close()

    # 导出解密后的密文
    def exportPlain(self):
        # 打开保存文件对话框，该函数返回一个二元组，其中第一个对象为文件的绝对路径
        fileName, ok = QFileDialog.getSaveFileName(None, "文件保存")
        result_ECB = self.txtDeECB.toPlainText()
        result_CBC = self.txtDeCBC.toPlainText()
        result_CFB = self.txtDeCFB.toPlainText()
        result_OFB = self.txtDeOFB.toPlainText()
        result_CTR = self.txtDeCTR.toPlainText()
        if str(fileName).__len__() != 0:
            # 打开文件，如果文件不存在则新建一个文件，'w'设置方式为write
            fp_ecb = open(fileName + '-ecb.txt', 'w')
            # 向文件写入
            fp_ecb.write(result_ECB)
            fp_ecb.close()
            fp_cbc = open(fileName + '-cbc.txt', 'w')
            fp_cbc.write(result_CBC)
            fp_cbc.close()
            fp_cfb = open(fileName + '-cfb.txt', 'w')
            fp_cfb.write(result_CFB)
            fp_cfb.close()
            fp_ofb = open(fileName + '-ofb.txt', 'w')
            fp_ofb.write(result_OFB)
            fp_ofb.close()
            fp_ctr = open(fileName + '-ctr.txt', 'w')
            fp_ctr.write(result_CTR)
            fp_ctr.close()

    #-----------------------ECB模式-------------------------
    #初始化
    def ECBinit(self):
        #主要参数是modes，选择ECB，ECB是各分组间加密相互独立，所以不需要初始向量
        cipher_suite = Cipher(algorithms.AES(self.key), modes.ECB(), backend=self.backend)
        return cipher_suite

    #加密
    def ECBencrypt(self, data, cipher):
        encryptor = cipher.encryptor()
        #先填充，再加密
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        ctECB = base64.urlsafe_b64encode(ct).decode()
        self.txtEnECB.setText(ctECB)
        return ct

    # 解密
    def ECBdecrypt(self, ct, dePass, cipher):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=self.salt,
            iterations=100000,
            backend=self.backend
        )
        try:
            # 验证解密密钥是否正确，如果和加密密钥不匹配，会抛出异常
            kdf.verify(dePass.encode(), self.key)
        except Exception as e:
            res = "密钥错误！"
            return res
        decryptor = cipher.decryptor()
        # 这里获得的明文是填充后的
        plaintext_padded = decryptor.update(ct)
        # 可能抛出“数据长度无效”的异常
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            return "InvalidToken"
        # 移除填充信息
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded = unpadder.update(plaintext_padded)
        # 可能抛出“填充无效无法被移除”的异常
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            return "InvalidToken"
        # 将以base64编码解密后的密文结果写入文件
        self.fp2.write("ECB:")
        self.fp2.write(base64.urlsafe_b64encode(unpadded).decode())
        self.fp2.write("\n")
        # 解密修改后的密文时会抛出异常
        try:
            plain = unpadded.decode()
        except BaseException:
            return "密文错误"
        if plain is not None:
            return plain

    #-----------------------CBC模式--------------------------
    #初始化
    def CBCinit(self):
        #在modes中选择模式CBC，同时需要参数iv，即初始向量，使用os.urandom(16)生成
        cipher_suite = Cipher(algorithms.AES(self.key), modes.CBC(self.iv), backend=self.backend)
        return cipher_suite

    # 加密
    def CBCencrypt(self, data, cipher):
        encryptor = cipher.encryptor()
        # 先填充，再加密
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        ctCBC = base64.urlsafe_b64encode(ct).decode()
        self.txtEnCBC.setText(ctCBC)
        return ct

    # 解密
    def CBCdecrypt(self, ct, dePass, cipher):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=self.salt,
            iterations=100000,
            backend=self.backend
        )
        # 验证解密密钥是否正确，如果和加密密钥不匹配，会抛出异常
        try:
            kdf.verify(dePass.encode(), self.key)
        except Exception as e:
            res = "密钥错误！"
            return res
        decryptor = cipher.decryptor()
        # 这里获得的明文是填充后的
        plaintext_padded = decryptor.update(ct)
        # 可能抛出“数据长度无效”的异常
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            return "InvalidToken"
        # 移除填充信息
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded = unpadder.update(plaintext_padded)
        # 可能抛出“填充无效无法被移除”的异常
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            return "InvalidToken"
        # 将以base64编码解密后的密文结果写入文件
        self.fp2.write("CBC:")
        self.fp2.write(base64.urlsafe_b64encode(unpadded).decode())
        self.fp2.write("\n")
        # 解密修改后的密文时会抛出异常
        try:
            plain = unpadded.decode()
        except BaseException:
            return "密文错误"
        if plain is not None:
            return plain

    #-----------------------CFB模式---------------------------
    #初始化
    def CFBinit(self):
        #在modes中选择模式CFB，同时需要参数iv，即初始向量，使用os.urandom(16)生成
        cipher_suite = Cipher(algorithms.AES(self.key), modes.CFB(self.iv), backend=self.backend)
        return cipher_suite

    #加密
    def CFBencrypt(self, data, cipher):
        encryptor = cipher.encryptor()
        #先填充，再加密
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        ctCFB = base64.urlsafe_b64encode(ct).decode()
        self.txtEnCFB.setText(ctCFB)
        return ct

    #解密
    def CFBdecrypt(self, ct, dePass, cipher):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=self.salt,
            iterations=100000,
            backend=self.backend
        )
        #验证解密密钥是否正确，如果和加密密钥不匹配，会抛出异常
        try:
            kdf.verify(dePass.encode(), self.key)
        except Exception as e:
            res = "密钥错误！"
            return res
        decryptor = cipher.decryptor()
        #这里获得的明文是填充后的
        plaintext_padded = decryptor.update(ct)
        #可能抛出“数据长度无效”的异常
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            return "InvalidToken"
        #移除填充信息
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded = unpadder.update(plaintext_padded)
        #可能抛出“填充无效无法被移除”的异常
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            return "InvalidToken"
        # 将以base64编码解密后的密文结果写入文件
        self.fp2.write("CFB:")
        self.fp2.write(base64.urlsafe_b64encode(unpadded).decode())
        self.fp2.write("\n")
        # 解密修改后的密文时会抛出异常
        try:
            plain = unpadded.decode()
        except BaseException:
            return "密文错误"
        if plain is not None:
            return plain

    #-----------------------OFB模式---------------------------
    #初始化
    def OFBinit(self):
        #在modes中选择模式OFB，同时需要参数iv，即初始向量，使用os.urandom(16)生成
        cipher_suite = Cipher(algorithms.AES(self.key), modes.OFB(self.iv), backend=self.backend)
        return cipher_suite

    #加密
    def OFBencrypt(self, data, cipher):
        encryptor = cipher.encryptor()
        #先填充，再加密
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        ctOFB = base64.urlsafe_b64encode(ct).decode()
        self.txtEnOFB.setText(ctOFB)
        return ct

    #解密
    def OFBdecrypt(self, ct, dePass, cipher):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=self.salt,
            iterations=100000,
            backend=self.backend
        )
        #验证解密密钥是否正确，如果和加密密钥不匹配，会抛出异常
        try:
            kdf.verify(dePass.encode(), self.key)
        except Exception as e:
            res = "密钥错误！"
            return res
        decryptor = cipher.decryptor()
        #这里获得的明文是填充后的
        plaintext_padded = decryptor.update(ct)
        #可能抛出“数据长度无效”的异常
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            return "InvalidToken"
        #移除填充信息
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded = unpadder.update(plaintext_padded)
        #可能抛出“填充无效无法被移除”的异常
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            return "InvalidToken"
        # 将以base64编码解密后的密文结果写入文件
        self.fp2.write("OFB:")
        self.fp2.write(base64.urlsafe_b64encode(unpadded).decode())
        self.fp2.write("\n")
        # 解密修改后的密文时会抛出异常
        try:
            plain = unpadded.decode()
        except BaseException:
            return "密文错误"
        if plain is not None:
            return plain

    #-----------------------CTR模式---------------------------
    #初始化
    def CTRinit(self):
        #在modes中选择模式CTR，同时需要一个16字节的nonce，使用os.urandom(16)生成
        cipher_suite = Cipher(algorithms.AES(self.key), modes.CTR(self.iv), backend=self.backend)
        return cipher_suite

    #加密
    def CTRencrypt(self, data, cipher):
        encryptor = cipher.encryptor()
        #先填充，再加密
        padder = padding.PKCS7(algorithms.AES.block_size).padder()
        padded_data = padder.update(data) + padder.finalize()
        ct = encryptor.update(padded_data) + encryptor.finalize()
        ctCTR = base64.urlsafe_b64encode(ct).decode()
        self.txtEnCTR.setText(ctCTR)
        return ct

    #解密
    def CTRdecrypt(self, ct, dePass, cipher):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=16,
            salt=self.salt,
            iterations=100000,
            backend=self.backend
        )
        #验证解密密钥是否正确，如果和加密密钥不匹配，会抛出异常
        try:
            kdf.verify(dePass.encode(), self.key)
        except Exception as e:
            res = "密钥错误！"
            return res
        decryptor = cipher.decryptor()
        #这里获得的明文是填充后的
        plaintext_padded = decryptor.update(ct)
        #可能抛出“数据长度无效”的异常
        try:
            plaintext_padded += decryptor.finalize()
        except ValueError:
            return "InvalidToken"
        #移除填充信息
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        unpadded = unpadder.update(plaintext_padded)
        #可能抛出“填充无效无法被移除”的异常
        try:
            unpadded += unpadder.finalize()
        except ValueError:
            return "InvalidToken"
        # 将以base64编码解密后的密文结果写入文件
        self.fp2.write("CTR:")
        self.fp2.write(base64.urlsafe_b64encode(unpadded).decode())
        self.fp2.write("\n")
        # 解密修改后的密文时会抛出异常
        try:
            plain = unpadded.decode()
        except BaseException:
            return "密文错误"
        if plain is not None:
            return plain

if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    MainWindow = QtWidgets.QMainWindow()
    ui = Ui_MainWindow()
    ui.setupUi(MainWindow)
    MainWindow.show()
    sys.exit(app.exec_())
