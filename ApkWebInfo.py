__author__ = 'xuyn'
# -*- coding:utf-8 -*-

import os
import time
import sys
from optparse import OptionParser

from androguard.core import androconf
from androguard.core.bytecodes import apk
from androguard.core.bytecodes import dvm
from androguard.core.analysis import analysis
from androguard.misc import *

APKINFODIR = "/media/50166FBC166FA1A8/Apks_kuan_infoStore/"
APKDIR = "/media/50166FBC166FA1A8/Apks_kuan/"

def getWebInfo(arg):
    a, d, dx = AnalyzeAPK(arg)
    a.show()
    print "==================="
    show_Permissions(dx)

def getBasicInfo(arg):
    os.system("aapt d badging "+arg)

if __name__ == '__main__':
    if sys.argv[1] == '1':
        getWebInfo(sys.argv[2])
    elif sys.argv[1] == '2':
        getBasicInfo(sys.argv[2])