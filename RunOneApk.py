# -*- coding: utf-8 -*-
from __future__ import print_function
__author__ = 'xuyn'

import sys
import os
from androguard.core.bytecodes import apk
from androguard.core.analysis import risk
from androguard.misc import *

ri = risk.RiskIndicator()
ri.add_risk_analysis(risk.RedFlags())
ri.add_risk_analysis(risk.FuzzyRisk())

def getAPKandroguardSecureInfo(apkfile, dex, output):
    if os.path.exists(apkfile):
        a = apk.APK(apkfile)
        res = ri.with_apk(a)
        with open(output, "a") as out:
            for i in res:
                print ("\t", i, file=out)
                for j in res[i]:
                    print ("\t\t", j, res[i][j], file=out)
    else:
        print (apkfile, "not exists")


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print("Usage: ./RunOnApk.py APK.apk OUTPUTDIR")
        sys.exit(1)

    apkFile = sys.argv[1]
    outputDir = sys.argv[2]
    if not os.path.exists(apkFile):
        print("无效的路径"+apkFile)
        sys.exit(1)

    if os.path.exists(outputDir):
        print("输出路径"+outputDir+"已经存在")
        sys.exit(1)
    # 创建目录
    os.makedirs(outputDir)
    # 解压zip
    os.system("unzip "+apkFile + " -d "+outputDir)

    osana = outputDir+"/"+"osAnalysis"

    # 反汇编
    smaliout = osana+"/"+"baksmaliout"
    if not os.path.exists(smaliout):
        try:
            os.system("java -jar baksmali-2.0.3.jar "+outputDir+"/classes.dex "+ "-o " + smaliout)
        except:
            print(outputDir+" classes.dex error")

    output = osana+"/"+"androguard_output"
    dexpath = outputDir+"/"+"classes.dex"
    try:
        # 跑androguard.risk
        getAPKandroguardSecureInfo(apkFile, dexpath, output)
    except:
        print ("error ---------------- " + apkFile)
    else:
        print ("no error ------------- " + apkFile)

    webInfoDir = outputDir+"/osAnalysis/webInfo/"
    if not os.path.exists(webInfoDir):
        os.makedirs(webInfoDir)

    print("python ApkWebInfo.py 1 "+ apkFile + " > "+osana+"/androlyzeResult")
    os.system("python ApkWebInfo.py 1 "+ apkFile + " > "+osana+"/androlyzeResult")
    print("python ApkWebInfo.py 2 "+ apkFile + " > "+osana+"/webInfo/basicinfo")
    os.system("python ApkWebInfo.py 2 "+ apkFile + " > "+osana+"/webInfo/basicinfo")
    print("python JsonDecoder.py "+ outputDir + " > " +osana+"/webInfo/jsonInfo")
    os.system("python JsonDecoder.py "+ outputDir + " > " +osana+"/webInfo/jsonInfo")
