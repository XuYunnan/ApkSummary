# -*- coding: utf-8 -*-
__author__ = 'xuyn'

import os
import json
import sys

def genJSON(androlyze, androrisk, aapt):
    file1 = open(androlyze)
    file2 = open(androrisk)
    file3 = open(aapt)

    DICT = {} # target dict
    USEAPI = []
    PERM = []
    NAME = ""
    VERSIONCODE = ""
    VERSIONNAME = ""
    APPLEBLE = ""
    SDKV = ""
    TARGETV = ""
    FUZZYRESULT = ""

    reach = 0
    while 1:
        line = file1.readline()
        if not line:
            break
        if line.startswith("==================="):
            reach = 1
        if reach == 1:
            if line.find(" :") != -1:
                #print line[:-3]
                USEAPI.append(line[:-3])

    line = file3.readline()
    names = line.find("'")
    namee = line.find("'", names+1)
    #print line[names+1:namee]
    NAME = line[names+1:namee]

    vcodes = line.find("'",namee+1)
    vcodee = line.find("'",vcodes+1)
    #print line[vcodes+1:vcodee]
    VERSIONCODE = line[vcodes+1:vcodee]

    vnames = line.find("'", vcodee+1)
    vnamee = line.find("'", vnames+1)
    #print line[vnames+1:vnamee]
    VERSIONNAME = line[vnames+1:vnamee]

    file3 = open(aapt)
    while 1:
        line = file3.readline()
        if not line:
            break
        if line.startswith("uses-permission"):
            #print line[17:-2]
            PERM.append(line[17:-2])
        if line.startswith("sdkVersion"):
            #print line[12:-2]
            SDKV = line[12:-2]
        if line.startswith("targetSdkVersion"):
            #print line[18:-2]
            TARGETV = line[18:-2]
        if line.startswith("application-label"):
            #print line[19:-2]
            APPLEBLE = line[19:-2]

    str1 = ""
    str2 = ""
    str3 = ""
    line = file2.readline()
    line = file2.readline()
    s = line.find("DEX ")

    str1 += line[s+4:-1]
    line = file2.readline()
    s = line.find("APK ")

    str2 += line[s+4:-1]
    line = file2.readline()
    s = line.find("PERM ")

    str3 += line[s+5:-1]
    line = file2.readline()
    line = file2.readline()
    s = line.find("VALUE")
    #print line[s+6:-1]
    FUZZYRESULT = line[s+6:-1]

    DICT['name'] = NAME
    DICT['versionCode'] = VERSIONCODE
    DICT['versionName'] = VERSIONNAME
    DICT['sdkVersion'] = SDKV
    DICT['targetVersion'] = TARGETV
    DICT['apply-perm'] = PERM
    DICT['use-priv-api'] = USEAPI
    DICT['fuzzyRisk'] = FUZZYRESULT
    DICT['applable'] = APPLEBLE
    #print "=============="
    DICT['dex'] = eval(str1)
    DICT['apk'] = eval(str2)
    DICT['perm'] = eval(str3)

    #print DICT
    jsonDumpsIndentStr = json.dumps(DICT, ensure_ascii=False, indent=2)
    #jsonDumpsIndentStr = json.dumps(DICT, indent=1)
    print jsonDumpsIndentStr

def execgenJSON(dir):
    genJSON(dir+"/osAnalysis/androlyzeResult",
            dir+"/osAnalysis/androguard_output",
            dir+"/osAnalysis/webInfo/basicinfo")

if __name__ == "__main__":
    execgenJSON(sys.argv[1])