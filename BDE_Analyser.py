
"""
Description: Binary Data Extract (BDE) Analyser
Version: 1.0
Author: ICT2202 DEL_SYS32
Purpose: This too is used to analyse a chunk of raw binary data extracted from filesystem, and identify the unfragmented file(s) present inside
"""


import os
import json
import glob
import binascii
import shutil

level3bool = False
stringonce = "FINAL VERDICT: 00"
stringonce2 = "FINAL VERDICT: 00"

dir_path = os.path.dirname(os.path.realpath(__file__))
for root, dirs, files in os.walk(dir_path+ '/temp/'):
    for f in files:
        os.unlink(os.path.join(root, f))
    for d in dirs:
        shutil.rmtree(os.path.join(root, d))
for root, dirs, files in os.walk(dir_path+ '/recovered/'):
    for f in files:
        os.unlink(os.path.join(root, f))
    for d in dirs:
        shutil.rmtree(os.path.join(root, d))

with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "data.json")) as data_file:
    data = json.loads(data_file.read())

probbaseline = 0.0
for x in range(len(data)):
    for y in range(len(data[x]["signature"])):
        if (len(data[x]["signature"][y]) > probbaseline):
            probbaseline = len(data[x]["signature"][y])


class Info:
    """
    Generates object with given arguments
    """

    def __init__(self, type_, extension, mime):
        self.type = type_
        self.extension = extension
        self.mime = mime

    def type_matches(self, type_):
        """ Checks if file type matches with given type """
        return type_ in self.type

    def extension_matches(self, extension):
        """ Checks if file extension matches with given extension """
        return extension in self.extension

    def mime_matches(self, mime):
        """ Checks if file MIME type matches with given MIME type """
        return mime in self.mime


def get(obj):
    """
    level 1 test
    """

    if not isinstance(obj, bytes):
        raise TypeError("object type must be bytes")

    info = {
        "type": dict(),
        "extension": dict(),
        "mime": dict()
    }

    stream = " ".join(['{:02X}'.format(byte) for byte in obj])

    for element in data:
        for signature in element["signature"]:
            offset = element["offset"] * 2 + element["offset"]
            if signature == stream[offset:len(signature) + offset]:
                for key in ["type", "extension", "mime"]:
                    info[key][element[key]] = len(signature)

    for key in ["type", "extension", "mime"]:
        info[key] = [element for element in sorted(info[key], key=info[key].get, reverse=True)]

    return Info(info["type"], info["extension"], info["mime"])

def get2(obj):
    """
    level 2 test
    """

    if not isinstance(obj, bytes):
        raise TypeError("object type must be bytes")

    info = {
        "type": dict(),
        "extension": dict(),
        "mime": dict()
    }


    stream = " ".join(['{:02X}'.format(byte) for byte in obj])
    fakestream = " ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ ZZ"
    stream2 = stream + fakestream

    streamsep = "".join(['{:02X}'.format(byte) for byte in obj])

    with open("hexdump", 'w') as file:
        file.write(stream)
    comparer = int(0)

    for x in range(len(streamsep)//2):
        for element in data:
            for signature in element["signature"]:
                offset = x * 2 + x
                if signature == stream2[offset:len(signature) + offset]:
                    for key in ["type", "extension", "mime"]:
                        info[key][element[key]] = len(signature)
                    global stringonce
                    global stringonce2
                    if ((element["extension"] == 'gif')or(element["extension"] == 'png')):
                        if (int(stringonce[15:17]) < (int((len(signature) / probbaseline) * 50.0) + int(
                        50.0 - ((x / (len(streamsep) / 2.0)) * 50.0)))):
                            stringonce = "FINAL VERDICT: " + str(int((len(signature) / probbaseline) * 50.0) + int(
                        50.0 - ((x / (len(streamsep) / 2.0)) * 50.0))) + "% CHANCE OF BEING " + str(element["extension"]) + ", DETECTED AT POSITION " + str(
                        offset) + " OF HEXDUMP"
                        print(str(element["extension"]) + " detected at position " + str(offset) + " of hexdump (Probability " + str(((len(signature)/probbaseline)*50.0)+(50.0-((x/(len(streamsep)/2.0))*50.0))) + "%, level 3 test eligible)")
                        global level3bool
                        level3bool = True
                        streamtemp1 = stream2[offset:]
                        with open("temp/" + question2 + str(x) + "." + element["extension"] + ".bdeanalyser", 'w') as file3:
                            file3.write(streamtemp1)
                    else:
                        if (int(stringonce[15:17]) < (int((len(signature) / probbaseline) * 50.0) + int(
                        50.0 - ((x / (len(streamsep) / 2.0)) * 50.0)))):
                            stringonce = "FINAL VERDICT: " + str(int((len(signature) / probbaseline) * 50.0) + int(
                        50.0 - ((x / (len(streamsep) / 2.0)) * 50.0))) + "% CHANCE OF BEING " + str(element["extension"]) + ", DETECTED AT POSITION " + str(
                        offset) + " OF HEXDUMP"
                        if (int(stringonce2[15:17]) < (int((len(signature) / probbaseline) * 50.0) + int(
                        50.0 - ((x / (len(streamsep) / 2.0)) * 50.0)))):
                            stringonce2 = "FINAL VERDICT: " + str(int((len(signature) / probbaseline) * 50.0) + int(
                        50.0 - ((x / (len(streamsep) / 2.0)) * 50.0))) + "% CHANCE OF BEING " + str(element["extension"]) + ", DETECTED AT POSITION " + str(
                        offset) + " OF HEXDUMP"

                        print(str(element["extension"]) + " detected at position " + str(
                        offset) + " of hexdump (Probability " + str(((len(signature) / probbaseline) * 50.0) + (
                        50.0 - ((x / (len(streamsep) / 2.0)) * 50.0))) + "%)")

        if (x>0):
            if (comparer != int(x/(len(streamsep)//2)*100)):
                if (int(x/(len(streamsep)//2)*100)%5 == 0):
                    print(str(int(x/(len(streamsep)//2)*100)) + "% scanned")
                comparer = int(x/(len(streamsep)//2)*100)
        else:
            print("0% scanned")
    for key in ["type", "extension", "mime"]:
        info[key] = [element for element in sorted(info[key], key=info[key].get, reverse=True)]

    return Info(info["type"], info["extension"], info["mime"])


def supported_types():
    """ Returns a list of supported file types """
    return sorted(set([x["type"] for x in data]))


def supported_extensions():
    """ Returns a list of supported file extensions """
    return sorted(set([x["extension"] for x in data]))


def supported_mimes():
    """ Returns a list of supported file MIME types """
    return sorted(set([x["mime"] for x in data]))




question2 = ""
while True:
    try:
        question2 = input('\nEnter filename of chunk:\n\n')
        with open(question2, "rb") as file:
            info = get(file.read(128))
        break
    except:
        print("\nBad input. Try again.")

print("\nRunning level 1 test.")
if len(info.extension) == 0:
    print("\nLevel 1 test failed.\n")
else:
    print("\nLevel 1 test passed.\n")
while True:
    try:
        question = input('Do you want to run level 2 test?\n\n')
        if question=="yes":
            print("\nRunning level 2 test.\n")
            with open(question2, "rb") as file2:
                info2 = get2(file2.read())
                if len(info2.extension) == 0:
                    print("100% scanned\n\nLevel 2 test failed.\n\nFINAL VERDICT: CHUNK HAS NO VALID FILE(S)")
                else:
                    print("100% scanned\n\nLevel 2 test encountered the possibilities: " + str(info2.extension))
                    if level3bool == True:
                        print("\nOne or more detections are eligible for level 3 test.")
                        while True:
                            try:
                                question = input(
                                    '\nDo you want to run level 3 test?\n\n')
                                if question == "yes":
                                    lvl3fl = True
                                    for filepath in glob.iglob(dir_path + '/temp/*.bdeanalyser'):
                                        data = ""
                                        if (filepath.split(".")[-2] == "png"):
                                            with open(filepath, 'rt') as file:
                                                data = file.read()
                                            if " 49 45 4E 44 AE 42 60 82" in data:
                                                lvl3fl = False
                                                data2 = ""
                                                for x in range(len(data.split(" 49 45 4E 44 AE 42 60 82"))):
                                                    data2 = data2 + data.split(" 49 45 4E 44 AE 42 60 82")[x] + " 49 45 4E 44 AE 42 60 82"
                                                    globals()['variable{}'.format(x)] = data2
                                                i = 0
                                                while True:
                                                    try:
                                                        if (globals()['variable{}'.format(i)] != None):
                                                            data3 = globals()['variable{}'.format(i)]
                                                            data3 = data3.strip()
                                                            data3 = data3.replace(' ', '')
                                                            data3 = data3.replace('\n', '')
                                                            data3 = data3.replace('Z', '')
                                                            data3 = binascii.a2b_hex(data3)
                                                            with open(dir_path + "/recovered" +
                                                                      filepath.split(".bdeanalyser")[0].split(dir_path)[
                                                                          1].split("/temp")[1] + "." + str(i) + ".png", 'wb') as file:
                                                                file.write(data3)
                                                        i = i + 1
                                                    except:
                                                        break
                                                i = 0
                                                while True:
                                                    try:
                                                        if (globals()['variable{}'.format(i)] != None):
                                                            globals()['variable{}'.format(i)] = None
                                                        i = i + 1
                                                    except:
                                                        break
                                        if (filepath.split(".")[-2] == "gif"):
                                            with open(filepath, 'rt') as file:
                                                data = file.read()
                                            if " 00 3B" in data:
                                                lvl3fl = False
                                                data2 = ""
                                                for x in range(len(data.split(" 00 3B"))):
                                                    data2 = data2 + data.split(" 00 3B")[x] + " 00 3B"
                                                    globals()['variable{}'.format(x)] = data2
                                                i = 0
                                                while True:
                                                    try:
                                                        if (globals()['variable{}'.format(i)] != None):
                                                            data3 = globals()['variable{}'.format(i)]
                                                            data3 = data3.strip()
                                                            data3 = data3.replace(' ', '')
                                                            data3 = data3.replace('\n', '')
                                                            data3 = data3.replace('Z', '')
                                                            data3 = binascii.a2b_hex(data3)
                                                            with open(dir_path + "/recovered" +
                                                                      filepath.split(".bdeanalyser")[0].split(dir_path)[
                                                                          1].split("/temp")[1] + "." + str(i) + ".gif", 'wb') as file:
                                                                file.write(data3)
                                                        i = i + 1
                                                    except:
                                                        break
                                                i = 0
                                                while True:
                                                    try:
                                                        if (globals()['variable{}'.format(i)] != None):
                                                            globals()['variable{}'.format(i)] = None
                                                        i = i + 1
                                                    except:
                                                        break

                                    if (lvl3fl == False):
                                        print("\nLevel 3 test passed.\n\nFINAL VERDICT:\n")
                                        for filepath2 in glob.iglob(dir_path + '/recovered/*.*'):
                                            print("100% CHANCE OF BEING " + filepath2.split("\\")[-1].replace(question2, '').split(".")[1] + ", DETECTED AT POSITION " + filepath2.split("\\")[-1].replace(question2, '').split(".")[0] + " OF HEXDUMP (RECOVERED CANDIDATE "+filepath2.split("\\")[-1].replace(question2, '').split(".")[2]+")\n")
                                    else:
                                        if (stringonce2 != "FINAL VERDICT: 00"):
                                            print("\nLevel 3 test failed.\n\n" + stringonce2)
                                        else:
                                            print("\nLevel 3 test failed.\n\nFINAL VERDICT: CHUNK HAS NO VALID FILE(S)")
                                    break
                                elif question == "no":
                                    print("\n"+ stringonce)
                                    break
                                else:
                                    raise Exception('Didnt get a "yes" no "no" response. Try again.')

                            except:
                                print("\nDidnt get a \"yes\" no \"no\" response. Try again.")
                    else:
                        print("\n" + stringonce + "\n\n")
            break
        elif question=="no":
            if len(info.extension) == 0:
                print("\nFINAL VERDICT: UNKNOWN AS OF LEVEL 1 TEST")
            else:
                print("\nFINAL VERDICT: VARYING CHANCE OF BEING: " + str(info.extension) + ", DETECTED AT POSITION 0 OF CHUNK")
            break
        else:
            raise Exception('Didnt get a "yes" no "no" response. Try again.')
    except:
        print("\nDidnt get a \"yes\" no \"no\" response. Try again.\n")


