# BDE_Analyser
BDE_Analyser v1.0



Description:
Binary Data Extract (BDE) Analyser



Version:
1.0



Author:
ICT2202 DEL_SYS32



Purpose:
This tool is used to analyse a chunk of raw binary data extracted from filesystem, and identify the filetype of unfragmented file(s) present inside, and even carve it/them out if supported filetype(s)



Recommended System Configuration:

The coding did not use any OS-specific libraries or features, so it should most likely be cross-platform, but that has not been tested yet. So, for now, kindly follow the recommended system configuration.

-Windows 10 x64 (https://www.microsoft.com/en-us/store/b/windows)

-Python 3.7.2 (https://www.python.org/downloads/release/python-372/)

-Intel i5(5th Gen) or better



Optional additional softwares:

-HxD (https://mh-nexus.de/en/hxd/)

-Linux's file command ported to windows (http://gnuwin32.sourceforge.net/packages/file.htm)



Usage instructions:

-This program runs on python console. So, if the user has python 3.7.2 installed on their Windows 10 x64 machine, they can just type "python .\BDE_Analyser.py" in Windows Powershell once navigated to the project directory

-The program does not need any parameters to start, as it is an interactive console program

-Follow the instructions on the console prompts, such as typing the name of input file, entering the keybaord sequence to stop or continue, etc

-All files should be in the same folder (project folder)

-There are 15 sample input in the project folder to try with BDE_Analyser – namely testfile01 to testfile14, and cutoffdemo. This will give a rough idea of how it works. 

-If Level 3 tests are successful, the recovered file(s) will be placed in the "recovered" folder

-There may be some temperoary file(s) created in the "temp" folder during operation



Understanding the terminology used in the program:

-Level 1: Very similar to the Linux's file command. Might not work for most complex cases

-Level 2: In depth scanning of chunks. This scan can detect way more than the previous level.

-Level 3: This is the recovery level. If level 3 scans are successful, recovery of file(s) embedded in the chunks will be done. As of the current state, only GIF and PNG files are eligible for Level 3 recovery



Limitations:

-For a level 2 scan, the probability % is assuming the input is a single-file chunk, and the probability % will not be applicable to a multi-file chunk as there is no algorithm in the tool for multi-file chunk probability % at level 2 scan stage.



When to use this program:

-This program is meant as an aid for computer forensics investigation

-If the user suspects that there is/are file(s) from sector x to sector y of an image, he/she can cut out the sector w (conservative start) to sector z (conservative finish)

-Although cutting x to y might work, it may not always be the best idea especially if the user cant identify the filetype. Hence, to avoid any harm to the files, the user can cut conservatively

-This tool will help to identify the file(s) present in the chunk given as input

-Additionally, this tool can also carve out the file(s) from the chunk if they are of supported filetypes (Level 3 eligible), or at the very least this tool will identify, during Level 2 scan, which position of the chunk does the file start.

-The stated positions are relative to the hexdump created by the tool. It can be accessed via the "hexdump" file in the project folder.
