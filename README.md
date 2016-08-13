# MacroInspector

A tool for analyzing dynamically the execution of macros in WORD documents.

### Description

The aim of the project is to assist malware analysts during the analysis of malicious Office documents. Very often malwares use macros to execute malicious code. Just by dumping statically the macro is not always enough, in fact 
it is common for malware to hide important information not directly in the macro source. With Macro Inspector you will be able to:

* Dump the source of all executed macros
* Dump all the referenced strings allocated during the macro execution
* Dump possible executables that are embedded in the document (done by string inspection)

### Usage

The usage is deadly simple, just run: **python macro_inspecto.py** that's all :) It will loop until a new WINWORD process is found. Now you have to just open the malicious document, enable the macro and then close the document (this will ensure that events that are triggered on the closing document are executed).

### Dependencies

In order to run the program you need to have the WinAppDbg library installed.

### Limitations

The project was created by considering Microsoft WORD 2013. On different Word versions it could be necessary to adjust the address offset.
