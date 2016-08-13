from winappdbg import Debug, EventHandler, System
import re
import os
import logging
import sys
import struct
import binascii
from datetime import datetime

__description__ = 'WORD Macro Inspector'
__author__ = "Antonio Parata"
__version__ = '1.0'

_dumped_macro = None
_is_in_metadata = True
_freed_strings = list()

# configure logging
log_format = "[%(asctime)s] %(levelname)s - %(message)s"
logging.basicConfig(format=log_format, datefmt='%m/%d/%Y %I:%M:%S', level=logging.INFO, filename='macro_inspector.log')
logging.getLogger().addHandler(logging.StreamHandler())


def _generate_filename():
    global _dumped_macro
    today = datetime.today()
    _dumped_macro = "%d%d%d%d%d%d.vbs" % (today.year, today.month, today.day, today.hour, today.minute, today.second)
    logging.info("Created dumped macro file: %s" % _dumped_macro)


def _check_for_new_script(src_line):
    global _is_in_metadata, _dumped_macro

    if not _dumped_macro:
        _generate_filename()

    attribute = "Attribute"
    if src_line[0:len(attribute)] == attribute:
        if not _is_in_metadata:
            _is_in_metadata = True
            _generate_filename()
    else:
        _is_in_metadata = False


def _write_line(src_line):
    _check_for_new_script(src_line)

    with open(_dumped_macro, 'a') as macro_file:
        macro_file.write(src_line)
        macro_file.write("\n")


def _read_script_source(event):
    global _dumped_macro
    process = event.get_process()
    process.suspend()
    registers = event.get_thread().get_context()
    edx = registers['Edx']
    src_line = process.peek_string(edx, fUnicode=False)
    _write_line(src_line)
    process.resume()


def _check_for_PE_file(raw_string_content):
    if len(raw_string_content) > 97:
        string_content = raw_string_content

        if raw_string_content[0:4] == '4d5a':
            # sometimes the strings is not correctl dumped, it needs more testing
            if not len(raw_string_content) % 2 == 0:
                raw_string_content += '0'
            string_content = binascii.unhexlify(raw_string_content)

        if string_content[0:2] == 'MZ':
            offset = struct.unpack('<I', string_content[0x3c:0x3c + 4])[0]
            if len(string_content) > offset + 2 and string_content[offset:offset+2] == 'PE':
                today = datetime.today()
                filename = "%d%d%d%d%d%d.bin" % (today.year, today.month, today.day, today.hour, today.minute, today.second)
                logging.info("Write possible PE file: %s" % filename)
                with open(filename, 'w') as f:
                    f.write(string_content)


def _read_freed_strings(event, ra, bstrString):
    try:
        process = event.get_process()
        if bstrString:
            freed_string = process.peek_string(bstrString, fUnicode=True)
            if len(freed_string) > 5 and freed_string not in _freed_strings:
                _freed_strings.append(freed_string)
                logging.info("String: %s" % freed_string)
                _check_for_PE_file(freed_string)
    except:
        pass


class ScriptExecutionMonitorEventHandler(EventHandler):
    def load_dll(self, event):
        module = event.get_module()

        if module.match_name("VBE7.dll"):
            process = event.get_process()
            process.suspend()

            """
            Interested instructions
            E8 30070000   CALL 7024428B
            8BF0          MOV ESI,EAX
            81FE C4880A80 CMP ESI,800A88C4
            0F84 CD000000 JE 70243C36
            81FE 0D9D0A80 CMP ESI,800A9D0D
            """

            # Don't use search_hexa becasue seems to have a bug in the implementation: https://github.com/MarioVilas/winappdbg/issues/11
            file_size = os.path.getsize(module.get_filename())
            module_buffer = process.peek(module.get_base(), module.get_base() + file_size)
            pattern = "\x8B\xF0\x81\xFE\xC4\x88\x0A\x80\x0F\x84....\x81\xFE\x0D\x9D\x0A\x80"
            m = re.search(pattern, module_buffer)
            if m:
                address = module.get_base() + m.start()
                logging.info("Set VBE7 breakpoint at: %s" % hex(address))
                event.debug.break_at(event.get_pid(), address, _read_script_source)
            else:
                logging.error("Unable to identify interesting VBE7 opcode, maybe an unsupported Microsoft Word Version?")

            process.resume()

        elif module.match_name("OLEAUT32.dll"):
            process = event.get_process()
            process.suspend()

            address = module.resolve("SysFreeString")
            event.debug.hook_function(process.get_pid(), address, _read_freed_strings, paramCount=1)
            logging.info("Hooked SysFreeString function, address: %s" % hex(address))

            process.resume()


def simple_debugger(argv):
    with Debug(ScriptExecutionMonitorEventHandler(), bKillOnExit=False) as debug:
        if len(argv) == 0:
            attached = False
            logging.info("Try to attach to WINWORD.EXE...")
            while not attached:
                for process in System():
                    filename = process.get_filename()
                    if filename and "WINWORD.EXE" in filename:
                        logging.info("Attaching to: %s (%d)" % (filename, process.get_pid()))
                        debug.attach(process.get_pid())
                        attached = True

            if attached:
                debug.loop()
            else:
                logging.error("Unabel to find a WINWORD.exe process")
        elif argv[0].isdigit():
            # attach via PID
            pid = int(argv[0])
            debug.attach(pid)
            logging.info("Attaching to: %d" % pid)
            debug.loop()
        else:
            logging.error("Usage: %s [PID]" % sys.argv[0])

if __name__ == "__main__":
    print("Macro Inspector - (C) %d Antonio Parata\n" % datetime.today().year)
    simple_debugger(sys.argv[1:])
    logging.info("Inspection completed, log saved to macro_inspector.log")
