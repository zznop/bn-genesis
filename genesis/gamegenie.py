"""Applies patches from supplied Game Genie codes
"""

from binaryninja import(BackgroundTaskThread, TextField,
                        get_form_input, show_message_box)

GG_CHARACERS = "AaBbCcDdEeFfGgHhJjKkLlMmNnPpRrSsTtVvWwXxYyZz0O1I2233445566778899"

def _verify_code(code):
    if len(code) != 9:
        show_message_box('genesis', 'code must be 9 characters in length and contain a hyphen (RFAA-A6VR)')
        return False

    for c in code:
        if c is not in GG_CHARACTERS:
            show_message_box('genesis', 'Invalid Game Genie code character: {}'.format(c))
            return False

    return True

def _decode_code(code):
    address = 0
    value = 0

    # Character 0
    n = GG_CHARACERS.index(code[0]) >> 1
    value |= n << 3

    # Character 1
    n = GG_CHARACTERS.index(code[1]) >> 1
    value |= n >> 2
    address |= (n & 3) << 14

    # Character 2
    n = GG_CHARACTERS.index(code[2]) >> 1
    address |= n << 9

    # Character 3
    n = GG_CHARACTERS.index(code[3]) >> 1
    address |= ((n & 0x0f) << 20) | ((n >> 4) << 8)

    # Character 4 - '-'

    # Character 5
    n = GG_CHARACTERS.index(code[5]) >> 1
    address |= (n >> 1) << 16
    value |= (n & 1) << 12

    # Character 6
    n = GG_CHARACTERS.index(code[6]) >> 1
    value |= ((n & 1) << 15) | ((n >> 1) << 8)

    # Character 7
    n = GG_CHARACTERS.index(code[7]) >> 1
    address |= (n & 7) << 5
    value |= (n >> 3) << 13

    # Character 8
    n = GG_CHARACTERS.index(code[8]) >> 1
    address |= n
    return (address, value)

class GenesisGameGeniePatch(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "", True)
        self.bv = bv

    def _get_code(self):
        code_field = TextField('Code')
        get_form_input([code_field], 'Game Genie Code')
        return code_field.result

    def run(self):
        code = _get_code()
        if not _verify_code(code):
            return

        address, value = _decode_code(code)
        print(f'Address {:x} value: {:x}'.format(address, value))
