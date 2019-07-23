'''Assembles Motorola 68000 code and drops the blob at the specified offset
in the ROM
'''

from binaryninja import *
import tempfile
import shutil
import os
import subprocess

__author__     = 'zznop'
__copyright__  = 'Copyright 2019, zznop'
__license__    = 'GPL'
__version__    = '1.1'
__email__      = 'zznop0x90@gmail.com'

class GenesisAssemble(BackgroundTaskThread):
    def __init__(self, bv):
        BackgroundTaskThread.__init__(self, "", True)
        self.bv = bv
        self.as_path = '/usr/bin/m68k-linux-gnu-as'
        self.ld_path = '/usr/bin/m68k-linux-gnu-ld'
        self.progress = 'genesis: Assembling code...'

    def _get_params(self):
        '''Launch an input box to get start offset for patch and code
        '''
        params = {}
        start_offset_field = AddressField('Start offset for patch (current offset: 0x{:08x})'.format(self.bv.offset),
            view=self.bv, current_address=self.bv.offset)
        code_field = MultilineTextField('Code')
        get_form_input([start_offset_field, code_field], 'Patch Parameters')
        params['start_offset'] = start_offset_field.result
        params['code'] = code_field.result
        return params

    def _assemble_code(self, dirpath):
        '''Assemble patch.S
        '''
        p = subprocess.Popen([self.as_path,'-m68000', '-c', '-a={}/patch.lst'.format(dirpath),
            '{}/patch.S'.format(dirpath), '-o', '{}/patch.o'.format(dirpath)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        (out, err) = p.communicate()
        print(out)
        print(err)
        if not os.path.exists('{}/patch.o'.format(dirpath)):
            return False
        return True

    def _link_code(self, dirpath):
        '''Link patch.o object
        '''
        p = subprocess.Popen([self.ld_path, '-Ttext', '0', '--oformat', 'binary', '-o',
            '{}/patch.bin'.format(dirpath), '{}/patch.o'.format(dirpath)],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        (out, err) = p.communicate()
        print(out)
        print(err)
        if not os.path.exists('{}/patch.bin'.format(dirpath)):
            return False
        return True

    def _assemble_link_extract(self, code):
        '''Write code to tempdir/patch.S and assemble it
        '''
        blob = None
        try:
            template = '.section .text\n' \
                '.globl _start\n\n' \
                '_start:\n' \
                '{}\n'.format(code)

            dirpath = tempfile.mkdtemp()
            print(dirpath)
            with open(dirpath + '/patch.S', 'w+b') as f:
                f.write(template)

            if not self._assemble_code(dirpath):
                raise OSError('Failed to assemble code')

            if not self._link_code(dirpath):
                raise OSError('Failed to link code')

            blob = open('{}/patch.bin'.format(dirpath), 'rb').read()
        except Exception as err:
            show_message_box('genesis', 'Error: {}'.format(err))

        shutil.rmtree(dirpath)
        return blob

    def run(self):
        '''Assemble code and patch offset
        '''
        params = self._get_params()
        blob = self._assemble_link_extract(params['code'])
        if blob is None:
            return

        blob_len = len(blob)
        if blob_len > 0:
            self.bv.write(params['start_offset'], blob)
            show_message_box('genesis', 'Wrote {} bytes beginning at {:08x}'.format(blob_len, params['start_offset']))
        else:
            show_message_box('genesis', 'Patch is 0 bytes in size')

if __name__ == '__main__':
    print('! this plugin does not run headless')
