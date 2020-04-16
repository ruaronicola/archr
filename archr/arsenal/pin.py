import contextlib
import logging
import tempfile
import subprocess
import os

from . import ContextBow

l = logging.getLogger("archr.arsenal.pin")

class PINTracerBow(ContextBow):
    """
    Launches a process under PIN
    """

    REQUIRED_ARROW = "pin"

    @contextlib.contextmanager
    def fire_context(self, args_prefix=None, basic_blocks=True, calls=False, syscalls=False, main_object_only=False, **kwargs): #pylint:disable=arguments-differ
        """
        Starts PIN with a fresh process.

        :param args_prefix: Additional prefix arguments to run_command
        :param basic_blocks: Trace BBL
        :param syscalls: Trace syscalls
        :param main_object_only: Trace BBL addresses only in the main object
        :param kwargs: Additional arguments to run_command
        :return: Target instance returned by run_command
        """

        # sysctl -w kernel.randomize_va_space=0
        
        if self.target.target_arch == 'x86_64':
            build_name = 'intel64'
        elif self.target.target_arch == 'i386':
            build_name = 'ia32'
        else: raise ArchrError(f'Arch {self.target.target_arch} not supported!')

        outfile = os.path.join(self.target.tmpwd, 'trace.out')
        bbl_tracer = os.path.join(self.target.tmpwd, f'pin/source/tools/bbl_tracer/obj-{build_name}/bbl_tracer.so')
        self.target.run_command(["touch", outfile]).wait()

        fire_path = os.path.join(self.target.tmpwd, "pin", "fire")

        args_prefix = (args_prefix or []) + [fire_path] + ['-t', bbl_tracer, '-o', outfile]
        args_prefix += ['-b'] if basic_blocks else []
        args_prefix += ['-c'] if calls else []
        args_prefix += ['-s'] if syscalls else []
        args_prefix += ['-m'] if main_object_only else []
        args_prefix += ['--']

        with self.target.flight_context(args_prefix=args_prefix, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, **kwargs) as flight:
            yield flight

        with open(outfile, 'r') as f:
            flight.result = f.read()

from ..errors import ArchrError
