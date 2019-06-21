import os
import shutil

from setuptools import setup

import setuptools.command.install as install
from distutils.errors import DistutilsArgError
from distutils import log

class CustomInstallCommand(install.install):
    user_options = install.install.user_options + [
        ('install-ida-plugin=', None, 'Install plugin in this IDA installation directory, empty arg defaults to IDAUSR directory'),
    ]
    def initialize_options(self):
        self.install_ida_plugin = None
        install.install.initialize_options(self)
    def run(self):
        path = None
        if self.install_ida_plugin is not None:
            base = None
            if self.install_ida_plugin == '':
                # Try IDAUSR first
                base = os.getenv("IDAUSR")
                if base is None:
                    # Use default from IDA docs
                    base = os.getenv("APPDATA")
                    if base is not None:
                        base = os.path.join(base, 'Hex-Rays', 'IDA Pro')
            else:
                base = self.install_ida_plugin
            if base and os.path.exists(base):
                path = os.path.join(base, 'plugins')
            if path is None:
                raise DistutilsArgError("Unable to locate IDA installation, pleasy specify")

        install.install.do_egg_install(self)
        # Install plugin
        if path is not None:
            log.info("Installing IDA plugin to: {}".format(path))
            if not os.path.exists(path):
                os.makedirs(path)
            plugin_file = 'annotate_lineinfo_plugin.py'
            shutil.copyfile(plugin_file, os.path.join(path, plugin_file))

with open("README.md", "r") as f:
    long_desc = f.read()

setup(
    name='annotate_lineinfo',
    version='0.1',
    description='Annotate IDA with source and line number information from a PDB',
    long_description=long_desc,
    long_description_content_type="text/markdown",
    url='https://github.com/clarkb7/annotate_lineinfo',
    license='MIT',

    author='Branden Clark',
    author_email='clark@rpis.ec',

    classifiers=[
        'Development Status :: 3 - Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Operating System :: Microsoft :: Windows',
        'Programming Language :: Python',
        'Topic :: Security',
        'Topic :: Software Development :: Disassemblers',
    ],
    keywords='IDA IDAPython PDB',

    packages=['annotate_lineinfo'],
    py_modules=['annotate_lineinfo_plugin'],
    install_requires=['comtypes'],

    cmdclass={
        'install': CustomInstallCommand,
    },
)
