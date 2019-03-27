from setuptools import setup

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
    install_requires=['comtypes', 'argparse'],
)
