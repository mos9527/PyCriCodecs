from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
import os

ENV_DEBUG = os.environ.get('CRICODECSEX_DEBUG', None)   

CriCodecsEx_sources = ["CriCodecsEx.cpp"]
CriCodecsEx_sources = [os.path.join("CriCodecsEx", source) for source in CriCodecsEx_sources]

class BuildExt(build_ext):
    def build_extensions(self):
        compile_args = []
        link_args = []
        if self.compiler.compiler_type == 'msvc':
            compile_args = ['/std:c++14']
            if ENV_DEBUG:                
                compile_args += ['/Od', '/Zi']
                link_args += ['/DEBUG']
            else:
                compile_args += ['/O2']
        else:
            compile_args = ['-std=c++14']
            if ENV_DEBUG:
                # ASAN on Linux
                # This only works with GCC - you also need to specify 
                # LD_PRELOAD=$(gcc -print-file-name=libasan.so)
                compile_args += ['-O0', '-g', '-fsanitize=address']
            else:
                compile_args += ['-O2']
        for ext in self.extensions:
            ext.extra_compile_args.extend(compile_args)
            ext.extra_link_args.extend(link_args)
        return super().build_extensions()

from PyCriCodecsEx import __version__
setup(
    name="PyCriCodecsEx",
    version=__version__,
    description="Criware formats library for Python",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    url='https://github.com/mos9527/PyCriCodecsEx',
    packages=["PyCriCodecsEx"],
    ext_modules=[Extension(
        'CriCodecsEx',
        CriCodecsEx_sources,
        include_dirs=[os.path.abspath("CriCodecsEx")],
        depends=[os.path.join('CriCodecsEx',f) for f in os.listdir("CriCodecsEx")]
    )],
    extras_require={'usm': ['ffmpeg-python']},
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],    
    python_requires=">=3.10",
    cmdclass={
        'build_ext': BuildExt
    }
)
