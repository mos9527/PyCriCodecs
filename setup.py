from setuptools import setup, Extension
from setuptools.command.build_ext import build_ext
import os

ENV_DEBUG = True #  os.environ.get('CRICODECSEX_DEBUG', None)   

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
                compile_args += ['-O0', '-g']
            else:
                compile_args += ['-O2']
        for ext in self.extensions:
            ext.extra_compile_args.extend(compile_args)
            ext.extra_link_args.extend(link_args)
        return super().build_extensions()
setup(
    name="PyCriCodecsEx",
    version="0.0.1",
    description="Python frontend with a C++ backend of managing Criware files of all kinds.",
    packages=["PyCriCodecsEx"],
    ext_modules=[Extension(
        'CriCodecsEx',
        CriCodecsEx_sources,
        include_dirs=[os.path.abspath("CriCodecsEx")],
        depends=[os.path.join('CriCodecsEx',f) for f in os.listdir("CriCodecsEx")]
    )],
    install_requires=[
        'ffmpeg-python'
    ],
    extras_require={"gui": ["GooeyEx>=0.0.8"]},
    entry_points={
        "console_scripts": [
            "PyCriCodecsEx = PyCriCodecsEx.__main__:__main__",
            "PyCriCodecsEx-gui = PyCriCodecsEx.__gui__:__main__",
        ],
    },
    python_requires=">=3.10",
    cmdclass={
        'build_ext': BuildExt
    }
)
