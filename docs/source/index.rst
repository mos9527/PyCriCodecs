.. include:: styles.rst

PyCriCodecsEx documentation
===========================

This site contains automatically generated API documentation for every format `PyCriCodecsEx` supports.

Most if not all features are verified to work with either commercial games, or official SDK tools. However issues are to be
expected - submit bug reports or feature requests on the `Issue Tracker <https://github.com/mos9527/PyCriCodecsEx/issues>`_.

PyCriCodecsEx is a fork of `Youjose/PyCriCodecs <https://github.com/Youjose/PyCriCodecs>`_. Refer to the original repository
and its `Wiki <https://github.com/Youjose/PyCriCodecs/wiki/Docs-and-Thoughts>`_ for more information.

The GitHub repository is available at `mos9527/PyCriCodecsEx <https://github.com/mos9527/PyCriCodecsEx>`_

Installation
============
PyCriCodecsEx is available on `PyPI <https://pypi.org/project/PyCriCodecsEx/>`_

.. code-block:: bash

   pip install PyCriCodecsEx

For USM features, you need `ffmpeg` installed and available in your PATH, and install the `[usm]` extra - which installs `ffmpeg-python <https://github.com/kkroening/ffmpeg-python>`_.

To make sure `ffmpeg` is available, you can refer to `ffmpeg-python's instructions <https://github.com/kkroening/ffmpeg-python?tab=readme-ov-file#installing-ffmpeg>`_.

.. code-block:: bash

   pip install PyCriCodecsEx[usm]


Support Status
========



USM Sofdec2 (Encode & Decode)
-----------------------------

**Audio Stream**

Decoding and Encoded format can be the following:

* |check| HCA
* |check| ADX

**Video Stream**

**NOTE**: You definitely want to tweak these encode settings a bit.

* |check| Sofdec Prime (MPEG1, from ``.m1v`` container)

  * Prepare source file with: ``ffmpeg -i <input_file> -c:v mpeg1video -an <output_file>.m1v``

* |check| H264 (from ``.h264`` raw container)

  * Prepare source file with: ``ffmpeg -i <input_file> -c:v libx264 -an <output_file>.h264``

* |check| VP9 (from ``.ivf`` container)

  * Prepare source file with: ``ffmpeg -i <input_file> -c:v libvpx -an <output_file>.ivf``

CPK
---
* |check| Unpacking
* |check| Packing

ACB Cue sheets (also AWB)
-------------------------
* |check| Cue extraction support for most ACBs
* |check| Cue waveform(s) encoding with ADX/HCA support
* |check| Comprehensive Cue metadata editing support (via Python API)

ADX Audio Codec
---------------
* |check| Decoding
* |check| Encoding

HCA Audio Codec
---------------
* |check| Decoding (up to version 3.0)
* |check| Encoding (up to version 3.0)

Roadmap
=======
* |uncheck| Interface for encode tasks (most probably done in a separate project)
* |uncheck| C/C++ port + FFI

Currently Known Bugs
====================
* USM seeking does not work. Though most games don't use it anyways.
* Not important, and might not fix: ADX encoding and decoding at higher bitdepths (11-15) adds popping noise.
* Some CPK's that has the same filename for every file in the entry will overwrite each other.
* Probably many more I am unaware of, report if you find any.

.. include:: USM.rst

.. include:: CPK.rst

.. include:: ACB.rst

.. include:: ADX.rst

.. include:: HCA.rst

.. include:: AWB.rst
   
.. include:: UTF.rst

.. include:: Misc.rst

Examples
==========================
.. include:: examples.rst

External Links
==========================
- https://github.com/donmai-me/WannaCRI
- https://github.com/vgmstream/vgmstream
- https://github.com/Nyagamon/HCADecoder
- https://github.com/Nyagamon/ADXDecoder
- https://github.com/Thealexbarney/VGAudio
- http://wiki.multimedia.cx/index.php?title=CRI_ADX_ADPCM
