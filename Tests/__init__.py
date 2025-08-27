import os
from logging import getLogger, DEBUG, basicConfig

basicConfig(level=DEBUG)
logger = getLogger("tests")

SOURCE_DIR = os.path.dirname(__file__)
sample_file_path = lambda *args: os.path.join(SOURCE_DIR, *args)
TEMP_DIR = sample_file_path(".temp")
os.makedirs(TEMP_DIR, exist_ok=True)
temp_file_path = lambda *args: os.path.join(TEMP_DIR, *args)

