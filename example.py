import os
from pathlib import Path

print(__file__)
print(os.path.realpath(__file__))
print(Path(os.path.dirname(os.path.realpath(__file__))))

