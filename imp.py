# This is a temporary workaround to address the incompatibility of the python-whois library with python 3.12.
# The issue is with the downstream https://github.com/PythonCharmers/python-future/ library, which is currently not being maintained.
# This file will short-circuit the problematic import which should prevent breaking compatibility until a real fix is in place in either whois or future.

pass
