from distutils.core import setup
setup(name='gccspendfrom',
      version='1.0',
      description='Command-line utility for crowcoin "coin control"',
      author='Gavin Andresen',
      author_email='gavin@crowcoinfoundation.org',
      requires=['jsonrpc'],
      scripts=['spendfrom.py'],
      )
