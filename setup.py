from setuptools import setup, find_packages

setup(
    name='throne',
    version='0.2.0',
    author='shrunbr',
    author_email='shrunbr@throne.dev',
    url='https://github.com/throne/throne-cli/',
    description='Watch the internet from up on your throne.',
    packages=['bin', 'src', 'src.parsers'],
    include_package_data=True,
    install_requires=[
        'Click',
        'colorama',
        'requests',
        'pyyaml'
    ],
    entry_points={
        'console_scripts': ['throne=bin.throne:cli']
    }
)