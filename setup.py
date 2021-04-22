from setuptools import setup, find_packages

setup(
    name='throne',
    version='0.1.0',
    author='shrunbr',
    author_email='shrunbr@as211553.net',
    description='Watch the internet from up on your throne.',
    packages=['bin', 'src', 'src.parsers'],
    include_package_data=True,
    install_requires=[
        'Click',
        'colorama',
        'requests'
    ],
    entry_points={
        'console_scripts': ['throne=bin.throne:cli']
    }
)