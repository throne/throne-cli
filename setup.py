import pathlib
from setuptools import setup, find_packages

parent_dir = pathlib.Path(__file__).parent
README = (parent_dir / "README.md").read_text()

setup(
    name='throne',
    version='0.3.0',
    author='shrunbr',
    author_email='shrunbr@throne.dev',
    url='https://github.com/throne/throne-cli/',
    description='Watch the internet from up on your throne.',
    long_description=README,
    long_description_content_type="text/markdown",
    license="BSD 3-Clause Clear License",
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