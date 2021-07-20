from setuptools import setup
import sys


if sys.version_info < (3, 3):
    sys.exit('Sorry, Python < 3.3 is not supported')


setup(
    name='ec2_allow_ssh',
    version='0.1',
    py_modules=['ec2_allow_ssh'],
    python_requires='>=3.3',
    install_requires=[
        'boto3',
        'Click',
        'ipgetter2',
    ],
    entry_points='''
        [console_scripts]
        ec2_allow_ssh=ec2_allow_ssh:allow_access
    ''',
)
