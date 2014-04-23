from setuptools import setup
import stacksync_oauth

setup(name='stacksync-oauth',
      version=stacksync_oauth.__version__,
      description='StackSync Authentication service',
      author='StackSync Team',
      author_email='info@stacksync_oauth.com',
      url='http://stacksync_oauth.org',
      packages=['stacksync_oauth'],
      install_requires=['oauthlib>=0.6.1', 'sqlalchemy>=0.9.4'],
)
