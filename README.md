1. The curve25519 repository is not in PyPI, so you will need to
install it by hand. To do that:

     git clone https://github.com/agl/curve25519-donna
     cd curve25519-donna
     sudo python setup.py install

2. There is a bug in the python-gnupg 0.3.6 module that throws an
exception if gpg emits an "UNEXPECTED" message. This happens when
two messages collide on receipt, and are mixed.

While the exception messes up the smmpchat screen a bit, it causes
no lasting harm. I submitted a patch to python-gnupg to fix the
bug. It was accepted and is in the official mercurial repository
at bitbucket. Presumably the PyPI repo will be updated at some point,
probably when the python-gnupg module version is bumped to 0.3.7.

Should you wish to install the patched python-gnupg module, you can
clone the official repository with the following command:

     hg clone https://bitbucket.org/vinay.sajip/python-gnupg

Then do the usual ```sudo python setup.py install``` to install it.
You may need to remove the old version first.
