SMMP is a secure, multi-party, synchronous communication protocol. The protocol follows
a peer-to-peer model and provides perfect forward secrecy and perfect future secrecy against a
computationally-bounded adversary, as well as information-theoretic plausible deniability for
participants in a multi-party conversation. The protocol uses a three-round, authenticated
Burmester-Desmedt group key agreement protocol to generate a shared secret between a group of N
participants. Conversation participants authenticate to each other during key agreement via a triple
Diffie-Hellman mechanism. Individual message keys are updated after receipt of each message by
incorporating new key material distributed by the sending participant. No security requirements
are imposed on the underlying transport layer, and our protocol leaks no metadata beyond that
exposed by the transport layer. Conversation transcript universality is assured by a conversation
digest that is updated upon receipt of each message, and all conversation messages are signed to
verify proof of origin. All setup operations prior to group key agreement take place over an insecure
channel. SMMP represents a significant improvement in security and efficiency over current secure,
multi-party messaging protocols including GOTR, mpOTR, and improved GOTR.

See the paper in the smmp/spec directory for full details on the protocol.

This repository includes a reference implementation of SMMP written in python.
It also inclues an ncurses-based secure multiparty chat client.

Notes:

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
