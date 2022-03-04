.. _github-guide:

============
GitHub guide
============

A walkthrough for using GitHub_ with a view to providing updates (source or documentation or testing) to the `Cyrus repository`_.

1. :ref:`Create a GitHub account <github-guide-account>`
2. :ref:`Add your ssh key <github-guide-sshkey>`
3. :ref:`Fork the repository <github-guide-fork>` to make a copy of the code for you to apply changes to.
4. :ref:`Issue a pull request <github-guide-pull>` to request that your changes are incorporated back into the master codebase.

This guide assumes you are familiar with the workings of `Git <https://help.github.com/articles/set-up-git/>`_ for source control.

.. _github-guide-account:

1. Create a GitHub account
--------------------------

Go to GitHub_ and sign up for an account. You only need the free plan to contribute to Cyrus.

Their `help pages <https://help.github.com/articles/signing-up-for-a-new-github-account/>`_ have more information 
on filling out your profile and setting up two-factor authentication for additional security.

.. _github-guide-sshkey:

2. Add your ssh key
-------------------

It's worth adding a ssh key to your account, so you're not having to input your password every time you access the repository.

If you don't have an ssh key already (and `here's how to check <https://help.github.com/articles/checking-for-existing-ssh-keys/>`_), 
you can `generate a new key <https://help.github.com/articles/generating-a-new-ssh-key-and-adding-it-to-the-ssh-agent/>`_. Once you have a key, 
`add it to GitHub <https://help.github.com/articles/adding-a-new-ssh-key-to-your-github-account/>`_ and 
`test it out <https://help.github.com/articles/testing-your-ssh-connection/>`_.


.. _github-guide-fork:

3. Fork the repository
----------------------

Whether you're contributing to `Cyrus <https://github.com/cyrusimap/cyrus-imapd>`_ (source, or documentation), 
or into helping out with `SASL <https://github.com/cyrusimap/cyrus-sasl>`_ or
any of the other `Cyrus component projects <https://github.com/cyrusimap>`_, use the Fork button to make a copy of the repository into your own GitHub work space.

GitHub has more information on `how to fork a repository <https://help.github.com/articles/fork-a-repo/>`_.

Once you have a forked copy, you can clone it into your working area on your computer. 

::

    git clone https://github.com/YOUR-USERNAME/REPOSITORY-NAME.git
    
You will then want to set your local copy to get its changes from the original repository, so it stays in sync. Use ``git remote -v`` to show the current origins of your clone which will currently be your fork.

::

    $ git remote -v
    origin  https://github.com/YOUR_USERNAME/YOUR_FORK.git (fetch)
    origin  https://github.com/YOUR_USERNAME/YOUR_FORK.git (push)
    
We want to set that instead to point to the primary original upstream repository.

::

    git remote add upstream https://github.com/cyrusimap/REPOSITORY-NAME.git  

Now we can check to see that the upstream is set:

::

    $ git remote -v
    origin    https://github.com/YOUR_USERNAME/YOUR_FORK.git (fetch)
    origin    https://github.com/YOUR_USERNAME/YOUR_FORK.git (push)
    upstream  https://github.com/cyrusimap/ORIGINAL_REPOSITORY.git (fetch)
    upstream  https://github.com/cyrusimap/ORIGINAL_REPOSITORY.git (push)    

We recommend you create a topic branch and make your changes (don't forget to :ref:`test! <developer-testing>`). Using a topic branch means you can keep your master 
source in sync without affecting your changes. It also means that if your patch undergoes further revisions before inclusion, you
can easily do so.

.. _github-guide-pull:

4. Issue a pull request
-----------------------

When your changes are done, you `issue a pull request <https://help.github.com/articles/using-pull-requests/>`_. 
This is done by logging into the GitHub interface, swapping to your branch, then selecting New Pull Request.

When submitting the pull request, note if there's a particular filed bug your patch addresses. The Cyrus Team
will review your pull request and make sure it gets integrated!

.. _GitHub: https://github.com
.. _Cyrus repository: https://github.com/cyrusimap/
