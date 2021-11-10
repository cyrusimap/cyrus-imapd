#!/bin/bash

BRANCH=${1:-HEAD}

FILTER_BRANCH_SQUELCH_WARNING=1 git filter-branch --tree-filter '
  mkdir -p ~/tmp/staging;
  mv * ~/tmp/staging;
  mkdir cassandane;
  mv ~/tmp/staging/* cassandane;
  if [ -e .github ]; then mv .github cassandane; fi;
  if [ -e .travis.yml ]; then mv .travis.yml cassandane; fi;
  if [ -e .gitignore ]; then mv .gitignore cassandane; fi;
  rm -r ~/tmp/staging;
' --prune-empty -- $BRANCH

