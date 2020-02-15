#!/bin/bash

add_to_profile () {
    line="$1"
    while read match ; do 
	if test "$match" == "$line" ; then
	    echo "'$line'" already included in ~/.profile
	    echo Not installing a second time
	    return
	fi
    done < <(grep -F "$line" ~/.profile)

    echo "$line" >> ~/.profile
}

cd $HOME
if test -d pyretic ; then
    pushd pyretic
    git pull
    git checkout deprecated
    popd
else
    git clone git://github.com/frenetic-lang/pyretic.git
    cd pyretic
    git checkout deprecated
fi

cd $HOME

test -f .screenrc || wget http://frenetic-lang.org/pyretic/useful/.screenrc

cd $HOME/pox
git pull || true
if ! git branch | grep -q " carp$" ; then
    git checkout -b carp origin/carp
else
    git checkout carp
fi

cd $HOME/mininet
git pull

add_to_profile 'export PYTHONPATH=$HOME/pyretic:$HOME/mininet/:$HOME/pox'
add_to_profile 'export PATH=$PATH:$HOME/pyretic:$HOME/pox'

sudo aptitude install python-bitarray
sudo easy_install ipdb

