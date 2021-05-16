export PATH=~/build/depot_tools:$PATH

PS1='\h:\W$ '
umask 022

export PAGER=less
export HISTSIZE=50000
export HISTFILESIZE=50000
export EDITOR='emacs -nw'

function share_history {
history -a
history -c
history -r
}
shopt -u histappend
PROMPT_COMMAND="share_history"

alias rm='rm -i'
alias cp='cp -i'
alias mv='mv -i'
alias ls='ls --color'
alias ll='ls --color -lhBA'

stty stop undef > /dev/null 2>&1
stty start undef > /dev/null 2>&1

function psgrep()
{
    if [ $# -lt 1 ]; then
        echo "usage : psgrep [regexp]..."
        return
    fi
    pat=".*"
    for p in "$@"; do
        pat="(?=.*$p)$pat"
    done
    ps -ef | perl -ne "print if /^$pat\$/" | egrep -v 'perl -ne print if /'
}

function pskill()
{
    if [ $# -lt 2 ]; then
        echo "usage : pskill [-SIGNAL] [regexp]..."
        return
    fi
    minus=`echo $1 | cut -c 1`
    if [ $minus != "-" ]; then
        echo "usage : pskill [-SIGNAL] [regexp]..."
        return
    fi
    sig=$1
    shift
    pat=".*"
    for p in "$@"; do
        pat="(?=.*$p)$pat"
    done
    ps -ef | perl -ne "print if /^$pat\$/" | egrep -v 'perl -ne print if /' | awk '{print $2}' | xargs kill $sig 2> /dev/null
}

function rsyncauv()
{
    if [ $# -lt 3 ]; then
        echo "usage : rsyncauv hostname:dir hostname:dir size[MB]"
        return
    fi
    rsync -auv --max-size=`expr $3 \* 1024 \* 1024` $1/ $2/
}

function convertSVG()
{
    for i in `ls -1 --color=never | grep .svg`; do
        j=`basename $i .svg`
        convert -transparent white ${j}.{svg,png};
    done
}

# The next line updates PATH for the Google Cloud SDK.
if [ -f '/home/haraken/build/google-cloud-sdk/path.bash.inc' ]; then . '/home/haraken/build/google-cloud-sdk/path.bash.inc'; fi

# The next line enables shell command completion for gcloud.
if [ -f '/home/haraken/build/google-cloud-sdk/completion.bash.inc' ]; then . '/home/haraken/build/google-cloud-sdk/completion.bash.inc'; fi
