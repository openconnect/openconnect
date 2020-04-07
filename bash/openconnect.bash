#
# Bash completion for OpenConnect
#
# Copyright © David Woodhouse <dwmw2@infradead.org>
#
# Author: David Woodhouse <dwmw2@infradead.org>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU Lesser General Public License
# version 2.1, as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# Lesser General Public License for more details.


# Consider a command line like the following:
#
# openconnect -c --authenticate\ -k -k "'"'"'.pem --authgroup 'foo
# bar' --o\s linux-64 myserver
#
# There is absolutely no way I want to attempt parsing that in C and
# attempting to come up with the correct results as bash would do.
# That is just designing for failure; we'll never get it right.
#
# Yet if we use 'complete -C openconnect openconnect' and allow the
# program to do completions all by itself, that's what bash expects
# it to do. All that's passed into the program is $COMP_LINE and
# some other metadata.
#
# So instead we use bash to help us. In a completion *function* we
# are given the ${COMP_WORDS[]} array which has actually been parsed
# correctly. We still want openconnect itself to be able to do the
# result generation, so just prepend --autocomplete to the args.
#
# For special cases like filenames and hostnames, we want to invoke
# compgen, again to avoid reinventing the wheel badly. So define
# special cases HOSTNAME, FILENAME as the autocomplete results,
# to be handled as special cases. In those cases we also use
# ${COMP_WORDS[$COMP_CWORD]}) as the string to bew completed,
# pristine from bash instead of having been passed through the
# program itself. Thus, we see correct completions along the lines
# of
#
#     $ ls foo\ *
#     'foo bar.pem'  'foo bar.xml'  'foo baz.crt'
#     $ openconnect -c ./fo<TAB>
#
# ... partially completes to:
#
#     $ openconnect -c ./foo\ ba
#
# ... and a second <TAB> shows:
#
#     foo bar.pem  foo baz.crt
#
# Likewise,
#
#     $ touch '"'"'".pem
#     $ openconnect -c '"'<TAB>
#
# ...completes to:
#
#    $ openconnect -c \"\'.pem
#
# This does fall down if I create a filename with a newline in it,
# but even tab-completion for 'ls' falls over in that case.
#
# The main problem with this approach is that we can't easily map
# $COMP_POINT to the precise character on the line at which TAB was
# being pressed, which may not be the *end*.


_complete_openconnect () {
    export COMP_LINE COMP_POINT COMP_CWORD COMP_KEY COMP_TYPE
    COMP_WORDS[0]="--autocomplete"
    local IFS=$'\n'
    COMPREPLY=( $(/home/dwmw/git/openconnect/gtls-ibm/openconnect "${COMP_WORDS[@]}") )
    case "${COMPREPLY[0]}" in
	FILENAME)
	    if [ "${COMPREPLY[1]}" != "" ]; then
		COMPREPLY=( $( compgen -f -o filenames -o plusdirs -X ${COMPREPLY[1]} ${COMP_WORDS[$COMP_CWORD]}) )
	    else
		COMPREPLY=( $( compgen -f -o filenames -o plusdirs ${COMP_WORDS[$COMP_CWORD]}) )
	    fi
	    ;;

	FILENAMEAT)
	    COMPREPLY=( $( compgen -P @ -f -o filenames -o plusdirs ${COMP_WORDS[$COMP_CWORD]#@}) )
	    ;;

	EXECUTABLE)
	    COMPREPLY=( $( compgen -c -o plusdirs ${COMP_WORDS[$COMP_CWORD]}) )
	    ;;

	HOSTNAME)
	    COMPREPLY=( $( compgen -A hostname ${COMP_WORDS[$COMP_CWORD]}) )
	    ;;

	USERNAME)
	    COMPREPLY=( $( compgen -A user ${COMP_WORDS[$COMP_CWORD]}) )
	    ;;
    esac
}

complete -F _complete_openconnect -o filenames openconnect
