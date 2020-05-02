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
    local cur
    _get_comp_words_by_ref cur
    # But if we do this, then our COMPREPLY isn't interpreted according to it.
    #_get_comp_words_by_ref-n =: -w COMP_WORDS -i COMP_CWORD cur
    COMP_WORDS[0]="--autocomplete"
    local IFS=$'\n'
    COMPREPLY=( $(COMP_CWORD=$COMP_CWORD openconnect "${COMP_WORDS[@]}") )
    local FILTERPAT="${COMPREPLY[1]}"
    local PREFIX="${COMPREPLY[2]}"
    local COMP_WORD=${cur#${PREFIX}}
    case "${COMPREPLY[0]}" in
	FILENAME)
	    compopt -o filenames
	    COMPREPLY=( $( compgen -A file -ofilenames -o plusdirs -X "${FILTERPAT}" -- "${COMP_WORD}") )
	    COMPREPLY=( "${COMPREPLY[@]/#/${PREFIX}}" )
	    ;;

	EXECUTABLE)
	    compopt -o filenames
	    COMPREPLY=( $( compgen -A command -ofilenames -o plusdirs -- "${COMP_WORD}") )
	    COMPREPLY=( "${COMPREPLY[@]/#/${PREFIX}}" )
	    ;;

	HOSTNAME)
	    compopt +o filenames
	    COMPREPLY=( $( compgen -A hostname -P "${PREFIX}" -- "${COMP_WORD}") )
	    ;;

	USERNAME)
	    compopt +o filenames
	    COMPREPLY=( $( compgen -A user -P "${PREFIX}" -- "${COMP_WORD}") )
	    ;;

	*)
	    compopt +o filenames
	    ;;

    esac
}

complete -F _complete_openconnect openconnect
