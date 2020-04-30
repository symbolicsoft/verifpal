" Vim syntax file
" Language:     Verifpal
" Maintainer:   Nadim Kobeissi <nadim@symbolic.software>
" Last Change:  2019 09 18
" SPDX-FileCopyrightText: © 2019-2020 Nadim Kobeissi <nadim@symbolic.software>
" SPDX-License-Identifier: GPL-3.0-only

if !exists("main_syntax")
    if version < 600
	syntax clear
    elseif exists("b:current_syntax")
	finish
    endif
    let main_syntax='verifpal'
endif

if version < 508
    command! -nargs=+ VerifpalHiLink hi link <args>
else
    command! -nargs=+ VerifpalHiLink hi def link <args>
endif

syn match verifpalOper "="
syn match verifpalDelim "?"
syn match verifpalDelim "("
syn match verifpalDelim ")"
syn match verifpalDelim "\["
syn match verifpalDelim "]"
syn keyword verifpalKeywrd knows generates leaks
syn keyword verifpalConstr UNBLIND BLIND RINGSIGNVERIF RINGSIGN PW_HASH HASH HKDF AEAD_ENC AEAD_DEC ENC DEC ASSERT CONCAT SPLIT MAC SIGNVERIF SIGN PKE_ENC PKE_DEC SHAMIR_SPLIT SHAMIR_JOIN G nil _
syn match verifpalConstr "\^"
syn keyword verifpalDecl principal phase queries attacker confidentiality authentication freshness unlinkability precondition
syn match verifpalTransfer "->"
syn match verifpalComment "//.*"

if version >= 508 || !exists("did_verifpal_syn_inits")
    if version < 508
	let did_verifpal_syn_inits = 1
    endif
    VerifpalHiLink verifpalOper      Operator
    VerifpalHiLink verifpalDelim     Delimiter
    VerifpalHiLink verifpalKeywrd    Keyword
    VerifpalHiLink verifpalConstr    Function
    VerifpalHiLink verifpalDecl      Typedef
    VerifpalHiLink verifpalTransfer  Typedef
    VerifpalHiLink verifpalComment   Comment
endif

delcommand VerifpalHiLink

let b:current_syntax = "verifpal"

if main_syntax == 'verifpal'
    unlet main_syntax
endif

let b:spell_options="contained"

" vim: ts=8
