/*
    DCG to match strings to patterns.

    Copyright 2024 David Farrell

    Permission is hereby granted, free of charge, to any person
    obtaining a copy of this software and associated documentation
    files (the "Software"), to deal in the Software without
    restriction, including without limitation the rights to use, copy,
    modify, merge, publish, distribute, sublicense, and/or sell copies
    of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be
    included in all copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
    EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
    MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
    NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
    HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
    WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
    DEALINGS IN THE SOFTWARE.

*/

:- module(wildcard, [patt//1]).
:- use_module(library(dcgs)).

% match a list to pattern list.
patt([])     --> [].
patt([C|Cs]) -->
  wildcard([C|Cs]) | placeholder([C|Cs]) | escape([C|Cs]) | regular([C|Cs]).

wildcard(['*'|Cs]) --> word([]), patt(Cs).

placeholder(['?'|Cs]) --> [_], patt(Cs).

escape(['\\'|Cs]) --> same(Cs).

regular([C|Cs]) --> [C], patt(Cs).

% matches any two identical list heads.
same([])     --> [].
same([C|Cs]) --> [C], patt(Cs).

% matches any list with an empty list.
word([]) --> [].
word([]) --> [_], word([]).
