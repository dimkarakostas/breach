% BibTeX bibliography style `nickie'
% Author: Nikolaos S. Papaspyrou (nickie@softlab.ntua.gr)
% Created: October 16, 1995
% Revised: June 24, 2002
% RCS version: $Id: softlab-thesis.bst,v 1.2 2005/10/18 10:19:38 nickie Exp $

ENTRY
  { address
    author
    booktitle
    chapter
    edition
    editor
    howpublished
    institution
    journal
    key
    month
    note
    number
    organization
    pages
    publisher
    school
    series
    title
    type
    volume
    year
    bibcheck
    bibfiles
    bibwhere
  }
  {}
  { label extra.label sort.label }

INTEGERS { output.state before.all after.block mid.block before.note }

FUNCTION {init.state.consts}
{ #0 'before.all :=
  #1 'after.block :=
  #2 'mid.block :=
  #3 'before.note :=
}


% Functions not, or, and
% ----------------------
% Logical operators, not covered

FUNCTION {not}
{
    { #0 }
    { #1 }
  if$
}

FUNCTION {and}
{
    'skip$
    { pop$ #0 }
  if$
}

FUNCTION {or}
{
    { pop$ #1 }
    'skip$
  if$
}


% Function output.nonnull
% -----------------------
% Parameter 1: item to be preserved
% Parameter 2: item to be printed
% Result:      parameter 2
%
% If we're after a block
%    output parameter 1 followed by a comma and a \newblock
% else if we're before all
%    output parameter 1
% else
%    output parameter 1 followed by a comma and a space

STRINGS { s t }

FUNCTION {output.nonnull}
{
  's :=
  output.state after.block =
    { "," * write$
      newline$
      "\newblock " write$
    }
    { output.state before.all =
	'write$
        { output.state before.note =
            { "." * write$
              newline$
              "\newblock " write$ }
	    { ", " * write$ }
          if$
        }
      if$
    }
  if$
  mid.block 'output.state :=
  s
}


% Function output
% ---------------
% Parameter 1: item to be printed
%
% Outputs parameter 1

FUNCTION {output}
{
  duplicate$ empty$
    'pop$
    'output.nonnull
  if$
}


% Function output.check
% ---------------------
% Parameter 1: type of field (just to be printed)
% Parameter 2: item to be printed
%
% Checks if parameter 2 is empty. If not, it outputs it,
% otherwise it prints a warning.

FUNCTION {output.check}
{
  't :=
  duplicate$ empty$
%
% If the first letter in the citation has an ASCII code > 128, we
% assume that it is in Greek...  We check if the first word is
% "Proceedings" and use the appropriate word before it.
%
    { duplicate$ #1 #1 substring$ chr.to.int$ #128 <
        { pop$ "empty " t * " in " * cite$ * warning$ }
        { duplicate$ #1 #8 substring$ "Πρακτικά" =
            { pop$ "empty " t * " στα " * cite$ * warning$ }
            { pop$ "empty " t * " " * cite$ * warning$ }
          if$
        }
      if$
    }
    'output.nonnull
  if$
}


% Function remove.blanks
% ----------------------
% Parameter 1: string to be parsed
% Result:      parameter 1, where leading and trailing blanks have been
%              removed

INTEGERS { len ptr }
STRINGS  { ss }

FUNCTION {remove.blanks}
{
  duplicate$ empty$
    { pop$ "" }
    { 'ss :=
      #0 'len :=
        { ss #1 len substring$ empty$ }
        { len #1 + 'len := }
      while$
      ss len global.max$ substring$ 'ss :=
      #0 'len :=
        { ss #-1 len substring$ empty$ }
        { len #1 + 'len := }
      while$
      ss #0 len - global.max$ substring$
    }
  if$
}


% Function parse.comma.delimited
% ------------------------------
% Parameter 1: string to be parsed
% Result:      an empty string, followed by the list of parsed elements in
%              the string in reverse order (first to be popped is first
%              element)

FUNCTION {parse.comma.delimited}
{
  duplicate$ empty$
    { pop$ "" }
    { 's :=
      ""
      #0 'len :=
      s text.length$ 'ptr :=
	{ ptr #0 > }
	{ s ptr #1 substring$ "," =
	    { len #0 =
		{ "Invalid element in comma delimited list" warning$ }
		{ s ptr #1 + len substring$ remove.blanks
		  #0 'len :=
		}
	      if$
	    }
	    { len #1 + 'len := }
	  if$
	  ptr #1 - 'ptr :=
	}
      while$
      len #0 =
	{ duplicate$ empty$
	    { "Invalid element in comma delimited list" warning$ }
	    'skip$
	  if$
	}
	{ s #1 len substring$ remove.blanks }
      if$
    }
  if$
}


% Function output.bibcheck
% ------------------------
% Writes the contents of the `bibcheck' field.

FUNCTION {output.bibcheck}
{
   bibcheck parse.comma.delimited
     { duplicate$ empty$ not }
     { "?" * write$
       duplicate$ empty$
         'skip$
         { " " write$ }
       if$
     }
   while$
   pop$
}


% Function output.bibwhere
% ------------------------
% Writes the contents of the `bibwhere' field.

FUNCTION {output.bibwhere}
{
   bibwhere empty$
     'skip$
     { bibwhere remove.blanks write$ }
   if$
}


% Function output.bibfiles
% ------------------------
% Writes the contents of the `bibfiles' field.
% Assumes just one bibwrite !!!

FUNCTION {output.bibfiles}
{
   bibfiles parse.comma.delimited
     { duplicate$ empty$ not }
     { duplicate$ bibwhere remove.blanks =
         { pop$ }
         { write$
	   duplicate$ empty$
	     'skip$
	     { ", " write$ }
	   if$
         }
       if$
     }
   while$
   pop$
}


% Function output.bibitem
% -----------------------
% Result: null string
%
% Starts an entry by writing the label and citation.

FUNCTION {output.bibitem}
{
  newline$
  "\nbibitem[" write$
  label write$
  "]{" write$
  cite$ write$
  "}{" write$
  output.bibcheck
  "}{" write$
  output.bibwhere
  "}{" write$
  output.bibfiles
  "}" write$
  newline$
  ""
  before.all 'output.state :=
}


% Function fin.entry
% ------------------
% Parameter 1: item to be printed
%
% Finishes an entry by writing whatever remains followed by a period.

FUNCTION {fin.entry}
{
  add.period$
  write$
  newline$
}


% Function new.block
% ------------------
% If we are not before all, now we are after a block.

FUNCTION {new.block}
{
  output.state before.all =
    'skip$
    { after.block 'output.state := }
  if$
}


% Function new.block.checka
% -------------------------
% Parameter 1: item to be printed
%
% If parameter 1 is not empty, new block

FUNCTION {new.block.checka}
{
  empty$
    'skip$
    'new.block
  if$
}


% Function new.block.checkb
% -------------------------
% Parameter 1: item to be printed
% Parameter 2: item to be printed
%
% if at least one of parameters is non empty, new block

FUNCTION {new.block.checkb}
{
  empty$
  swap$ empty$
  and
    'skip$
    'new.block
  if$
}


% Function new.block.note
% -----------------------
% If we are not before all, now we are before a note.

FUNCTION {new.block.note}
{
  output.state before.all =
    'skip$
    { before.note 'output.state := }
  if$
}


% Function field.or.null
% ----------------------
% Parameter 1: item
% Result:      parameter 1, if not empty or missing, null string otherwise

FUNCTION {field.or.null}
{
  duplicate$ empty$
    { pop$ "" }
    'skip$
  if$
}


% Function emphasize
% ------------------
% Parameter 1: item to be printed
% Result:      parameter 1, surrounded by `{\em ' and `}'

FUNCTION {emphasize}
{
  duplicate$ empty$
    { pop$ "" }
    { "{\em " swap$ * "}" * }
  if$
}


% Function format.names
% ---------------------
% Parameter 1: names to be printed
% Result:      formatted names from parameter 1

INTEGERS { nameptr namesleft numnames }

FUNCTION {format.names}
{
  's :=
  #1 'nameptr :=
  s num.names$ 'numnames :=
  numnames 'namesleft :=
    { namesleft #0 > }
    { s nameptr "{ff~}{vv~}{ll}{, jj}" format.name$ 't :=
      nameptr #1 >
	{ namesleft #1 >
	    { ", " * t * }
	    {
%
% Uncomment the following two lines if you want a comma to be
% printed before the `and' if there are more than two names.
%
%             numnames #2 >
%		{ "," * }
%		'skip$
%	      if$
%
% If the first letter in the name of the first author has an
% ASCII code >= 128, we assume that the authors' names are in
% Greek...
%
              s #1 #1 substring$ chr.to.int$ #128 <
                { t "others" =
                    { " et~al." * }
                    { " and " * t * }
                  if$
                }
                { t "others" =
                    { " κ.α." * }
                    { " και " * t * }
                  if$
                }
              if$
	    }
	  if$
	}
	't
      if$
      nameptr #1 + 'nameptr :=
      namesleft #1 - 'namesleft :=
    }
  while$
}


% Function format.authors
% -----------------------
% Result: formatted names of authors

FUNCTION {format.authors}
{
  author empty$
    { "" }
    { author format.names }
  if$
}


% Function format.editors
% -----------------------
% Result: formatted names of editors

FUNCTION {format.editors}
{
  editor empty$
    { "" }
    { editor format.names
      editor #1 #1 substring$ chr.to.int$ #128 <
        { editor num.names$ #1 >
	    { ", editors" * }
	    { ", editor" * }
          if$
        }
        { editor num.names$ #1 >
	    { ", επιμελητές" * }
	    { ", επιμελητής" * }
          if$
        }
      if$
    }
  if$
}


% Function format.title.case
% --------------------------
% Parameter 1: item to be printed
% Result:      parameter 1 in "title"-case
%
% The first letters of all normal words are transformed to upper case,
% except for some words (e.g. prepositions, etc.).

FUNCTION {format.title.case}
{
  % nothing so far !!!
}


% Function format.quote
% ---------------------
% Parameter 1: item to be printed
% Result:      parameter 1 surrounded by quotes and with all
%              double quotes transformed to single (in braces)

FUNCTION {format.quote}
{
  's :=
  "" 't :=
    { s text.length$ #1 > }
    { s #1 #2 substring$ "``" =
        { t "{`}" * 't :=
          s #3 global.max$ substring$ 's :=
        }
        { s #1 #2 substring$ "''" =
            { t "{'}" * 't :=
              s #3 global.max$ substring$ 's :=
            }
            { t s #1 #1 substring$ * 't :=
              s #2 global.max$ substring$ 's :=
            }
          if$
        }
      if$
    }
  while$
  "``" t * s * "''" *
}


% Function format.title
% ---------------------
% Result: the formatted title
%
% Format the title, converting it to "title"-case.

FUNCTION {format.title}
{
  title empty$
    { "" }
    { title format.title.case format.quote }
  if$
}


% Function n.dashify
% ------------------
% Parameter 1: pages field
% Result:      properly formatted pages field
%
% Fix number of dashes (always > 1, if any)

FUNCTION {n.dashify}
{
  't :=
  ""
    { t empty$ not }
    { t #1 #1 substring$ "-" =
	{ t #1 #2 substring$ "--" = not
	    { "--" *
	      t #2 global.max$ substring$ 't :=
	    }
	    {   { t #1 #1 substring$ "-" = }
		{ "-" *
		  t #2 global.max$ substring$ 't :=
		}
	      while$
	    }
	  if$
	}
	{ t #1 #1 substring$ *
	  t #2 global.max$ substring$ 't :=
	}
      if$
    }
  while$
}


% Function format.date
% --------------------
% Result: formatted month and year

FUNCTION {format.date}
{
  year empty$
    { month empty$
	{ "" }
	{ "there's a month but no year in " cite$ * warning$
	  month
	}
      if$
    }
    { month empty$
	'year
	{ month " " * year * }
      if$
    }
  if$
}

% Function format.btitle
% ----------------------
% Result: formatted book title (emphasized, without touching it)

FUNCTION {format.btitle}
{
  title emphasize
}


% Function tie.or.space.connect
% -----------------------------
% Parameter 1: item to be printed
% Parameter 2: item to be printed
% Result:      parameter 1 followed by space (hard or soft) and parameter 2

FUNCTION {tie.or.space.connect}
{
  duplicate$ text.length$ #3 <
    { "~" }
    { " " }
  if$
  swap$ * *
}


% Function tie.or.sspace.connect
% ------------------------------
% Parameter 1: item to be printed
% Parameter 2: item to be printed
% Result:      parameter 1 followed by space (hard or soft) and parameter 2
% 
% The space will be short, in any case

FUNCTION {tie.or.sspace.connect}
{
  duplicate$ text.length$ #3 <
    { "~" }
    { "\ " }
  if$
  swap$ * *
}


% Function either.or.check
% ------------------------
% Parameter 1: item to be printed
% Parameter 2: warning message
%
% Print a warning if parameter 1 is not empty

FUNCTION {either.or.check}
{
  empty$
    'pop$
    { "can't use both " swap$ * " fields in " * cite$ * warning$ }
  if$
}


% Function format.bvolume
% -----------------------
% Result: formatted book volume and series

FUNCTION {format.bvolume}
{
  volume empty$
    { "" }
    { "vol." volume tie.or.sspace.connect
      series empty$
	'skip$
	{ " of " * series emphasize * }
      if$
      "volume and number" number either.or.check
    }
  if$
}


% Function format.number.series
% -----------------------------
% Result: formatted number and series (or nothing if volume is not empty).

FUNCTION {format.number.series}
{
  volume empty$
    { number empty$
	{ series field.or.null }
	{ "no." number tie.or.sspace.connect
	  series empty$
	    { "there's a number but no series in " cite$ * warning$ }
	    { " in " * series * }
	  if$
	}
      if$
    }
    { "" }
  if$
}


% Function format.edition
% -----------------------
% Result: formatted edition

FUNCTION {format.edition}
{
  edition empty$
    { "" }
    { edition "l" change.case$ " edition" * }
  if$
}


% Function multi.page.check
% -------------------------
% Parameter 1: range of pages
% Result:      1 if there are more than one pages, 0 otherwise
%
% Checks by searching for `-', `,' or `+' characters.

INTEGERS { multiresult }

FUNCTION {multi.page.check}
{
  't :=
  #0 'multiresult :=
    { multiresult not
      t empty$ not
      and
    }
    { t #1 #1 substring$
      duplicate$ "-" =
      swap$ duplicate$ "," =
      swap$ "+" =
      or or
	{ #1 'multiresult := }
	{ t #2 global.max$ substring$ 't := }
      if$
    }
  while$
  multiresult
}


% Function format.pages
% ---------------------
% Result: formatted pages (long format) `page(s) pages'

FUNCTION {format.pages}
{
  pages empty$
    { "" }
    { pages multi.page.check
	{ "pp." pages n.dashify tie.or.sspace.connect }
	{ "p." pages tie.or.sspace.connect }
      if$
    }
  if$
}


% Function format.vol.num.pages
% -----------------------------
% Result: formatted volume, number and pages

FUNCTION {format.vol.num.pages}
{
  volume empty$
    { "" }
    { "vol." volume tie.or.sspace.connect }
  if$
  number empty$
    'skip$
    { volume empty$
	{ "there's a number but no volume in " cite$ * warning$ }
	{ ", " * }
      if$
      "no." number tie.or.sspace.connect *
    }
  if$
  pages empty$
    'skip$
    { duplicate$ empty$
        'skip$
	{ ", " * }
      if$
      format.pages *
    }
  if$
}


% Function format.chapter.pages
% -----------------------------
% Result: formatted chapter and pages, long format

FUNCTION {format.chapter.pages}
{
  chapter empty$
    'format.pages
    { type empty$
	{ "chapter" }
	{ type "l" change.case$ }
      if$
      chapter tie.or.space.connect
      pages empty$
	'skip$
	{ ", " * format.pages * }
      if$
    }
  if$
}


% Function format.in.ed.booktitle
% -------------------------------
% Result: formatted editors for booktitle

FUNCTION {format.in.ed.booktitle}
{
  booktitle empty$
    { "" }
    { editor empty$
	{ "in " booktitle emphasize * }
	{ "in " format.editors * ", " * booktitle emphasize * }
      if$
    }
  if$
}


% Function empty.misc.check
% -------------------------
% Check if all fields in a misc entry are empty.

FUNCTION {empty.misc.check}
{
  author empty$ title empty$ howpublished empty$
  month empty$ year empty$ note empty$
  and and and and and
  key empty$ not and
    { "all relevant fields are empty in " cite$ * warning$ }
    'skip$
  if$
}


% Function format.thesis.type
% ---------------------------
% Parameter 1: default type
% Result:      formatted type of thesis

FUNCTION {format.thesis.type}
{
  type empty$
    'skip$
    { pop$
      type "t" change.case$
    }
  if$
}


% Function format.tr.number
% -------------------------
% Result: formatted number of technical report

FUNCTION {format.tr.number}
{
  type empty$
    { "Technical Report" }
    'type
  if$
  number empty$
    { "t" change.case$ }
    { number tie.or.space.connect }
  if$
}


% Function format.article.crossref
% --------------------------------
% Result: formatted article cross reference
%
% If the key field is empty
%    return `in {\em journal \/} citation'
% else
%    return `in key citation'

FUNCTION {format.article.crossref}
{
  key empty$
    { journal empty$
	{ "need key or journal for " cite$ * " to crossref " * crossref *
	  warning$
	  ""
	}
	{ "in {\em " journal * "\/}" * }
      if$
    }
    { "in " key * }
  if$
  " \cite{" * crossref * "}" *
}


% Function format.crossref.editor
% -------------------------------
% Result: editor name(s) formatted for a cross reference (abbreviated)

FUNCTION {format.crossref.editor}
{
  editor #1 "{vv~}{ll}" format.name$
  editor num.names$ duplicate$
  #2 >
    { pop$ " et~al." * }
    { #2 <
	'skip$
	{ editor #2 "{ff }{vv }{ll}{ jj}" format.name$ "others" =
	    { " et~al." * }
	    { " and " * editor #2 "{vv~}{ll}" format.name$ * }
	  if$
	}
      if$
    }
  if$
}


% Function format.book.crossref
% -----------------------------
% Result: formatted book cross reference as in `VEC'
%
% where:
%    V: `Volume volume of'
%    E: if there is an editor (different from the author)
%          formatted-editor
%       else if the key field is empty
%          `{\em series\/}
%       else
%          key
%    C: citation

FUNCTION {format.book.crossref}
{
  volume empty$
    { "empty volume in " cite$ * "'s crossref of " * crossref * warning$
      "in "
    }
    { "vol." volume tie.or.sspace.connect
      " of " *
    }
  if$
  editor empty$
  editor field.or.null author field.or.null =
  or
    { key empty$
	{ series empty$
	    { "need editor, key, or series for " cite$ * " to crossref " *
	      crossref * warning$
	      "" *
	    }
	    { "{\em " * series * "\/}" * }
	  if$
	}
	{ key * }
      if$
    }
    { format.crossref.editor * }
  if$
  " \cite{" * crossref * "}" *
}


% Function format.incoll.inproc.crossref
% --------------------------------------
% Result: formatted incoll/inproc cross reference as in `EC'
%
% where:
%    E: if there is an editor (different from the author)
%          formatted-editor
%       else if the key field is empty
%          `{\em booktitle\/}
%       else
%          key
%    C: citation

FUNCTION {format.incoll.inproc.crossref}
{
  editor empty$
  editor field.or.null author field.or.null =
  or
    { key empty$
	{ booktitle empty$
	    { "need editor, key, or booktitle for " cite$ * " to crossref " *
	      crossref * warning$
	      ""
	    }
	    { "in {\em " booktitle * "\/}" * }
	  if$
	}
	{ "in " key * }
      if$
    }
    { "in " format.crossref.editor * }
  if$
  " \cite{" * crossref * "}" *
}


% Function article
% ----------------
% Prints an article as:
%    start...
%    authors                                \newblock
%    title                                  \newblock
%    journal, volume, number, pages, date   \newblock
%    note
%    finish...

FUNCTION {article}
{
  output.bibitem
  format.authors "author" output.check
  new.block
  format.title "title" output.check
  new.block
  crossref missing$
    { journal emphasize "journal" output.check
      format.vol.num.pages output
      format.date "year" output.check
    }
    { format.article.crossref output.nonnull
      format.pages output
    }
  if$
  new.block.note
  note output
  fin.entry
}


% Function book
% -------------
% Prints a book as:
%    start...
%    authors x-or editors                   \newblock
%    title, volume                          \newblock
%    number, series                         
%    publisher, address, edition, date      \newblock
%    note
%    finish...

FUNCTION {book}
{
  output.bibitem
  author empty$
    { format.editors "author and editor" output.check }
    { format.authors output.nonnull
      crossref missing$
	{ "author and editor" editor either.or.check }
	'skip$
      if$
    }
  if$
  new.block
  format.btitle "title" output.check
  crossref missing$
    { format.bvolume output
      new.block
      format.number.series output
      publisher "publisher" output.check
      address output
    }
    { new.block
      format.book.crossref output.nonnull
    }
  if$
  format.edition output
  format.date "year" output.check
  new.block.note
  note output
  fin.entry
}


% Function booklet
% ----------------
% Prints a booklet as:
%    start...
%    authors                                \newblock
%    title                                  \newblock if next exists
%    howpublished, address
%    date                                   \newblock
%    note
%    finish...

FUNCTION {booklet}
{
  output.bibitem
  format.authors output
  new.block
  format.title "title" output.check
  howpublished address new.block.checkb
  howpublished output
  address output
  format.date output
  new.block.note
  note output
  fin.entry
}


% Function inbook
% ---------------
% Prints an inbook as:
%    start...
%    authors x-or editors                   \newblock
%    title, volume                          \newblock
%    chapter, pages                         \newblock
%    number, series                        
%    publisher, address, edition, date      \newblock
%    note
%    finish...

FUNCTION {inbook}
{
  output.bibitem
  author empty$
    { format.editors "author and editor" output.check }
    { format.authors output.nonnull
      crossref missing$
	{ "author and editor" editor either.or.check }
	'skip$
      if$
    }
  if$
  new.block
  format.btitle "title" output.check
  crossref missing$
    { format.bvolume output
      format.chapter.pages "chapter and pages" output.check
      new.block
      format.number.series output
      publisher "publisher" output.check
      address output
    }
    { format.chapter.pages "chapter and pages" output.check
      new.block
      format.book.crossref output.nonnull
    }
  if$
  format.edition output
  format.date "year" output.check
  new.block.note
  note output
  fin.entry
}


% Function incollection
% ---------------------
% Prints an incollection as:
%    start...
%    authors                                             \newblock
%    title                                               \newblock
%    booktitle, volume, number, series, chapter, pages   
%    publisher, address, edition, date                   \newblock
%    note
%    finish...

FUNCTION {incollection}
{
  output.bibitem
  format.authors "author" output.check
  new.block
  format.title "title" output.check
  new.block
  crossref missing$
    { format.in.ed.booktitle "booktitle" output.check
      format.bvolume output
      format.number.series output
      format.chapter.pages output
      publisher "publisher" output.check
      address output
      format.edition output
      format.date "year" output.check
    }
    { format.incoll.inproc.crossref output.nonnull
      format.chapter.pages output
    }
  if$
  new.block.note
  note output
  fin.entry
}


% Function inproceedings / conference
% -----------------------------------
% Prints an inproceedings/conference as:
%    start...
%    authors                             \newblock
%    title                               \newblock
%    booktitle, volume, number, pages   
%    organization, publisher, address    { not exactly! }
%    date                                \newblock
%    note
%    finish...

FUNCTION {inproceedings}
{
  output.bibitem
  format.authors "author" output.check
  new.block
  format.title "title" output.check
  new.block
  crossref missing$
    { format.in.ed.booktitle "booktitle" output.check
      format.bvolume output
      format.number.series output
      format.pages output
      address empty$
	{ organization output
	  publisher output
	  format.date "year" output.check
	}
	{ address output.nonnull
	  format.date "year" output.check
	  organization output
	  publisher output
	}
      if$
    }
    { format.incoll.inproc.crossref output.nonnull
      format.pages output
    }
  if$
  new.block.note
  note output
  fin.entry
}

FUNCTION {conference} { inproceedings }


% Function manual
% ---------------
% Prints a manual as:
%    start...
%    whatever...
%    finish...

FUNCTION {manual}
{
  output.bibitem
  author empty$
    { organization empty$
	'skip$
	{ organization output.nonnull
	  address output
	}
      if$
    }
    { format.authors output.nonnull }
  if$
  new.block
  format.btitle "title" output.check
  author empty$
    { organization empty$
	{ address new.block.checka
	  address output
	}
	'skip$
      if$
    }
    { organization address new.block.checkb
      organization output
      address output
    }
  if$
  format.edition output
  format.date output
  new.block.note
  note output
  fin.entry
}


% Function mastersthesis
% ----------------------
% Prints a Master's thesis as:
%    start...
%    whatever...
%    finish...

FUNCTION {mastersthesis}
{
  output.bibitem
  format.authors "author" output.check
  new.block
  format.title "title" output.check
  new.block
  "Master's thesis" format.thesis.type output.nonnull
  school "school" output.check
  address output
  format.date "year" output.check
  new.block.note
  note output
  fin.entry
}


% Function misc
% -------------
% Prints a misc entry as:
%    start...
%    whatever...
%    finish...

FUNCTION {misc}
{
  output.bibitem
  format.authors output
  title howpublished new.block.checkb
  format.title output
  howpublished new.block.checka
  howpublished output
  format.date output
  new.block.note
  note output
  fin.entry
  empty.misc.check
}


% Function phdthesis
% ------------------
% Prints a Ph.D. thesis as:
%    start...
%    whatever...
%    finish...

FUNCTION {phdthesis}
{
  output.bibitem
  format.authors "author" output.check
  new.block
  format.btitle "title" output.check
  new.block
  "Ph.D.\ thesis" format.thesis.type output.nonnull
  school "school" output.check
  address output
  format.date "year" output.check
  new.block.note
  note output
  fin.entry
}


% Function proceedings
% --------------------
% Prints a proceedings entry as:
%    start...
%    whatever...
%    finish...

FUNCTION {proceedings}
{
  output.bibitem
  editor empty$
    { organization output }
    { format.editors output.nonnull }
  if$
  new.block
  format.btitle "title" output.check
  format.bvolume output
  format.number.series output
  address empty$
    { editor empty$
	'skip$
	{ organization output }
      if$
      publisher output
      format.date "year" output.check
    }
    { address output.nonnull
      format.date "year" output.check
      editor empty$
	'skip$
	{ organization output }
      if$
      publisher output
    }
  if$
  new.block.note
  note output
  fin.entry
}


% Function techreport
% -------------------
% Prints a technical report as:
%    start...
%    whatever...
%    finish...

FUNCTION {techreport}
{
  output.bibitem
  format.authors "author" output.check
  new.block
  format.title "title" output.check
  new.block
  format.tr.number output.nonnull
  institution "institution" output.check
  address output
  format.date "year" output.check
  new.block.note
  note output
  fin.entry
}


% Function unpublished
% --------------------
% Prints an unpublished entry as:
%    start...
%    whatever...
%    finish...

FUNCTION {unpublished}
{
  output.bibitem
  format.authors "author" output.check
  new.block
  format.title "title" output.check
  new.block.note
  note "note" output.check
  format.date output
  fin.entry
}


% Auxiliary

FUNCTION {default.type} { misc }


% Months

MACRO {jan} {"January"}

MACRO {feb} {"February"}

MACRO {mar} {"March"}

MACRO {apr} {"April"}

MACRO {may} {"May"}

MACRO {jun} {"June"}

MACRO {jul} {"July"}

MACRO {aug} {"August"}

MACRO {sep} {"September"}

MACRO {oct} {"October"}

MACRO {nov} {"November"}

MACRO {dec} {"December"}


% Periodicals

MACRO {acmcs} {"ACM Computing Surveys"}

MACRO {acta} {"Acta Informatica"}

MACRO {cacm} {"Communications of the ACM"}

MACRO {ibmjrd} {"IBM Journal of Research and Development"}

MACRO {ibmsj} {"IBM Systems Journal"}

MACRO {ieeese} {"IEEE Transactions on Software Engineering"}

MACRO {ieeetc} {"IEEE Transactions on Computers"}

MACRO {ieeetcad}
 {"IEEE Transactions on Computer-Aided Design of Integrated Circuits"}

MACRO {ipl} {"Information Processing Letters"}

MACRO {jacm} {"Journal of the ACM"}

MACRO {jcss} {"Journal of Computer and System Sciences"}

MACRO {scp} {"Science of Computer Programming"}

MACRO {sicomp} {"SIAM Journal on Computing"}

MACRO {tocs} {"ACM Transactions on Computer Systems"}

MACRO {tods} {"ACM Transactions on Database Systems"}

MACRO {tog} {"ACM Transactions on Graphics"}

MACRO {toms} {"ACM Transactions on Mathematical Software"}

MACRO {toois} {"ACM Transactions on Office Information Systems"}

MACRO {toplas} {"ACM Transactions on Programming Languages and Systems"}

MACRO {tcs} {"Theoretical Computer Science"}


% Do the reading!

READ


% Sorting

FUNCTION {sortify}
{ purify$
  "l" change.case$
}

FUNCTION {chop.word}
{ 's :=
  'len :=
  s #1 len substring$ =
    { s len #1 + global.max$ substring$ }
    's
  if$
}

FUNCTION {format.lab.chop}
{
  #4 text.prefix$
}

FUNCTION {format.lab.names}
{
  #1 "{v{}}{ll{}}" format.name$
  purify$
  format.lab.chop
}

FUNCTION {author.key.label}
{ author empty$
    { key empty$
	{ cite$ format.lab.chop }
	{ key format.lab.chop }
      if$
    }
    { author format.lab.names }
  if$
}

FUNCTION {author.editor.key.label}
{ author empty$
    { editor empty$
	{ key empty$
	    { cite$ format.lab.chop }
	    { key format.lab.chop }
	  if$
	}
	{ editor format.lab.names }
      if$
    }
    { author format.lab.names }
  if$
}

FUNCTION {author.key.organization.label}
{ author empty$
    { key empty$
	{ organization empty$
	    { cite$ format.lab.chop }
	    { "The " #4 organization chop.word format.lab.chop }
	  if$
	}
	{ key format.lab.chop }
      if$
    }
    { author format.lab.names }
  if$
}

FUNCTION {editor.key.organization.label}
{ editor empty$
    { key empty$
	{ organization empty$
	    { cite$ format.lab.chop }
	    { "The " #4 organization chop.word format.lab.chop }
	  if$
	}
	{ key format.lab.chop }
      if$
    }
    { editor format.lab.names }
  if$
}

FUNCTION {calc.label}
{ type$ "book" =
  type$ "inbook" =
  or
    'author.editor.key.label
    { type$ "proceedings" =
	'editor.key.organization.label
	{ type$ "manual" =
	    'author.key.organization.label
	    'author.key.label
	  if$
	}
      if$
    }
  if$
  duplicate$
  year field.or.null purify$ #-1 #2 substring$
  *
  'label :=
  year field.or.null purify$ #-1 #4 substring$
  *
  sortify 'sort.label :=
}

FUNCTION {sort.format.names}
{ 's :=
  #1 'nameptr :=
  ""
  s num.names$ 'numnames :=
  numnames 'namesleft :=
    { namesleft #0 > }
    { nameptr #1 >
	{ "   " * }
	'skip$
      if$
      s nameptr "{vv{ } }{ll{ }}{  ff{ }}{  jj{ }}" format.name$ 't :=
      nameptr numnames = t "others" = and
	{ "et al" * }
	{ t sortify * }
      if$
      nameptr #1 + 'nameptr :=
      namesleft #1 - 'namesleft :=
    }
  while$
}

FUNCTION {sort.format.title}
{ 't :=
  "A " #2
    "An " #3
      "The " #4 t chop.word
    chop.word
  chop.word
  sortify
  #1 global.max$ substring$
}

FUNCTION {author.sort}
{ author empty$
    { key empty$
	{ "to sort, need author or key in " cite$ * warning$
	  ""
	}
	{ key sortify }
      if$
    }
    { author sort.format.names }
  if$
}

FUNCTION {author.editor.sort}
{ author empty$
    { editor empty$
	{ key empty$
	    { "to sort, need author, editor, or key in " cite$ * warning$
	      ""
	    }
	    { key sortify }
	  if$
	}
	{ editor sort.format.names }
      if$
    }
    { author sort.format.names }
  if$
}

FUNCTION {author.organization.sort}
{ author empty$
    { organization empty$
	{ key empty$
	    { "to sort, need author, organization, or key in " cite$ * warning$
	      ""
	    }
	    { key sortify }
	  if$
	}
	{ "The " #4 organization chop.word sortify }
      if$
    }
    { author sort.format.names }
  if$
}

FUNCTION {editor.organization.sort}
{ editor empty$
    { organization empty$
	{ key empty$
	    { "to sort, need editor, organization, or key in " cite$ * warning$
	      ""
	    }
	    { key sortify }
	  if$
	}
	{ "The " #4 organization chop.word sortify }
      if$
    }
    { editor sort.format.names }
  if$
}

FUNCTION {presort}
{ calc.label
  sort.label
  "    "
  *
  type$ "book" =
  type$ "inbook" =
  or
    'author.editor.sort
    { type$ "proceedings" =
	'editor.organization.sort
	{ type$ "manual" =
	    'author.organization.sort
	    'author.sort
	  if$
	}
      if$
    }
  if$
  *
  "    "
  *
  year field.or.null sortify
  *
  "    "
  *
  title field.or.null
  sort.format.title
  *
  #1 entry.max$ substring$
  'sort.key$ :=
}


% Sort

ITERATE {presort}

SORT


% Find longest label

STRINGS { longest.label last.sort.label next.extra }

INTEGERS { longest.label.width last.extra.num }

FUNCTION {initialize.longest.label}
{ "" 'longest.label :=
  #0 int.to.chr$ 'last.sort.label :=
  "" 'next.extra :=
  #0 'longest.label.width :=
  #0 'last.extra.num :=
}

FUNCTION {forward.pass}
{ last.sort.label sort.label =
    { last.extra.num #1 + 'last.extra.num :=
      last.extra.num int.to.chr$ 'extra.label :=
    }
    { "a" chr.to.int$ 'last.extra.num :=
      "" 'extra.label :=
      sort.label 'last.sort.label :=
    }
  if$
}

FUNCTION {reverse.pass}
{ next.extra "b" =
    { "a" 'extra.label := }
    'skip$
  if$
  label extra.label * 'label :=
  label width$ longest.label.width >
    { label 'longest.label :=
      label width$ 'longest.label.width :=
    }
    'skip$
  if$
  extra.label 'next.extra :=
}

EXECUTE {initialize.longest.label}

ITERATE {forward.pass}

REVERSE {reverse.pass}

FUNCTION {begin.bib}
{ 
  "\providecommand\nbibitem[5][]{\bibitem[#1]{#2}}" write$ newline$
  preamble$ empty$
    'skip$
    { preamble$ write$ newline$ }
  if$
  "\begin{thebibliography}{"  longest.label  * "}" * write$ newline$
}

EXECUTE {begin.bib}

EXECUTE {init.state.consts}

ITERATE {call.type$}

FUNCTION {end.bib}
{ newline$
  "\end{thebibliography}" write$ newline$
}

EXECUTE {end.bib}
