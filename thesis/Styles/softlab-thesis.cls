%******************************************************************************
%  CVS/RCS version:
%     $Id: softlab-thesis.cls,v 1.3 2003/07/21 12:43:42 nickie Exp $
%******************************************************************************
%  LaTeX file  : softlab-thesis.cls
%  Written by  : Nikolaos S. Papaspyrou
%  Date        : October 17, 2002
%  Revised     : December 17, 2008
%
%  Description : A uniform template for diploma projects and doctoral
%                dissertations at the Software Engineering Laboratory,
%                School of Electrical and Computer Engineering,
%                National Technical University of Athens.
%
% Notes        : This package is based on `thesis.cls', written by 
%                Wenzel Matiaske (mati1831@perform.ww.tu-berlin.de)
%                Copyright (C) 1991, 1996.  Version 1.0g (1996/25/01).
%                Revised in July 2003, to adhere to NTUA's ECE library
%                policy for diploma projects and doctoral dissertations.


% Package information
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\def\filename{softlab-thesis}
\def\fileversion{1.3a}
\def\filedate{2010/10/26}
\NeedsTeXFormat{LaTeX2e}
\ProvidesClass{softlab-thesis}[\filedate\space\fileversion\space%
       LaTeX document class (nsp).]

% Options and related stuff
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\newcommand\@ptsize{}
\newif\if@openright
\newif\if@openbib
\@openbibfalse
\newif\if@mainmatter \@mainmattertrue
\DeclareOption{a4paper}
   {\setlength\paperheight {297mm}%
    \setlength\paperwidth  {210mm}}
\DeclareOption{a5paper}
   {\setlength\paperheight {210mm}%
    \setlength\paperwidth  {148mm}}
\DeclareOption{b5paper}
   {\setlength\paperheight {250mm}%
    \setlength\paperwidth  {176mm}}
\DeclareOption{letterpaper}
   {\setlength\paperheight {11in}%
    \setlength\paperwidth  {8.5in}}
\DeclareOption{legalpaper}
   {\setlength\paperheight {14in}%
    \setlength\paperwidth  {8.5in}}
\DeclareOption{executivepaper}
   {\setlength\paperheight {10.5in}%
    \setlength\paperwidth  {7.25in}}
\DeclareOption{landscape}
   {\setlength\@tempdima   {\paperheight}%
    \setlength\paperheight {\paperwidth}%
    \setlength\paperwidth  {\@tempdima}}
\DeclareOption{10pt}{\renewcommand\@ptsize{0}}
\DeclareOption{11pt}{\renewcommand\@ptsize{1}}
\DeclareOption{12pt}{\renewcommand\@ptsize{2}}
\DeclareOption{oneside}{\@twosidefalse \@mparswitchfalse}
\DeclareOption{twoside}{\@twosidetrue  \@mparswitchtrue}
\newif\if@greek \@greekfalse
\DeclareOption{greek}{\@greektrue}
\DeclareOption{english}{\@greekfalse}
\newcount\c@type
\DeclareOption{diploma}{\c@type=1}
\DeclareOption{master}{\c@type=2}
\DeclareOption{dissertation}{\c@type=3}
\newcount\hours \newcount\minutes
\def\SetTime{\hours=\time
        \global\divide\hours by 60
        \minutes=\hours
        \multiply\minutes by 60
        \advance\minutes by-\time
        \global\multiply\minutes by-1 }
\def\now{\number\hours:\ifnum\minutes<10 0\fi\number\minutes}
\newif\iffinal \finaltrue
\DeclareOption{draft}{\setlength\overfullrule{5pt}\finalfalse \SetTime}
\DeclareOption{final}{\setlength\overfullrule{0pt}\finaltrue}
\newif\if@crosshair       \@crosshairfalse
\DeclareOption{crosshair}{\@crosshairtrue}
\DeclareOption{nocrosshair}{\@crosshairfalse}
\newif\if@itemization     \@itemizationtrue
\DeclareOption{itemize}  {\@itemationtrue}
\DeclareOption{noitemize}{\@itemizationfalse}
\newif\if@enumeration       \@enumerationtrue
\DeclareOption{enumerate}  {\@enumerationtrue}
\DeclareOption{noenumerate}{\@enumerationfalse}
\newif\if@noind          \@noindfalse
\DeclareOption{indent}  {\@noindfalse}
\DeclareOption{noindent}{\@noindtrue}
\newif\if@center         \@centerfalse
\DeclareOption{center}  {\@centertrue}
\DeclareOption{nocenter}{\@centerfalse}
\newif\if@upper        \@upperfalse
\DeclareOption{upper}  {\@uppertrue}
\DeclareOption{noupper}{\@upperfalse}
\newif\if@contpage        \@contpagetrue
\DeclareOption{contpage}  {\@contpagetrue}
\DeclareOption{nocontpage}{\@contpagefalse}
\def\partfont#1{\def\p@font{#1}}             \def\p@font{}
\def\chapterfont#1{\def\c@font{#1}}          \def\c@font{}
\def\chapterauthorfont#1{\def\ca@font{#1}}   \def\ca@font{}
\def\sectionfont#1{\def\s@font{#1}}          \def\s@font{}
\def\subsectionfont#1{\def\ss@font{#1}}      \def\ss@font{}
\def\subsubsectionfont#1{\def\sss@font{#1}}  \def\sss@font{}
\def\paragraphfont#1{\def\pg@font{#1}}       \def\pg@font{}
\def\subparagraphfont#1{\def\spg@font{#1}}   \def\spg@font{}
\def\titlefont#1{\def\t@font{#1}}            \def\t@font{}
\def\subtitlefont#1{\def\st@font{#1}}        \def\st@font{}
\def\authorfont#1{\def\a@font{#1}}           \def\a@font{}
\def\institutionfont#1{\def\in@font{#1}}     \def\in@font{}
\def\schoolfont#1{\def\sc@font{#1}}          \def\sc@font{}
\def\departmentfont#1{\def\dp@font{#1}}      \def\dp@font{}
\def\thesistypefont#1{\def\ty@font{#1}}      \def\ty@font{}

\def\theoremheaderfont#1{\def\thh@font{#1}}  \def\thh@font{}
\def\theorembodyfont#1{\def\thb@font{#1}}    \def\thb@font{}
\def\itemfont#1{\def\item@font{#1}}          \def\item@font{}
\def\examplefont#1{\def\ex@font{#1}}         \def\ex@font{}
\def\headingstextfont#1{\def\h@font{#1}}     \def\h@font{}
\def\pagenumberfont#1{\def\pn@font{#1}}      \def\pn@font{}
\def\captionheaderfont#1{\def\cph@font{#1}}  \def\cph@font{}
\def\captionbodyfont#1{\def\cpb@font{#1}}    \def\cpb@font{}
\def\figurefont#1{\def\fig@font{#1}}         \def\fig@font{}
\def\tablefont#1{\def\tab@font{#1}}          \def\tab@font{}
\def\indexsize#1{\def\index@size{#1}}        \def\index@size{}
\def\bibsize#1{\def\bib@size{#1}}            \def\bib@size{}
\DeclareOption{slanted}{
    \partfont{\Large}
    \chapterfont{\large}
    \chapterauthorfont{\large}
    \sectionfont{\large\slshape}
    \subsectionfont{\slshape}
    \subsubsectionfont{\slshape}
    \paragraphfont{\slshape}
    \subparagraphfont{\slshape}
    \titlefont{\LARGE}
    \subtitlefont{\large}
    \authorfont{}
    \institutionfont{\slshape}
    \schoolfont{\slshape}
    \departmentfont{\slshape}
    \thesistypefont{}
    \theoremheaderfont{\upshape}
    \theorembodyfont{}
    \itemfont{\slshape}
    \examplefont{}
    \headingstextfont{\small\slshape}
    \pagenumberfont{\small}
    \captionheaderfont{\slshape\small}
    \captionbodyfont{\small}
    \figurefont{}
    \tablefont{}
}
\DeclareOption{bold}{%
    \partfont{\LARGE\bfseries}
    \chapterfont{\LARGE\bfseries}
    \chapterauthorfont{\large}
    \sectionfont{\Large\bfseries}
    \subsectionfont{\large\bfseries}
    \subsubsectionfont{\bfseries}
    \paragraphfont{\bfseries}
    \subparagraphfont{\bfseries}
    \titlefont{\LARGE\bfseries}
    \subtitlefont{\large}
    \authorfont{}
    \thesistypefont{}
    \institutionfont{\slshape}
    \schoolfont{\slshape}
    \departmentfont{\slshape}
    \theoremheaderfont{\bfseries}
    \theorembodyfont{\itshape}
    \itemfont{\bfseries}
    \examplefont{}
    \headingstextfont{\small\bfseries}
    \pagenumberfont{\small}
    \captionheaderfont{\bfseries}
    \captionbodyfont{}
    \figurefont{}
    \tablefont{}
}
\DeclareOption{sfbold}{%
    \partfont{\LARGE\sffamily\bfseries}
    \chapterfont{\LARGE\sffamily\bfseries}
    \chapterauthorfont{\Large\sffamily\bfseries}
    \sectionfont{\large\sffamily\bfseries}
    \subsectionfont{\large\sffamily\bfseries}
    \subsubsectionfont{\sffamily\bfseries}
    \paragraphfont{\sffamily\bfseries}
    \subparagraphfont{\sffamily}
    \titlefont{\LARGE\sffamily\bfseries}
    \subtitlefont{\large\sffamily}
    \authorfont{\Large\sffamily\slshape}
    \thesistypefont{}
    \institutionfont{\sffamily}
    \schoolfont{\sffamily}
    \departmentfont{\sffamily}
    \theoremheaderfont{\sffamily}
    \theorembodyfont{}
    \itemfont{\sffamily}
    \examplefont{}
    \headingstextfont{\small\sffamily}
    \pagenumberfont{\small\rmfamily}
    \captionheaderfont{\sffamily}
    \captionbodyfont{}
    \figurefont{}
    \tablefont{}
}
\DeclareOption{openright}{\@openrighttrue}
\DeclareOption{openany}{\@openrightfalse}
\DeclareOption{leqno}{\input{leqno.clo}}
\DeclareOption{fleqn}{\input{fleqn.clo}}
\DeclareOption{openbib}{\@openbibtrue}
\newif\if@chapterbib \@chapterbibfalse
\DeclareOption{chapterbib}{\@chapterbibtrue}
\ExecuteOptions{a4paper,11pt,twoside,final,openright,%
                bold,nocenter,noupper,greek,contpage}

\ProcessOptions*

\ifnum\c@type=0
  \ClassError{softlab-thesis}{Undefined type of thesis}{%
    Please, give one of the options: diploma, master, dissertation%
  }
\fi


% Miscellaneous settings
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\input{bk1\@ptsize.clo}
\setlength\lineskip{1\p@}
\setlength\normallineskip{1\p@}
\renewcommand\baselinestretch{}
\if@noind
  \setlength\parskip{0.5\baselineskip
         \@plus.1\baselineskip \@minus.1\baselineskip}
  \setlength\parindent{\z@}
  \def\noparskip{\par\vspace{-\parskip}}
\else
  \setlength\parskip{0\p@ \@plus 1\p@}
  \let\noparskip\relax
\fi
\@lowpenalty   51
\@medpenalty  151
\@highpenalty 301
\setcounter{topnumber}{3}
\renewcommand\topfraction{.8}
\setcounter{bottomnumber}{2}
\renewcommand\bottomfraction{.8}
\setcounter{totalnumber}{5}
\renewcommand\textfraction{.2}
\renewcommand\floatpagefraction{.8}
\setcounter{dbltopnumber}{2}
\renewcommand\dbltopfraction{.8}
\renewcommand\dblfloatpagefraction{.8}
\def\e@skip{\h@font{\phantom{y}}}

% Required packages
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\RequirePackage{graphicx}
\RequirePackage{fontspec}
%\RequirePackage{xunicode}
%\RequirePackage{xltxtra}
\defaultfontfeatures{Mapping=tex-text}
\RequirePackage[english]{babel}
\RequirePackage{xgreek}

% Headings
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\if@twoside
  \def\ps@headings{
    \def\@oddfoot{\vbox{\hsize=\textwidth
      \hbox to \textwidth{%
      \hfill{\pn@font\thepage}\if@center\hfill\fi}}}
    \def\@evenfoot{\vbox{\hsize=\textwidth
      \hbox to \textwidth{%
      \if@center\hfill\fi{\pn@font\thepage}\hfill}}}
    \let\@oddhead\relax
    \let\@evenhead\relax
    \let\@mkboth\markboth
    \def\chaptermark##1{%
      \markboth {%
        \ifnum \c@secnumdepth >\m@ne
          \if@mainmatter
            \@chapapp\ \thechapter. \ %
          \fi
        \fi
        ##1}{}}%
    \def\sectionmark##1{%
      \markright {%
        \ifnum \c@secnumdepth >\z@
            \thesection. \ %
        \fi
        ##1}}}
\else
  \def\ps@headings{%
    \def\@oddfoot{\vbox{\hsize=\textwidth
      \hbox to \textwidth{%
      \hfill{\pn@font\thepage}\if@center\hfill\fi}}}
    \let\@oddhead\relax
    \let\@mkboth\markboth
    \def\chaptermark##1{%
      \markright {%
        \ifnum \c@secnumdepth >\m@ne
          \if@mainmatter
            \@chapapp\ \thechapter. \ %
          \fi
        \fi
        ##1}}}
\fi
\def\ps@myheadings{%
    \def\@oddfoot{\vbox{\hsize=\textwidth
      \hbox to \textwidth{%
      \hfill{\pn@font\thepage}\if@center\hfill\fi}}}
    \def\@evenfoot{\vbox{\hsize=\textwidth
      \hbox to \textwidth{%
      \if@center\hfill\fi{\pn@font\thepage}\hfill}}}
    \let\@oddhead\relax
    \let\@evenhead\relax
    \let\@mkboth\@gobbletwo
    \let\chaptermark\@gobble
    \let\sectionmark\@gobble
    }
\def\ps@draft{%
    \def\@oddfoot{\vbox{\hsize=\textwidth
      \hbox to \textwidth{%
      \hfill{\pn@font\thepage}\if@center\hfill\fi}}}
    \def\@evenfoot{\vbox{\hsize=\textwidth
      \hbox to \textwidth{%
      \if@center\hfill\fi{\pn@font\thepage}\hfill}}}
    \def\@oddhead{\vbox{\hsize=\textwidth
      \hbox to \textwidth{%
      \hfill{\pn@font\today,\ \now\ ---
      {\h@font \draftname: ``\jobname''}}\if@center\hfill\fi}}}%
    \def\@evenhead{\vbox{\hsize=\textwidth
       \hbox to \textwidth{%
       \if@center\hfill\fi{\pn@font{\h@font \draftname: ``\jobname''} ---
       \today,\ \now}\hfill}}}%
    \let\@mkboth\@gobbletwo
    \let\chaptermark\@gobble
    \let\sectionmark\@gobble
    }
\@ifundefined{option@crosshair}{}{%
  \def\clap#1{\hbox to 0pt{\hss#1\hss}} \newdimen\@crosshairrule
  \@crosshairrule=.24pt \def\@crosshairs{\vbox to
    0pt{\hsize=0pt\baselineskip=0pt\lineskip=0pt \vss \clap{\vrule
        height .125in width \@crosshairrule depth 0pt} \clap{\vrule
        width .25in height \@crosshairrule depth 0pt} \clap{\vrule
        height .125in width \@crosshairrule depth 0pt} \vss}}
 \def\ps@empty{%
    \let\@oddfoot\@empty\let\@evenfoot\@empty
    \def\@oddhead{\hfill\raise\headheight\@crosshairs}
    \let\@evenhead\@oddhead}}

% Title page and front matter
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\def\@supervisor{}       \def\supervisor#1{\gdef\@supervisor{#1}}
\def\@supervisor@pos{}   \def\supervisorpos#1{\gdef\@supervisor@pos{#1}}
\def\@committee@one{}    \def\committeeone#1{\gdef\@committee@one{#1}}
\def\@committee@one@pos{}\def\committeeonepos#1{\gdef\@committee@one@pos{#1}}
\def\@committee@two{}    \def\committeetwo#1{\gdef\@committee@two{#1}}
\def\@committee@two@pos{}\def\committeetwopos#1{\gdef\@committee@two@pos{#1}}
\def\@committee@three{}  \def\committeethree#1{\gdef\@committee@three{#1}}
\def\@committee@three@pos{}\def\committeethreepos#1{\gdef\@committee@three@pos{#1}}
\def\@subtitle{}         \def\subtitle#1{\gdef\@subtitle{#1}}
\def\@thesistype{}       \def\thesistype#1{\gdef\@thesistype{#1}}
\def\@institution{}      \def\institution#1{\gdef\@institution{#1}}
\def\@school{}           \def\school#1{\gdef\@school{#1}}
\def\@department{}       \def\department#1{\gdef\@department{#1}}
\def\@dedication{}       \def\dedication#1{\def\@dedication{#1}}
\def\@uppertitleback{}   \long\def\uppertitleback#1{\def\@uppertitleback{#1}}
\def\@middletitleback{}  \long\def\middletitleback#1{\def\@middletitleback{#1}}
\def\@lowertitleback{}   \long\def\lowertitleback#1{\def\@lowertitleback{#1}}
\def\@date@defense{}     \def\datedefense#1#2#3{%
                           \gdef\@date@defense{#1η\ \@date@month@gen[#2]\ #3}%
                           \gdef\@date@defenseen{\@date@month[#2]\ #1,\ #3}%
                           \gdef\@date{\@date@month@nom[#2]\ #3}%
                           \gdef\@dateen{\@date@month[#2]\ #3}%
                           \gdef\@date@year{#3}%
                         }
                         \def\url#1{\gdef\@url{\texttt{#1}}}
\def\@TRnumber{}         \def\TRnumber#1{\gdef\@TRnumber{#1}}
\def\@trurl{}            \def\trurl#1{\gdef\@trurl{\texttt{#1}}}
\def\@trftp{}            \def\trftp#1{\gdef\@trftp{\texttt{#1}}}

\def\new@tpage{\newpage\thispagestyle{empty}\null}

\def\authoren#1{\gdef\@authoren{#1}}
\def\@author@and{\end{tabular}\hskip 1em plus.17fil
  \begin{tabular}[t]{@{}l@{}}}
\def\@committeemembers@and{\\ &}
\let\and\relax

\newcommand\@date@month[1][\month]{%
  \ifcase#1\or January\or February\or March\or April\or
    May\or June\or July\or August\or
     September\or October\or November\or December\fi}
\newcommand\@date@month@nom[1][\month]{%
  \ifcase#1\or Ιανουάριος\or Φεβρουάριος\or Μάρτιος\or Απρίλιος\or
    Μάιος\or Ιούνιος\or Ιούλιος\or Αύγουστος\or
     Σεπτέμβριος\or Οκτώβριος\or Νοέμβριος\or Δεκέμβριος\fi}
\newcommand\@date@month@gen[1][\month]{%
  \ifcase#1\or Ιανουαρίου\or Φεβρουαρίου\or Μαρτίου\or Απριλίου\or
    Μαΐου\or Ιουνίου\or Ιουλίου\or Αυγούστου\or
     Σεπτεμβρίου\or Οκτωβρίου\or Νοεμβρίου\or Δεκεμβρίου\fi}

\def\maketitle{%
  \begingroup
%
  \cleardoublepage
  \newpage
  \thispagestyle{empty}%
  \if@compatibility
    \setcounter{page}{0}
  \fi
%
  \let\footnotesize\small
  \let\footnoterule\relax
  \def\thefootnote{\fnsymbol{footnote}}
  \new@tpage
%
  \noindent
  \begin{minipage}{4.0cm}
  \includegraphics[height=3.5cm]{pyrforos}%
  \end{minipage}
  \begin{minipage}{11.0cm}
  \raggedright%
  \renewcommand\baselinestretch{1.2}\normalsize%
  {\in@font\@institution} \\
  {\sc@font\@school} \\[3pt]
  {\dp@font\@department}
  \end{minipage}
%
  \vfill
%
  \begin{center}
  \renewcommand\baselinestretch{1.8}\normalsize%
  {\t@font\@title}
  \end{center}
  \ifx\@subtitle\@empty\else
  \vspace{1cm}
  \begin{center}
  {\st@font\@subtitle}
  \end{center}
  \fi
%
  \vspace{1cm}
%
  \begin{center}
%
  {\ty@font\uppercase\expandafter{\@thesistype}} \\
%
  \vspace{1cm}
  \let\old@and\and%
  \let\and\@author@and%                           
  {\a@font%
  \begin{tabular}[t]{@{}l@{}}%
  \uppercase\expandafter{\@author}%
  \end{tabular}}%
  \let\and\old@and%
  \end{center}
%
  \vfill
%
  {\st@font%
  \textbf{\supervisorname~:\ \ }
  \begin{tabular}[t]{@{}l@{}}
    \@supervisor \\[6pt]
    \@supervisor@pos
  \end{tabular}}
%
  \vfill
%
  \begin{center}
  {\st@font Αθήνα, \@date}
  \end{center}
%
  \cleardoublepage
  \newpage
  \thispagestyle{empty}%
%
  \let\footnotesize\small
  \let\footnoterule\relax
  \def\thefootnote{\fnsymbol{footnote}}
  \new@tpage
%
  \noindent%
  \begin{minipage}{4.0cm}
  \includegraphics[height=3.5cm]{pyrforos}%
  \end{minipage}
  \begin{minipage}{11.0cm}
  \raggedright%
  \renewcommand\baselinestretch{1.2}\normalsize%
  {\in@font\@institution} \\
  {\sc@font\@school} \\[3pt]
  {\dp@font\@department}
  \end{minipage}
%
  \vfill
%
  \begin{center}
  \renewcommand\baselinestretch{1.8}\normalsize%
  {\t@font\@title}
  \end{center}
  \ifx\@subtitle\@empty\else
  \vspace{1cm}
  \begin{center}
  {\st@font\@subtitle}
  \end{center}
  \fi
%
  \vspace{1cm}
%
  \begin{center}
%
  {\ty@font\uppercase\expandafter{\@thesistype}} \\
%
  \vspace{1cm}
  \let\old@and\and%
  \let\and\@author@and%                           
  {\a@font%
  \begin{tabular}[t]{@{}l@{}}%
  \uppercase\expandafter{\@author}%
  \end{tabular}}%
  \let\and\old@and%
  \end{center}
%
  \vfill
%
  {\st@font%
  \textbf{\supervisorname~:\ \ }
  \begin{tabular}[t]{@{}l@{}}
    \@supervisor \\[6pt]
    \@supervisor@pos
  \end{tabular}
%
  \vspace{1.0cm}\par
%
  \noindent
  Εγκρίθηκε από την τριμελή εξεταστική επιτροπή την \@date@defense.
  }
%
  \vspace{1.5cm}\par
%
  \noindent{\small
  \hfill
  \begin{tabular}{@{}l@{}}
    \signature{\@committee@one}{\@committee@one@pos}
  \end{tabular}
  \hfill
  \begin{tabular}{@{}l@{}}
    \signature{\@committee@two}{\@committee@two@pos}
  \end{tabular}
  \hfill
  \begin{tabular}{@{}l@{}}
    \signature{\@committee@three}{\@committee@three@pos}
  \end{tabular}
  \hfill
  \hbox{}
  }
%
  \vfill
%
  \begin{center}
  {\st@font Αθήνα, \@date}
  \end{center}
%
  \if@twoside\new@tpage
  \noindent\begin{minipage}[t]{\textwidth}
  \@uppertitleback
  \end{minipage}\par
  \vfill
  \noindent\begin{minipage}[t]{\textwidth}
  \@middletitleback
  \end{minipage}\par
  \vfill
  \noindent\begin{minipage}[b]{\textwidth}
  \@lowertitleback
  \end{minipage}
  \fi
  \ifx\@dedication\@empty\else \new@tpage
       {\centering \Large \@dedication \par}
       \if@twoside \new@tpage \fi
  \fi
%
  \newpage
  \endgroup
%
  \def\thefootnote{\arabic{footnote}}
  \setcounter{footnote}{0}
  \gdef\@thanks{}%
  \gdef\@uppertitleback{}\gdef\@lowertitleback{}\gdef\@dedication{}%
  \let\maketitle\relax%
}
\def\abstractgr{%
  \setlanguage{monogreek}%
  \chapter*{\abstractnamegr\@mkboth{\abstractnamegr}{\abstractnamegr}}%
  \addcontentsline{toc}{chapter}{\abstractnamegr}%
  \noindent\ignorespaces}
\def\endabstractgr{\par\vfil\null}
\def\abstracten{%
  \selectlanguage{english}%
  \chapter*{\abstractnameen\@mkboth{\abstractnameen}{\abstractnameen}}%
  \addcontentsline{toc}{chapter}{\abstractnameen}%
  \noindent\ignorespaces}
\def\endabstracten{\par\vfil\null}

% Sectioning
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\newcommand*{\chaptermark}[1]{}
\setcounter{secnumdepth}{2}
\newcounter {part}
\newcounter {chapter}
\newcounter {section}[chapter]
\newcounter {subsection}[section]
\newcounter {subsubsection}[subsection]
\newcounter {paragraph}[subsubsection]
\newcounter {subparagraph}[paragraph]
\renewcommand{\thepart}         {\Roman{part}}
\renewcommand{\thechapter}      {\arabic{chapter}}
\renewcommand{\thesection}      {\thechapter.\arabic{section}}
\renewcommand{\thesubsection}   {\thesection.\arabic{subsection}}
\renewcommand{\thesubsubsection}{\thesubsection .\arabic{subsubsection}}
\renewcommand{\theparagraph}    {\thesubsubsection.\arabic{paragraph}}
\renewcommand{\thesubparagraph} {\theparagraph.\arabic{subparagraph}}
\def\chapapp#1{\def\@chapapp{#1}}      \def\@chapapp{}
\newcommand{\frontmatter}{\cleardoublepage\@mainmatterfalse%
  \if@contpage\else\pagenumbering{roman}\fi}
\newcommand{\mainmatter}{%
  \ifodd\c@page
    \clearpage\thispagestyle{empty}\hbox{}%
  \fi%
  \label{pg:last-front}%
  \clearpage\@mainmattertrue%
  \if@contpage\else\pagenumbering{arabic}\fi%
  \addtocontents{toc}{\protect\addvspace{1em}}}
\newcommand{\backmatter}{\if@openright\cleardoublepage\else\clearpage\fi
      \@mainmatterfalse}
\newcommand{\part}{\cleardoublepage
    \thispagestyle{empty}%
    \vspace*{\beforechaptervspace}%
    \secdef\@part\@spart}
\def\@part[#1]#2{%
    \ifnum \c@secnumdepth >-2\relax \refstepcounter{part}
      \addcontentsline{toc}{part}{\partname\ \thepart \hspace{1em}#1}%
    \else
     \addcontentsline{toc}{part}{#1}\fi \markboth{}{}%
     {\raggedright
      \reset@font
      \ifnum \c@secnumdepth >-2\relax
        \p@font \partname{} \thepart \par
         \vskip 20pt
      \fi
      \p@font
      \if@upper
        \uppercase{#2}
      \else #2
      \fi
  \par}
\@endpart}
\def\@spart#1{%
      {\raggedright
       \reset@font\p@font
       \if@upper
          \uppercase\expandafter{#1}
       \else #1%
       \fi\par}
  \@endpart}
\def\@endpart{\vfil\newpage
              \if@twoside
                \hbox{}%
                \thispagestyle{empty}%
                \newpage
              \fi}
\newcommand{\chapter}{\if@openright\cleardoublepage\else\clearpage\fi
                    %\thispagestyle{empty}
                    \global\@topnum\z@
                    \@afterindentfalse
                    \secdef\@chapter\@schapter}
\def\@chapter[#1]#2{%
    \ifnum \c@secnumdepth >\m@ne
       \if@mainmatter
          \refstepcounter{chapter}%
          \typeout{\chaptername\space\thechapter.}
          \addcontentsline{toc}{chapter}{%
          \protect\numberline{\thechapter.}#1}%
      \else
        \addcontentsline{toc}{chapter}{#1}
      \fi
   \else
      \addcontentsline{toc}{chapter}{#1}
   \fi
   \chaptermark{#1}
   \addtocontents{lof}{\protect\addvspace{10pt}}
   \addtocontents{lot}{\protect\addvspace{10pt}}
   \@makechapterhead{#2}
   \@afterheading}
\newlength{\beforechaptervspace}
\setlength{\beforechaptervspace}{50pt}
\newlength{\afterchaptervspace}
\setlength{\afterchaptervspace}{30pt}
\def\@makechapterhead#1{%
  \vspace*{\beforechaptervspace}{%
  \ifx\@chapapp\@empty
    \raggedright
    \ifnum \c@secnumdepth >\m@ne
      \setbox\@tempboxa\hbox{\c@font\thechapter.\ %
        \c@font
        \if@upper
          \uppercase{#1}
        \else
          #1%
        \fi}
      \ifdim \wd\@tempboxa >\hsize
        \@hangfrom{\c@font\thechapter.\ }%
                  {\c@font
		   \if@upper
		     \uppercase{#1}
		   \else
		     #1%
		   \fi
		   \par\nobreak}
      \else
           \hbox to\hsize{\box\@tempboxa\hfil}
      \fi
    \fi
  \else
    \raggedright
    \ifnum \c@secnumdepth >\m@ne
      \if@mainmatter
         {\s@font \@chapapp{} \thechapter}
         \par \vskip 15\p@
      \fi
    \fi
    {\c@font
    \if@upper
       \uppercase{#1}
    \else
      #1%
    \fi
    \par \nobreak}
  \fi
  \vspace{\afterchaptervspace}}
}
\def\@schapter#1{\@makeschapterhead{#1}\@afterheading}
\def\@makeschapterhead#1{%
   \vspace*{\beforechaptervspace}{%
     \parindent\z@\raggedright
     {\c@font
     \if@upper
       \uppercase\expandafter{#1}
     \else
        #1%
     \fi
     \par\nobreak
     \vskip 30\p@}
     }}
\newcommand\section{\@startsection {section}{1}{\z@}%
                                   {-3.5ex \@plus -1ex \@minus -.2ex}%
                                   {2.3ex \@plus.2ex}%
                                   {\raggedright\reset@font\s@font}}
\newcommand\subsection{\@startsection{subsection}{2}{\z@}%
                                     {-3.25ex\@plus -1ex \@minus -.2ex}%
                                     {1.5ex \@plus .2ex}%
                                     {\raggedright\reset@font\ss@font}}
\newcommand\subsubsection{\@startsection{subsubsection}{3}{\z@}%
                                     {-3.25ex\@plus -1ex \@minus -.2ex}%
                                     {1.5ex \@plus .2ex}%
                                     {\raggedright\reset@font\sss@font}}
\newcommand\paragraph{\@startsection{paragraph}{4}{\z@}%
                                    {3.25ex \@plus1ex \@minus.2ex}%
                                    {-1em}%
                                    {\reset@font\pg@font}}
\newcommand\subparagraph{\@startsection{subparagraph}{5}{\parindent}%
                                       {3.25ex \@plus1ex \@minus .2ex}%
                                       {-1em}%
                                      {\reset@font\spg@font}}
\newcommand\appendix{\par
  \setcounter{chapter}{0}%
  \setcounter{section}{0}%
  \ifx\@chapapp\@empty
    \def\@addappendixtocontents{\addcontentsline{toc}{part}{\appendixname}}
    \part*{\appendixname\@mkboth{\appendixname}{\appendixname}%%
           \@addappendixtocontents}
  \else
    \renewcommand{\@chapapp}{\appendixname}%
  \fi
  \renewcommand{\thechapter}{\Alph{chapter}}}

% Space lengths
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\setlength\leftmargini  {2.5em}
\setlength\leftmarginii  {2.2em}
\setlength\leftmarginiii {1.87em}
\setlength\leftmarginiv  {1.7em}
\setlength\leftmarginv  {1em}
\setlength\leftmarginvi {1em}
\setlength\leftmargin    {\leftmargini}
\setlength  \labelsep  {.5em}
\setlength  \labelwidth{\leftmargini}
\addtolength\labelwidth{-\labelsep}
\@beginparpenalty -\@lowpenalty
\@endparpenalty   -\@lowpenalty
\@itempenalty     -\@lowpenalty
\if@enumeration
  \renewcommand\theenumi{\arabic{enumi}}
  \renewcommand\theenumii{\alph{enumii}}
  \renewcommand\theenumiii{\roman{enumiii}}
  \renewcommand\theenumiv{\Alph{enumiv}}
  \newcommand\labelenumi{\theenumi.}
  \newcommand\labelenumii{(\theenumii)}
  \newcommand\labelenumiii{\theenumiii.}
  \newcommand\labelenumiv{\theenumiv.}
  \renewcommand\p@enumii{\theenumi}
  \renewcommand\p@enumiii{\theenumi(\theenumii)}
  \renewcommand\p@enumiv{\p@enumiii\theenumiii}
\else
  \renewcommand\theenumi{\arabic{enumi}}
  \renewcommand\theenumii{\arabic{enumii}}
  \renewcommand\theenumiii{\arabic{enumiii}}
  \renewcommand\theenumiv{\arabic{enumiv}}
  \newcommand\labelenumi{\theenumi.}
  \newcommand\labelenumii{\theenumi.\theenumii.}
  \newcommand\labelenumiii{\theenumi.\theenumii.\theenumiii.}
  \newcommand\labelenumiv{\theenumi.\theenumii.\theenumiii.\theenumiv.}
  \renewcommand\p@enumii{\theenumi}
  \renewcommand\p@enumiii{\theenumi(\theenumii)}
  \renewcommand\p@enumiv{\p@enumiii\theenumiii}
\fi
\if@itemization
  \newcommand\labelitemi{$\m@th\bullet$}
  \newcommand\labelitemii{\normalfont\bfseries --}
  \newcommand\labelitemiii{$\m@th\ast$}
  \newcommand\labelitemiv{$\m@th\cdot$}
\else
  \newcommand\labelitemi{\bfseries --}
  \newcommand\labelitemii{\bfseries --}
  \newcommand\labelitemiii{\bfseries --}
  \newcommand\labelitemiv{\bfseries --}
\fi

% Some new environments
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\newenvironment{description}
               {\list{}{\labelwidth\z@ \itemindent-\leftmargin
                        \let\makelabel\descriptionlabel}}
               {\endlist}
\newcommand\descriptionlabel[1]{\hspace\labelsep
                                \item@font #1}
\newenvironment{verse}
               {\let\\=\@centercr
                \list{}{\itemsep      \z@
                        \itemindent   -1.5em%
                        \listparindent\itemindent
                        \rightmargin  \leftmargin
                        \advance\leftmargin 1.5em}%
                \item[]}
               {\endlist}
\newenvironment{quotation}
               {\list{}{\listparindent 1.5em%
                        \itemindent    \listparindent
                        \rightmargin   \leftmargin
                        \parsep        \z@ \@plus\p@}%
                \item[]}
               {\endlist}
\newenvironment{quote}
               {\list{}{\rightmargin\leftmargin}%
                \item[]}
               {\endlist}
\def\@begintheorem#1#2{\reset@font\thb@font\trivlist
      \item[\hskip \labelsep{\reset@font\thh@font #1\ #2:}]}
\def\@opargbegintheorem#1#2#3{\reset@font\thb@font\trivlist
      \item[\hskip \labelsep{\reset@font\thh@font #1\ #2\ (#3):}]}
\def\@endtheorem{\endtrivlist}
\newlength{\exampleindent}    \setlength{\exampleindent}{\parindent}
\newenvironment{example}%
   {\begin{list}{}{%
    \setlength{\leftmargin}{\exampleindent}}
    \ex@font \item[]}
   {\end{list}}
\newenvironment{describe}[1][\quad]%
  {\begin{list}{}{%
    \renewcommand{\makelabel}[1]{{\item@font ##1}\hfil}%
    \settowidth{\labelwidth}{{\item@font #1}}%
    \setlength{\leftmargin}{\labelwidth}%
    \addtolength{\leftmargin}{\labelsep}}}%
  {\end{list}}

% More lengths and settings
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\setlength\arraycolsep{5\p@}
\setlength\tabcolsep{6\p@}
\setlength\arrayrulewidth{.4\p@}
\setlength\doublerulesep{2\p@}
\setlength\tabbingsep{\labelsep}
\skip\@mpfootins = \skip\footins
\setlength\fboxsep{3\p@}
\setlength\fboxrule{.4\p@}
\@addtoreset{equation}{chapter}
\renewcommand{\theequation}{\thechapter.\arabic{equation}}
\def\marginlabel#1{\marginpar%
   {\if@twoside
       \ifodd\c@page
          \raggedright
       \else
          \raggedleft
       \fi
     \else
        \raggedright
     \fi #1}}
\def\attention{\mbox{}%
    \marginpar[\raggedleft\large\bf! $\rightarrow$]%
        {\raggedright\large\bf $\leftarrow$ !}}
\def\seealso#1{\mbox{}%
    \marginpar[\raggedleft$\rightarrow$ \small #1]%
        {\raggedright\small  #1 $\leftarrow$}\ignorespaces}

% Floating environments
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\newcounter{figure}[chapter]
\renewcommand{\thefigure}{\thechapter.\@arabic\c@figure}
\def\fps@figure{tbp}
\def\ftype@figure{1}
\def\ext@figure{lof}
\def\fnum@figure{\figureshortname~\thefigure}
\newenvironment{figure}
               {\fig@font\@float{figure}}
               {\end@float}
\newenvironment{figure*}
               {\fig@font\@dblfloat{figure}}
               {\end@dblfloat}
\newcounter{table}[chapter]
\renewcommand{\thetable}{\thechapter.\@arabic\c@table}
\def\fps@table{tbp}
\def\ftype@table{2}
\def\ext@table{lot}
\def\fnum@table{\tableshortname~\thetable}
\newenvironment{table}
               {\tab@font\@float{table}}
               {\end@float}
\newenvironment{table*}
               {\tab@font\@dblfloat{table}}
               {\end@dblfloat}
\newlength\abovecaptionskip
\newlength\belowcaptionskip
\setlength\abovecaptionskip{10\p@}
\setlength\belowcaptionskip{0\p@}
\long\def\@makecaption#1#2{%
 \vskip\abovecaptionskip
 \setbox\@tempboxa\hbox{{\cph@font #1:} {\cpb@font #2}}%
 \ifdim \wd\@tempboxa >\hsize
    \@hangfrom{\cph@font #1: }{\cpb@font #2\par}%
 \else
    \hbox to\hsize{\hfil\box\@tempboxa\hfil}%
 \fi
 \vskip\belowcaptionskip}
\def\rb#1{\raisebox{1.5ex}[-1.5ex]{#1}}
\def\tablerule{\noalign{\ifnum0=`}\fi
   \hrule \@height \arrayrulewidth \vskip\doublerulesep
   \futurelet \@tempa\@xhline}
\def\thicktablerule{\noalign{\ifnum0=`}\fi
   \hrule \@height 2\arrayrulewidth \vskip\doublerulesep
   \futurelet \@tempa\@xhline}
\def\doubletablerule{\noalign{\ifnum0=`}\fi
   \hrule \@height \arrayrulewidth \vskip2\arrayrulewidth
   \hrule \@height \arrayrulewidth \vskip\doublerulesep
   \futurelet \@tempa\@xhline}
\def\thickhline{\noalign{\ifnum0=`}\fi
   \hrule \@height 2\arrayrulewidth\futurelet \@tempa\@xhline}
\def\doublehline{\noalign{\ifnum0=`}\fi
   \hrule \@height \arrayrulewidth\vskip2\arrayrulewidth
   \hrule \@height \arrayrulewidth \futurelet \@tempa\@xhline}
\DeclareOldFontCommand{\rm}{\normalfont\rmfamily}{\mathrm}
\DeclareOldFontCommand{\sf}{\normalfont\sffamily}{\mathsf}
\DeclareOldFontCommand{\tt}{\normalfont\ttfamily}{\mathtt}
\DeclareOldFontCommand{\bf}{\normalfont\bfseries}{\mathbf}
\DeclareOldFontCommand{\it}{\normalfont\itshape}{\mathit}
\DeclareOldFontCommand{\sl}{\normalfont\slshape}{\@nomath\sl}
\DeclareOldFontCommand{\sc}{\normalfont\scshape}{\@nomath\sc}
\DeclareRobustCommand*{\cal}{\@fontswitch{\relax}{\mathcal}}
\DeclareRobustCommand*{\mit}{\@fontswitch{\relax}{\mathnormal}}
\newcommand{\@pnumwidth}{1.55em}
\newcommand{\@tocrmarg} {2.55em}
\newcommand{\@dotsep}{4.5}
\setcounter{tocdepth}{2}

% Table of contents, etc.
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\newcommand{\tableofcontents}{%
    \chapter*{\contentsname
        \@mkboth{\contentsname}%
                {\contentsname}}%
    \addcontentsline{toc}{chapter}{\contentsname}
    \@starttoc{toc}%
    }
\newcommand*{\l@part}[2]{%
  \ifnum \c@tocdepth >-2\relax
    \addpenalty{-\@highpenalty}%
    \addvspace{2.25em \@plus\p@}%
    \begingroup
      \setlength\@tempdima{3em}%
      \parindent \z@ \rightskip \@pnumwidth
      \parfillskip -\@pnumwidth
      {\leavevmode
       {\sss@font #1}\hfil \hbox to\@pnumwidth{\hss #2}}\par
       \nobreak
         \global\@nobreaktrue
         \everypar{\global\@nobreakfalse\everypar{}}
    \endgroup
  \fi}
\newcommand*{\l@chapter}[2]{%
  \ifnum \c@tocdepth >\m@ne
    \addpenalty{-\@highpenalty}%
    \vskip 1.0em \@plus\p@
    \setlength\@tempdima{1.5em}%
    \begingroup
      \parindent \z@ \rightskip \@pnumwidth
      \parfillskip -\@pnumwidth
      \leavevmode
      \advance\leftskip\@tempdima
      \hskip -\leftskip
      {\sss@font #1}%
      \nobreak\leaders\hbox{%
         $\m@th \mkern \@dotsep mu.\mkern \@dotsep mu$}
      \hfill\nobreak\hbox to\@pnumwidth{\hfil\textrm{#2}}\par
      \penalty\@highpenalty
    \endgroup
  \fi}
\newcommand*{\l@section}      {\@dottedtocline{1}{1.5em}{2.3em}}
\newcommand*{\l@subsection}   {\@dottedtocline{2}{3.8em}{3.2em}}
\newcommand*{\l@subsubsection}{\@dottedtocline{3}{7.0em}{4.1em}}
\newcommand*{\l@paragraph}    {\@dottedtocline{4}{10em}{5em}}
\newcommand*{\l@subparagraph} {\@dottedtocline{5}{12em}{6em}}
\newcommand{\listoffigures}{%
    \chapter*{\listfigurename
      \@mkboth{\listfigurename}%
              {\listfigurename}}%
    \addcontentsline{toc}{chapter}{\listfigurename}
    \@starttoc{lof}%
    }
\newcommand*{\l@figure}{\@dottedtocline{1}{1.5em}{2.3em}}
\newcommand{\listoftables}{%
    \chapter*{\listtablename
      \@mkboth{\listtablename}%
              {\listtablename}}%
    \addcontentsline{toc}{chapter}{\listtablename}
    \@starttoc{lot}%
    }
\let\l@table\l@figure

% Bibliography
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\newdimen\bibindent
\bibindent=1.5em
\newenvironment{thebibliography}[1]
     {\if@chapterbib
        \section*{\refname\@mkboth{\refname}{\refname}}%
        \addcontentsline{toc}{section}{\refname}%
      \else
        \chapter*{\bibname\@mkboth{\bibname}{\bibname}}%
        \addtocontents{toc}{\protect\addvspace{1em}}%
        \addcontentsline{toc}{chapter}{\bibname}%
        \addtocontents{toc}{\protect\addvspace{1em}}%
      \fi
      \list{\@biblabel{\arabic{enumiv}}}%
           {\settowidth\labelwidth{\@biblabel{#1}}%
            \leftmargin\labelwidth
            \advance\leftmargin\labelsep
            \if@openbib
              \advance\leftmargin\bibindent
              \itemindent -\bibindent
              \listparindent \itemindent
              \parsep \z@
            \fi
            \usecounter{enumiv}%
            \let\p@enumiv\@empty
            \renewcommand\theenumiv{\arabic{enumiv}}}%
      \if@openbib
        \renewcommand\newblock{\par}
      \else
        \renewcommand\newblock{\hskip .11em \@plus.33em \@minus.07em}%
      \fi
      \sloppy\clubpenalty4000\widowpenalty4000%
      \sfcode`\.=\@m}
     {\def\@noitemerr
       {\@latex@warning{Empty `thebibliography' environment}}%
      \endlist}
\newcommand\newblock{}
\if@chapterbib
  \def\@mainbblfile{\jobname.bbl}
  \let\@bblfile=\@mainbblfile
  \def\bibliography#1{%
    \if@filesw\immediate\write\@auxout{\string\bibdata{#1}}\fi
    \@input{\@bblfile}}
  \def\@include#1 {\clearpage
    \if@filesw \immediate\write\@mainaux{\string\@input{#1.aux}}\fi
    \@tempswatrue
    \if@partsw \@tempswafalse\edef\@tempb{#1}
       \@for\@tempa:=\@partlist\do{\ifx\@tempa\@tempb\@tempswatrue\fi}
    \fi
    \if@tempswa
       \if@filesw \let\@auxout=\@partaux
           \immediate\openout\@partaux #1.aux
           \immediate\write\@partaux{\relax}
       \fi
       \def\@bblfile{#1.bbl}\@input{#1.tex}
       \let\@bblfile\@mainbblfile\clearpage
       \@writeckpt{#1}
       \if@filesw
          \immediate\closeout\@partaux
       \fi
       \let\@auxout=\@mainaux\else\@nameuse{cp@#1}
   \fi}
\fi

% Index
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\newcommand{\nindexbefore}{}
\newcommand{\nindexafter}{}
\newenvironment{theindex}{%
  \columnseprule \z@%
  \columnsep 35\p@%
  \twocolumn[\@makeschapterhead{\indexname}]%
  \nindexbefore%
  \@mkboth{\indexname}{\indexname}%
  \thispagestyle{empty}\parindent\z@%
  \parskip\z@ \@plus .3\p@\relax%
  \let\item\@idxitem\index@size%
}{%
  \nindexafter%
  \onecolumn%
}
\newcommand{\@idxitem}  {\par\hangindent 40\p@}
\newcommand{\subitem}   {\par\hangindent 40\p@ \hspace*{20\p@}}
\newcommand{\subsubitem}{\par\hangindent 40\p@ \hspace*{30\p@}}
\newcommand{\indexspace}{\par \vskip 10\p@ \@plus5\p@ \@minus3\p@\relax}

% Footnotes
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\renewcommand\footnoterule{%
  \kern-3\p@
  \hrule width .4\columnwidth
  \kern 2.6\p@}
\@addtoreset{footnote}{chapter}
\if@noind
  \long\def\@makefntext#1{%
        \leftskip 2.0em%
        \noindent
        \hbox to 0em{\hss\@makefnmark\kern 0.25em}#1}
\else
  \long\def\@makefntext#1{%
      \parindent 1em%
      \noindent
      \hbox to 1.8em{\hss\@makefnmark\kern 0.25em}#1}
\fi

% Names
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\if@greek
\def\contentsname{Περιεχόμενα}
\def\listfigurename{Σχήματα}
\def\listtablename{Πίνακες}
\def\bibname{Βιβλιογραφία}
\def\refname{Αναφορές}
\def\indexname{Ευρετήριο}
\def\figurename{Σχήμα}
\def\tablename{Πίνακας}
\def\chaptername{Κεφάλαιο}
\def\appendixname{Παράρτημα}
\def\partname{Μέρος}
\def\abstractname{Περίληψη}
\def\draftname{Προσχέδιο}
\def\prefacename{Πρόλογος}
\def\committeename{Συμβουλευτική επιτροπή}
\def\supervisorname{Επιβλέπων}
\def\committeemembersname{Μέλη}
\def\pagesname{Σελίδες}
\def\urlname{URL}
\def\ftpname{FTP}
\def\today{\number\day\space \ifcase\month\or
  Ιανουαρίου\or Φεβρουαρίου\or Μαρτίου\or Απριλίου\or
  Μαΐου\or Ιουνίου\or Ιουλίου\or Αυγούστου\or
  Σεπτεμβρίου\or Οκτωβρίου\or Νοεμβρίου\or Δεκεμβρίου\fi
  \space\number\year}
\else
\def\contentsname{Contents}
\def\listfigurename{List of Figures}
\def\listtablename{List of Tables}
\def\bibname{Bibliography}
\def\refname{References}
\def\indexname{Index}
\def\figurename{Figure}
\def\tablename{Table}
\def\chaptername{Chapter}
\def\appendixname{Appendix}
\def\partname{Part}
\def\abstractname{Abstract}
\def\draftname{Preliminary draft}
\def\prefacename{Preface}
\def\keywordsname{Keywords}
\def\committeename{Counselling committee}
\def\supervisorname{Supervisor}
\def\committeemembersname{Members}
\def\pagesname{Pages}
\def\urlname{URL}
\def\ftpname{FTP}
\def\today{\ifcase\month\or
  January\or February\or March\or April\or
  May\or June\or July\or August\or September\or
  October\or November\or December\fi
  \space\number\day, \number\year}
\fi
\def\abstractnamegr{Περίληψη}
\def\abstractnameen{Abstract}
\def\keywordsnamegr{Λέξεις κλειδιά}
\def\keywordsnameen{Key words}
\def\acknowledgementsnamegr{Ευχαριστίες}
\def\acknowledgementsnameen{Acknowledgements}
\chapapp{\chaptername}                   % Print ``Chapter'' (?)
\def\figureshortname{\figurename}        % I don't like short names
\def\tableshortname{\tablename}

\if@greek
  \uccode`ά=`Α%
  \uccode`έ=`Ε%
  \uccode`ή=`Η%
  \uccode`ί=`Ι%
  \uccode`ό=`Ο%
  \uccode`ύ=`Υ%
  \uccode`ώ=`Ω%
  %
  \uccode`Ά=`Α%
  \uccode`Έ=`Ε%
  \uccode`Ή=`Η%
  \uccode`Ί=`Ι%
  \uccode`Ό=`Ο%
  \uccode`Ύ=`Υ%
  \uccode`Ώ=`Ω%
  %
  \uccode`ϊ=`Ϊ%
  \uccode`ϋ=`Ϋ%
  \uccode`ΐ=`Ϊ%
  \uccode`ΰ=`Ϋ%
  %
  \uccode`ς=`Σ%
\fi

\setlength\columnsep{10\p@}
\setlength\columnseprule{0\p@}
\iffinal
  \pagestyle{headings}
\else
  \pagestyle{draft}
\fi
\pagenumbering{arabic}
\if@twoside
\else
  \raggedbottom
\fi
\onecolumn

% Page setup
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
% Formulae for calculating the layout parameters:
%     odd side margin = IM - 1 in
%    even side margin = OM - 1 in
%          top margin = TM - 1 in

                                         % Paper width
                                         % --------------------------------
\oddsidemargin    4.6 mm                 % Margins: inside  =    30 mm (IM)
\evensidemargin  -0.4 mm                 %          outside =    25 mm (OM)
\textwidth      155.0 mm                 %        text body =   155 mm (TB)
                                         % --------------------------------
                                         %            total =   210 mm
                                         %
                                         % Paper height
                                         % --------------------------------
\topmargin       -0.4 mm                 % Margins:     top =    25 mm (TM)
\textheight     247.0 mm                 %           bottom =    25 mm (BM)
                                         %        text body =   247 mm (TH)
                                         % ------------------------------
                                         %            total =   297 mm

\advance \topmargin by -\headheight
\advance \topmargin by -\headsep

% More environments
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\newenvironment{keywordsgr}{\section*{\keywordsnamegr}}{}
\newenvironment{keywordsen}{\section*{\keywordsnameen}}{}
\newcommand{\footacknowledgement}[1]{%
  \let\footnotesize\small%
  \let\@tmp@makefntext\@makefntext%
  \long\def\@makefntext##1{%
    \parindent 1em%
    \noindent##1}%
  \footnotetext{#1}%
  \let\@makefntext\@tmp@makefntext%
}
\newenvironment{acknowledgementsgr}{%
  \setlanguage{monogreek}%
  \chapter*{\acknowledgementsnamegr}%
  \addcontentsline{toc}{chapter}{\acknowledgementsnamegr}%
  \begingroup%
  \let\footnoterule\relax%
}{%
  \begin{flushright}
    \@author, \\[6pt]
    Αθήνα, \@date@defense
  \end{flushright}
  \newpage%
  \endgroup%
}
\newenvironment{acknowledgementsen}{%
  \selectlanguage{english}%
  \chapter*{\acknowledgementsnameen}%
  \addcontentsline{toc}{chapter}{\acknowledgementsnameen}%
  \begingroup%
  \let\footnoterule\relax%
}{%
  \begin{flushright}
    \@authoren, \\[6pt]
    Athens, \@date@defenseen
  \end{flushright}
  \newpage%
  \endgroup%
}

% Font customization
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\institutionfont{\LARGE\scshape}
\schoolfont{\Large\scshape}
\departmentfont{\Large\scshape}
\titlefont{\LARGE\bfseries}
\authorfont{\Large\bfseries}
\thesistypefont{\Large}
\def\st@font{\large}

% Miscellaneous stuff
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

   % Empty pages should be really empty (not have headings)
\def\cleardoublepage{\clearpage\if@twoside \ifodd\c@page\else
    \thispagestyle{empty}\hbox{}\newpage\fi\fi}

   % This saves the underfull boxes resulting from equations that
   % are typeset in just one page
%\raggedbottom

   % This typesets footnotes always at the very bottom of the page
\renewcommand\footnoterule{\vfill\kern-3\p@%
  \hrule width .4\columnwidth\kern 2.6\p@}

% Macros for signatures
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
\newcommand\signature[3][0pt]{\makebox[40mm]{\tiny\dotfill}\\[6pt]#2\\[#1]#3}

% More names
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

\def\@author@accusative{τον συγγραφέα}

\if@greek
\thesistype{Διπλωματική Εργασία}
\institution{Εθνικό Μετσόβιο Πολυτεχνείο}
\school{Σχολή Ηλεκτρολόγων Μηχανικών \\ και Μηχανικών Υπολογιστών}
\department{Τομέας Τεχνολογίας Πληροφορικής \\ και Υπολογιστών}
\else
\thesistype{Diploma Project}
\institution{National Technical University of Athens}
\school{School of Electrical and Computer Engineering}
\department{Department of Computer Science}
\fi
\trurl{http://www.softlab.ntua.gr/techrep/}
\trftp{ftp://ftp.softlab.ntua.gr/pub/techrep/}

\uppertitleback{%
  \vspace*{4cm}%
  {\large%
  \signature[6pt]{%
    \textbf{\uppercase{\@author}}
  }{%
    Διπλωματούχος Ηλεκτρολόγος Μηχανικός και Μηχανικός Υπολογιστών Ε.Μ.Π.
  }}
}
\lowertitleback{%
  {\large Copyright \copyright\ \ \@author, \@date@year.\\
\if@greek
  Με επιφύλαξη παντός δικαιώματος.  All rights reserved.\\[12pt]
\else
  All rights reserved.\\[12pt]
\fi
  }
\if@greek
  Απαγορεύεται η αντιγραφή, αποθήκευση και διανομή της παρούσας
  εργασίας, εξ ολοκλήρου ή τμήματος αυτής, για εμπορικό σκοπό.
  Επιτρέπεται η ανατύπωση, αποθήκευση και διανομή για σκοπό μη
  κερδοσκοπικό, εκπαιδευτικής ή ερευνητικής φύσης, υπό την προϋπόθεση
  να αναφέρεται η πηγή προέλευσης και να διατηρείται το παρόν μήνυμα.
  Ερωτήματα που αφορούν τη χρήση της εργασίας για κερδοσκοπικό σκοπό
  πρέπει να απευθύνονται προς τον συγγραφέα.
\medskip\par
  Οι απόψεις και τα συμπεράσματα που περιέχονται σε αυτό το
  έγγραφο εκφράζουν \@author@accusative{} και δεν πρέπει να
  ερμηνευθεί ότι αντιπροσωπεύουν τις επίσημες θέσεις του
  Εθνικού Μετσόβιου Πολυτεχνείου.
\else
  This work is copyright and may not be reproduced, stored nor
  distributed in whole or in part for commercial purposes.  Permission
  is hereby granted to reproduce, store and distribute this work for
  non-propfit, educational and research purposes, provided that the
  source is acknowledged and the present copyright message is retained.
  Enquiries regarding use for profit should be directed to the author.
\medskip\par
  The views and conclusions contained in this document are those
  of the author and should not be interpreted as representing the
  official policies, either expressed or implied, of the National
  Technical University of Athens.
\fi
  \vspace*{2cm}
}
\def\cr@comma{, }

\let\nickie@oldenddocument\enddocument
\def\enddocument{\label{pg:last-document}\nickie@oldenddocument}

\endinput
