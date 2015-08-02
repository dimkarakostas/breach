.PHONY: FORCE lenny all clean distclean

FILE=thesis
.SUFFIXES: .pdf .ps .dvi .tex
.PHONY: clean distclean 

export TEXINPUTS:=${PWD}/Styles//:${TEXINPUTS}
export BSTINPUTS:=${PWD}/Styles//:${BSTINPUTS}

all: $(FILE).pdf

%.pdf: %.tex FORCE
	latexmk -pdf -f -e '$$pdflatex=q/xelatex %O %S/' $<

lenny: thesis.tex
	env TEXINPUTS="${PWD}/Styles.lenny//:$$TEXINPUTS" \
	  latexmk -r latexmkrc.lenny -pdf -f $<

clean:
	for ext in aux log toc lof lot lol dlog bbl blg out tpt fdb_latexmk; \
	do \
		$(RM) $(FILE).$$ext ; \
	done
	$(RM) *.aux *.bak *~

distclean: clean
	$(RM) $(FILE).pdf
	$(RM) *.d
