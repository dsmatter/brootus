#!/bin/bash
# This script is supposed to automatically generate a C-headerfile from a symbol-table.
# It takes two arguments, argument one specifying the file to read from and argument two specifying the file to write to
# @author Christoph Baur, Daniel Strittmatter

# some validation first
if [ $# -ne 2 ]; then
  echo "Usage: `basename $0` {arg}"
  exit 65
fi

# arguments
INPUTFILE=$1
OUTPUTFILE=$2

# some blabla at the beginning of the header file that is going to be created
HEADER="/*This is a C-Headerfile containing all the renamed symbols and adresses of the symbol-table $INPUTFILE*/\n\n#ifndef SYSMAP_H\n#define SYSMAP_H\n\n"

TAIL="\n\n#endif"

# creating the actual C-Headercode and assigning it to the variable called SYMBOLS

echo "Reading and parsing the input file...please be patient.\n"
SYMBOLS=`grep ' [TtDdRr] ' $INPUTFILE | awk '{ gsub(/\./, "_", $3); if (h[$3] != 1) {printf("#define rk_%s 0x%s;\n" ,$3 ,$1)} h[$3] = 1 }'`

# saving the results to OUTPUTFILE
echo "Done. Saving results to the specified output file.\n"
echo -e "${HEADER}${SYMBOLS}${TAIL}" > $OUTPUTFILE

echo "Mission accomplished.\n"
exit 0
