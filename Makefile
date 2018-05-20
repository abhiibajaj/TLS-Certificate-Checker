##Adapted from http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/
##Name: Arpit Bajaj
##Login: bajaja@student.unimelb.edu.au
CC=gcc
LDFLAGS = -L/usr/local/ssl/lib
CFLAGS=-Wall -Wextra -std=gnu99 -I. -O3 -lssl -lcrypto 
OBJ = certcheck.o 
EXE = certcheck

##Create .o files from .c files. Searches for .c files with same .o names given in OBJ
%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

##Create executable linked file from object files. 
$(EXE): $(OBJ)
	gcc -o $@ $^ $(CFLAGS)

##Delete object files
clean:
	/bin/rm $(OBJ)

##Performs clean (i.e. delete object files) and deletes executable
clobber: clean
	/bin/rm $(EXE) 

