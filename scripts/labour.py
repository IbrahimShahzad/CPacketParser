
def my_mod(file,new_file):
    with open(file, "r+") as f:
        myline = f.readline() # read everything in the file
        while myline:
            print(myline)
            myline = f.readline()
            wordToAdd = ""
            if " string " in myline:
                wordToAdd = " char* "
            elif " text " in myline:
                wordToAdd = " char* "
            elif " int " in myline:
                wordToAdd = " int "
            elif " enum " in myline:
                wordToAdd = " int "
            else:
                wordToAdd = " //TODO: FIX ME "

            with open(new_file,"a") as new_f:
                new_f.write(wordToAdd + myline)


if __name__ == "__main__":
    my_mod("rfc.txt","new_file.txt")