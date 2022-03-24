#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/wait.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#define BUFFER_LEN 1024
// global vars
char cmd[BUFFER_LEN];
char environment_vars[BUFFER_LEN][BUFFER_LEN];
char vars_index[BUFFER_LEN][BUFFER_LEN];
int count = 0;
size_t length;
char *token;
char *dollar;
char* parsedcmd[BUFFER_LEN];
pid_t pid;
bool waitFlag;
bool isLs = false;;
int i=0;

// methods
void change_dir() {
 // cd call
    char cwd[256];
    char *dir = getcwd(cwd, sizeof(cwd));
    // home path
    if((parsedcmd[1] == NULL) || !strcmp(parsedcmd[1],"~") || !strcmp(parsedcmd[1],"..")) {
        chdir("/yara/home");
    }
    // given path
    else {
        chdir(strcat(strcat(dir, "/"), parsedcmd[1]));    
    }        
}
void parse_input() {
    i=0; // reset i
    length = strlen(cmd);
    if (cmd[length - 1] == '\n') { // replace end of line by end of string
        cmd[length - 1] = '\0'; 
    }
    token = strtok(cmd," "); //cmd
    
    while(token != NULL) { //cmd and arguments
        if (!strcmp(token,"&")) {
            token = '\0';
            parsedcmd[i]= token;
            waitFlag= true; // set flag to background process
            break;
        }
        else { 
            parsedcmd[i++] = token;
            token = strtok(NULL," ");
        }
    parsedcmd[i] = token; // null
    }

    int j;
    for(j=0;j<i;j++) {
            char lol[100];
            memset(lol, '\0', sizeof(lol));
            strcpy(lol, parsedcmd[j]);
            if('$' == lol[0]) {
                if(!strcmp(cmd, "ls")) isLs = true;
                // handle export
                int k;
                char val[100];
                memmove(lol, lol + 1, strlen(lol));
                for(k=0;k<count; k++) {
                    if(!strcmp(environment_vars[k], lol)) {
                        strcpy(parsedcmd[1], vars_index[k]);
                        break;
                    }
                }
           }       
    }

    if(isLs) { // multiple argument command with an evaluated expression as an argument
        i=1;
        dollar = strtok(parsedcmd[1]," ");
        
        while(dollar != NULL) {
            parsedcmd[i++] = dollar;
            dollar = strtok(NULL," ");
        }
        parsedcmd[i] = dollar;
        isLs = false;
       }
    
}
void shell() {
    pid = fork();
    if(pid == -1) { printf("\nForking failed.");}
    if(pid == 0) {
        if(execvp(parsedcmd[0], parsedcmd) < 0) {
            printf("\nExecution failed.");
            exit(0);
        } 
    }
    else {
        if(!waitFlag) { waitpid(pid,NULL,0); } // wait for foreground processes
        else { waitFlag = false;} // background
    }
}
void echo() {
    char text[BUFFER_LEN];
    strcpy(text, parsedcmd[1]);
    // regular expression
    if(text[0] == '"') {
        memmove(text, text + 1, strlen(text));
        printf("\n%s", text);
        int j=2;
        while(j != i) {
            strcpy(text, parsedcmd[j]);
            if(text[strlen(text) - 1] == '"') text[strlen(text) - 1] = '\0';
            printf(" %s", text);
            j++;
        }
    }
    // evaluated expression
    else printf("\n%s", parsedcmd[1]);
}
void export() {
    int l;
    char tempo[BUFFER_LEN];
    strcpy(tempo, parsedcmd[1]);
    for(l=2;l<i;l++) {
        strcat(tempo, " ");
        strcat(tempo, parsedcmd[l]);
    }
    strcpy(parsedcmd[1], tempo);
    char *var;
    char temp[BUFFER_LEN];
    strcpy(temp, parsedcmd[1]);
    var = strtok(temp, "=");
    strcpy(environment_vars[count], var);   // store env vars 
    var = strtok(NULL, "=");
    char value[100];
    strcpy(value, var);
    if(value[0] == '"') { // remove quotes
        memmove(value, value + 1, strlen(value));
        value[strlen(value) - 1] = '\0';
    }
    strcpy(vars_index[count], value); // store value of each var at the corresponding index
    count++; // increment count of env vars
}
void setup_environment() {
    int status;
    int pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) { // handle zombie processes
        // `pid` exited with `status`
    }
    FILE *fp;
    fp = fopen ("logFile.txt", "a");
    fputs("Child Process Terminated.\n",fp); // write to log file when child executes
    fclose(fp);
}

// main
int main() {
    while(true) {
        signal (SIGCHLD, setup_environment);
        printf("\nyara@yara:~ ");
        if(!fgets(cmd,BUFFER_LEN, stdin)){} 
        // split innput to command and arguments
        parse_input();
        // exit command
        if (!strcmp(parsedcmd[0], "exit")) exit(0);
        // echo command
        else if (!strcmp(parsedcmd[0], "echo")){
            echo();
            continue;
        }
        // export command
        else if (!strcmp(parsedcmd[0], "export")){
            export();
            continue;
        }
        // cd command
        else if(!strcmp(parsedcmd[0], "cd")) {
            change_dir();
            continue;
        }
        // regular commands
        shell();

    }
    return 0;
}
