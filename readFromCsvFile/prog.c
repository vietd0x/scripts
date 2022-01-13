#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

typedef struct person{
  char firstName[15];
  char lastName[15];
  char gender[7];
  char edu[40];
  int age, exp;
  struct person *next;
} person;

void readFromCSV(){
  FILE *fp = fopen("data.csv", "r");
  if(!fp){
    printf("Can't open the file data.csv");
    exit(1);
  }
  int dataLine = 0;
  for(char c = getc(fp); c != EOF; c = getc(fp)){
    if(c == '\n')
      dataLine++;
  }
  person tmp[dataLine+1];

  char buf[200];
  int i = 0;
  char* delimiter = ",";
  rewind(fp);
  // data tu file -> array tmp
  while(fgets(buf, 200, (FILE*)fp) != NULL){
    strcpy(tmp[i].firstName, strtok(buf, delimiter));
    strcpy(tmp[i].lastName, strtok(NULL, delimiter));
    strcpy(tmp[i].gender, strtok(NULL, delimiter));
    tmp[i].age = atoi(strtok(NULL, delimiter));
    strcpy(tmp[i].edu, strtok(NULL, delimiter));
    tmp[i].exp = atoi(strtok(NULL, delimiter));
    i++;
  }
  fclose(fp);
  for(int i = 0; i <dataLine; i++){
    insert(tmp[i].firstName, tmp[i].lastName, tmp[i].gender, tmp[i].age, tmp[i].edu, tmp[i].exp);
    // printf("%s-%s-%s-%d-%s-%d\n", tmp[i].firstName, tmp[i].lastName, tmp[i].gender, tmp[i].age, tmp[i].edu, tmp[i].exp);
  }
}