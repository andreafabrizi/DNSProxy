#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LENGTH 80

int main(void)
{
    FILE *fout = fopen("out.txt", "w");

    if(ferror(fout))
    {
        fprintf(stderr, "Error opening output file");
        return 1;
    }
    char init_line[]  = {"char hex_array[] = { "};
    const int offset_length = strlen(init_line);

    char offset_spc[offset_length];

    unsigned char buff[1024];
    char curr_out[64];

    int count, i;
    int line_length = 0;

    memset((void*)offset_spc, (char)32, sizeof(char) * offset_length - 1);
    offset_spc[offset_length - 1] = '\0';

    fprintf(fout, "%s", init_line);

    while(!feof(stdin))
    {
        count = fread(buff, sizeof(char), sizeof(buff) / sizeof(char), stdin);

        for(i = 0; i < count; i++)
        {
            line_length += sprintf(curr_out, "%#x, ", buff[i]);

            fprintf(fout, "%s", curr_out);
            if(line_length >= MAX_LENGTH - offset_length)
            {
                fprintf(fout, "\n%s", offset_spc);
                line_length = 0;
            }
        }
    }
    fseek(fout, -2, SEEK_CUR);
    fprintf(fout, " };");

    fclose(fout);

    return EXIT_SUCCESS;
}
