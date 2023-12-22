#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#include "wav.h"

int check_format(WAVHEADER header);
int get_block_size(WAVHEADER header);

int main(int argc, char *argv[])
{
    // Ensure proper usage
    if (argc != 3)
    {
        printf("Usage: ./reverse input.wav output.wav\n");
        return 1;
    }

    // check that the input and output file is WAV format
    if (strcmp(argv[argc - 2], "input.wav") != 0 || strcmp(argv[argc - 1], "output.wav") != 0)
    {
        printf("Input is not a WAV file.\n");
        return 1;
    }


    // Open input file for reading
    FILE *input_file = fopen(argv[1], "r");
    // Сhecking that there was no error opening the file
    if (input_file == NULL)
    {
        printf("Could not open %s.\n", argv[1]);
        return 2;
    }

    // Read header
    WAVHEADER wa_h;
    fread(&wa_h, sizeof(WAVHEADER), 1, input_file);

    // Use check_format to ensure WAV format
    if (!check_format(wa_h))
    {
        fclose(input_file);
        printf("Input is not a WAV file.");
        return 1;
    }

    // Open output file for writing
    FILE *output_file = fopen(argv[2], "w");
    // Сhecking that there was no error opening the file
    if (output_file == NULL)
    {
        fclose(input_file);
        printf("Could not create %s.\n", argv[1]);
        return 5;
    }

    // Write header to file
    fwrite(&wa_h, sizeof(WAVHEADER), 1, output_file);

    // Use get_block_size to calculate size of block
    int block_size = get_block_size(wa_h);

    // Write reversed audio to file
    int ofset_after_read_header = ftell(input_file); // should be 44

    // Create an array of 2 byte numbers to store the data of one sample
    int16_t buffer[2];

    // Move the file pointer at last to find out the total number of bytes in the file
    fseek(input_file, 0, SEEK_END);

    // Loop through the number of bytes in a file
    for (int i = 0, j = ftell(input_file); i < j; i++)
    {
        // Shift the pointer to the block size relative to the end of the file to read it in reverse order
        fseek(input_file, -block_size * (i + 1), SEEK_END);
        // Checking if the loop has reached the header
        if (ftell(input_file) <= 40)
        {
            fseek(input_file, 0, SEEK_END);
            break;
        }
        // Read into the buffer the block size by channel
        fread(buffer, block_size / 2, block_size / 2, input_file);
        // Write to output file
        fwrite(buffer, block_size / 2, block_size / 2, output_file);
    }

    // Сlose input and output file
    fclose(input_file);
    fclose(output_file);
}

int check_format(WAVHEADER header)
{
    char *check_string = "WAVE";
    if (header.format[0] != 0x57 || header.format[1] != 0x41 || header.format[2] != 0x56 || header.format[3] != 0x45)
    {
        return 0;
    }
    return 1;
}

int get_block_size(WAVHEADER header)
{
    return (header.bitsPerSample) / 8 * header.numChannels;
}