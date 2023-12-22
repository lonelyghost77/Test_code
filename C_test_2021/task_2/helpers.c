#include "helpers.h"
#include "stdio.h"
#include "math.h"

// Convert image to grayscale
void grayscale(int height, int width, RGBTRIPLE image[height][width])
{
    for (int row = 0; row < height; row++)
    {
        for (int column = 0; column < width; column++)
        {
            int mean = roundf((image[row][column].rgbtBlue + image[row][column].rgbtGreen + image[row][column].rgbtRed) / 3.0);
            image[row][column].rgbtBlue = image[row][column].rgbtGreen = image[row][column].rgbtRed =  mean;
        }
    }
    return;
}

// Convert image to sepia
void sepia(int height, int width, RGBTRIPLE image[height][width])
{
    for (int row = 0; row < height; row++)
    {
        for (int column = 0; column < width; column++)
        {
            int sepiaRed = roundf(.393 * image[row][column].rgbtRed + .769 * image[row][column].rgbtGreen + .189 * \
                                  image[row][column].rgbtBlue);
            int sepiaGreen = roundf(.349 * image[row][column].rgbtRed + .686 * image[row][column].rgbtGreen + .168 * \
                                    image[row][column].rgbtBlue);
            int sepiaBlue = roundf(.272 * image[row][column].rgbtRed + .534 * image[row][column].rgbtGreen + .131 * \
                                   image[row][column].rgbtBlue);

            image[row][column].rgbtRed = (sepiaRed > 255) ? 255 : sepiaRed;
            image[row][column].rgbtGreen = (sepiaGreen > 255) ? 255 : sepiaGreen;
            image[row][column].rgbtBlue = (sepiaBlue > 255) ? 255 : sepiaBlue;
        }
    }
    return;
}

// Reflect image horizontally
void reflect(int height, int width, RGBTRIPLE image[height][width])
{
    // printf("%d", (width +1) % 2);
    for (int row = 0; row < height; row++)
    {
        if (width % 2 == 0)
        {
            RGBTRIPLE temp[1][1];
            for (int column = 0; column < width / 2; column++)
            {
                temp[0][0] =  image[row][column];
                image[row][column] =  image[row][width - column - 1];
                image[row][width - column - 1] = temp[0][0];
            }
        }
        else
        {
            RGBTRIPLE temp[1][1];
            for (int column = 0; column < (width - 1) / 2; column++)
            {
                temp[0][0] = image[row][column];
                image[row][column] =  image[row][width - column - 1];
                image[row][width - column - 1] = temp[0][0];
            }
        }
    }
    return;
}

// Blur image
void blur(int height, int width, RGBTRIPLE image[height][width])
{
    // temporary array for copy of main
    RGBTRIPLE temp[height][width];
    // iterate over the rows
    for (int row = 0; row < height; row++)
    {
        // iterate over the coluums
        for (int column = 0; column < width; column++)
        {
            // initialization of temporary variable for blue pixel
            int s1 = 0;
            // initialization of temporary variable for green pixel
            int s2 = 0;
            // initialization of temporary variable for red pixel
            int s3 = 0;
            // initialization of temporary variable for counter
            int c = 0;
            // iterate over the rows subarray 3x3
            for (int i = -1; i < 2; i++)
            {
                // iterate over the columns subarray 3x3
                for (int j = -1; j < 2; j++)
                {
                    // array out of bounds check
                    if (row + i < 0 || row + i > height - 1 || column + j < 0 || column + j > width - 1)
                    {
                        continue;
                    }
                    // calculate sum for each pixel
                    s1 += image[row + i][column + j].rgbtBlue; // blue
                    s2 += image[row + i][column + j].rgbtGreen; // green
                    s3 += image[row + i][column + j].rgbtRed; // red
                    // update the counter
                    c++;
                }
            }
            // calculate the average value of each pixel by rounding the value and write it to a temporary array
            temp[row][column].rgbtBlue = roundf((float) s1 / c); // blue
            temp[row][column].rgbtGreen = roundf((float) s2 / c); // green
            temp[row][column].rgbtRed = roundf((float) s3 / c); // red
        }
    }

    // iterate over the rows
    for (int row = 0; row < height; row++)
    {
        // iterate over the coluums
        for (int column = 0; column < width; column++)
        {
            // write the value from the temporary array to the main one
            image[row][column] = temp[row][column];
        }
    }
    return;
}
