#include <stdio.h>
short ip[8] = { 2, 6, 3, 1, 4, 8, 5, 7 };
short ip_inverse[8] = { 4,1,3,5,7,2,8,6 };
short p10[10] = { 3,5,2,7,4,10,1,9,8,6 };
short p8[8] = { 6,3,7,4,8,5,10,9 };
short ep[8] = { 4,1,2,3,2,3,4,1 };
short p4[4] = { 2,4,3,1 };
short s0[16] = { 1,0,3,2,3,2,1,0,0,2,1,3,3,1,3,2 };
short s1[16] = { 0,1,2,3,2,0,1,3,3,0,1,0,2,1,0,3 };
short key = -1, k1, k2, P, C;

short tablePermute(short bits4, short table[]);
short permute(short num, short numSize, short function[], short returnSize);
short leftShift(short* num, short ammount);
short getBitAt(short num, short position);
void printBits(short num, short size);
short getBits(short num, short size, short startPos);
short combine(short left, short right, short size);
void fk(short aIn, short bIn, short* aOut, short* bOut, short key);
short inputBinary(short bitSize, char* bitName);
void getKeys();
void encryption();
void decryption();

int main() {

    int input;
    while (1)
    {
        printf("\n1. Encrypt\n2. Decrypt\nEnter Choice: ");
        scanf("%d", &input);
        switch (input)
        {
        case 0:
            return 0;
        case 1:
            if ((key = inputBinary(10, "key")) == -1)
            {
                printf("Please enter a valid key\n");
                break;
            }
            if ((P = inputBinary(8, "Plaintext")) == -1)
            {
                printf("Please enter valid Plaintext\n");
                break;
            }
            getKeys();
            encryption();
            break;
        case 2:
            if ((key = inputBinary(10, "key")) == -1)
            {
                printf("Please enter a valid key\n");
                break;
            }
            if ((C = inputBinary(8, "ciphertext")) == -1)
            {
                printf("Please enter valid ciphertext\n");
                break;
            }
            getKeys();
            decryption();
            break;
        }

    }

    return 0;
}

short tablePermute(short bits4, short table[])
{
    short row, col;
    row = getBitAt(bits4, 3) * 2;
    row += getBitAt(bits4, 0);
    col = getBitAt(bits4, 2) * 2;
    col += getBitAt(bits4, 1);
    row *= 4;
    return table[row + col];
}

short permute(short num, short numSize, short function[], short returnSize)
{
    short result = 0;
    for (short i = 0; i < returnSize; i++)
        result += getBitAt(num, numSize - function[i]) << (returnSize - 1 - i);
    return result;
}

short leftShift(short* num, short ammount)
{
    for (short i = 0; i < ammount; i++)
        *num = (*num << 1) ^ getBitAt(*num, 4);
    *num = getBits(*num, 5, 0);
}

short getBitAt(short num, short position)
{
    return (num >> position) & 1;
}

void printBits(short num, short size)
{
    for (short i = size - 1; i >= 0; i--)
    {
        char c = (num & (1 << i)) ? '1' : '0';
        printf("%c", c);
    }
    printf("\n");
}

short getBits(short num, short size, short startPos)
{
    return ((1 << size) - 1) & (num >> (startPos));
}

short combine(short left, short right, short size)
{
    left = getBits(left, size, 0);
    right = getBits(right, size, 0);
    return (left <<= size) | right;
}

void getKeys()
{
    short p10result, l5, r5;

    printf("\nKey: ");
    printBits(key, 10);

    // apply p10 to key
    p10result = permute(key, 10, p10, 10);

    // get left & right 5 bits
    l5 = getBits(p10result, 5, 5);
    r5 = getBits(p10result, 5, 0);

    // left shift by 1 on both
    leftShift(&l5, 1);
    leftShift(&r5, 1);

    // combine them
    k1 = combine(l5, r5, 5);
    // apply p8 for K1
    k1 = permute(k1, 10, p8, 8);

    // left shift by 2 on both
    leftShift(&l5, 2);
    leftShift(&r5, 2);

    // combine them
    k2 = combine(l5, r5, 5);

    // apply p8 for K2
    k2 = permute(k2, 10, p8, 8);

    printf("k1: ");
    printBits(k1, 8);
    printf("k2: ");
    printBits(k2, 8);
}

void fk(short aIn, short bIn, short* aOut, short* bOut, short key)
{
    short epResult, p4Result, l4, r4;

    // apply ep to right 4 bits in
    epResult = permute(bIn, 4, ep, 8);
    epResult ^= key;

    // get left & right 4 bits of epResult
    l4 = getBits(epResult, 8, 4);
    r4 = getBits(epResult, 4, 0);

    // get the values from the tables
    l4 = tablePermute(l4, s0);
    r4 = tablePermute(r4, s1);

    // combine the values
    p4Result = combine(l4, r4, 2);

    // apply p4 to the combination
    p4Result = permute(p4Result, 4, p4, 4);

    // XOR with the left 4 bits in
    p4Result ^= aIn;
    //p4Result = getBits(p4Result, 4, 0);

    // assign the values
    *aOut = p4Result;
    *bOut = bIn;

}


void encryption()
{
    short ipResult, a, b;

    printf("\nPlaintext: ");
    printBits(P, 8);

    // apply ip to Plashortext
    ipResult = permute(P, 8, ip, 8);

    // get left & right 4 bits of ipResult
    a = getBits(ipResult, 8, 4);
    b = getBits(ipResult, 4, 0);

    // call FK
    fk(a, b, &a, &b, k1);
    // swap a and b for next FK
    fk(b, a, &a, &b, k2);

    // combine output and apply ip_inverse
    C = combine(a, b, 4);
    C = permute(C, 8, ip_inverse, 8);
    printf("Ciphertext: ");
    printBits(C, 8);
}

void decryption()
{
    short ipResult, a, b;

    printf("\nCiphertext: ");
    printBits(C, 8);

    // apply ip to ciphertext
    ipResult = permute(C, 8, ip, 8);

    // get left & right 4 bits of ipResult
    a = getBits(ipResult, 8, 4);
    b = getBits(ipResult, 4, 0);

    // call FK
    fk(a, b, &a, &b, k2);
    // swap a and b for next FK
    fk(b, a, &a, &b, k1);

    // combine output and apply ip_inverse
    P = combine(a, b, 4);
    P = permute(P, 8, ip_inverse, 8);
    printf("Plaintext: ");
    printBits(P, 8);
}

short inputBinary(short bitSize, char* bitName)
{
    char input[10];
    short number = 0;
    printf("Enter a %d bit %s: ", bitSize, bitName);
    scanf("%s", input);
    for (short i = 0; i < bitSize; i++)
    {
        if (input[i] == '1')
            number = (number << 1) ^ 1;
        else if (input[i] == '0')
            number <<= 1;
        else
        {
            printf("\nIncorrect value entered\n");
            return -1;
        }
    }
    return number;
}

