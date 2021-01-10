
unsigned char asciiToHex(char ch) {
    unsigned char ret = 0;
    if (ch >= '0' && ch <= '9') {
        ret = ch - '0';
    }
    else if (ch >= 'a' && ch <= 'f') {
        ret = ch - 'a' + 10;
    }
    else if (ch >= 'A' && ch <= 'F') {
        ret = ch - 'A' + 10;
    }
    return ret;
}
