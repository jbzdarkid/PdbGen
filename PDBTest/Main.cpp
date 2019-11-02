/*
    Some large block comment. Obviously not required in a generated file...

*/

int foo(int bar) {
    bar += 5;
    bar *= 6;
    bar -= 7;
    bar /= 8;
    return bar;
}

int main() {
    int a = 1;
    a += foo(5);
    a++;
    a *= 2;
    a -= 3;
    a /= 4;
    return a;
}