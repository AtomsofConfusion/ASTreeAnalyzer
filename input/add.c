int main(){
    int x = 3;
    char y = 'a';
    for (int i = 0; i < 5; i++) {
        if (i % 2 == 0) {
            y++;
        }
    }
    return (x + y) * 2;
}