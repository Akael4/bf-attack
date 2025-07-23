#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <atomic>
#include <openssl/sha.h>
#include <iomanip>
#include <sstream>

using namespace std;

const string CHARSET =
    "0123456789"
    "abcdefghijklmnopqrstuvwxyz";

atomic<bool> found(false);
string foundWord;
int threadCount = 8;

string sha256(const string& str) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    SHA256_Update(&sha256, str.c_str(), str.size());
    SHA256_Final(hash, &sha256);

    stringstream ss;
    for(int i = 0; i < SHA256_DIGEST_LENGTH; i++)
        ss << hex << setw(2) << setfill('0') << (int)hash[i];
    return ss.str();
}

// Funzione ricorsiva per generare tutte le combinazioni di lunghezza "len"
void generateWords(const string& targetHash, int len, string& current, int pos, int threadId, uint64_t& counter) {
    if (found) return;

    if (pos == len) {
        counter++;
        if (counter % 1000 == 0) {
            cout << "Thread " << threadId << " - Tentativi: " << counter << " - Ultima parola: " << current << endl;
        }
        if (sha256(current) == targetHash) {
            foundWord = current;
            found = true;
        }
        return;
    }

    for (char c : CHARSET) {
        if (found) return;
        current[pos] = c;
        generateWords(targetHash, len, current, pos + 1, threadId, counter);
    }
}

// Wrapper per il multithreading: ogni thread inizia con un carattere diverso
void worker(const string& targetHash, int threadId) {
    uint64_t counter = 0;
    for (int len = 3; len <= 7 && !found; ++len) {
        string current(len, ' ');
        // il primo carattere lo assegniamo per dividere il lavoro fra i thread
        for (int i = threadId; i < (int)CHARSET.size() && !found; i += threadCount) {
            current[0] = CHARSET[i];
            generateWords(targetHash, len, current, 1, threadId, counter);
        }
    }
}

int main() {
    while (true) {
        cout << "=== MENU ===\n";
        cout << "1. Inserisci password per ottenere hash\n";
        cout << "2. Inserisci hash e cerca \n";
        cout << "0. Esci\n";
        cout << "Scelta: ";
        int choice;
        cin >> choice;
        cin.ignore();

        if (choice == 0) break;

        if (choice == 1) {
            string parola;
            while (true) {
                cout << "Inserisci password (3-7 caratteri): ";
                getline(cin, parola);
                if (parola.size() < 3 || parola.size() > 7) {
                    cout << "Lunghezza non valida!\n";
                } else {
                    break;
                }
            }
            string hash = sha256(parola);
            cout << "Hash SHA-256: " << hash << endl;

        } else if (choice == 2) {
            string hashInput;
            cout << "Inserisci hash (SHA-256, esadecimale): ";
            getline(cin, hashInput);

            if (hashInput.size() != 64) {
                cout << "Hash non valido (deve essere di 64 caratteri esadecimali)!\n";
                continue;
            }

            found = false;
            foundWord.clear();

            cout << "Avvio " << threadCount << " thread...\n";

            vector<thread> threads;
            for (int i = 0; i < threadCount; ++i) {
                threads.emplace_back(worker, hashInput, i);
            }

            for (auto& t : threads) {
                t.join();
            }

            if (found) {
                cout << "Password trovata: " << foundWord << endl;
            } else {
                cout << "Password non trovata nel range di lunghezza 3-7.\n";
            }
        } else {
            cout << "Scelta non valida.\n";
        }
        cout << endl;
    }
    return 0;
}
// Questo programma permette di calcolare l'hash SHA-256 di una parola
//g++ -o brute_force_menu main.cpp -lcrypto && ./brute_force_menu