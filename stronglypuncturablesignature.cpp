#include <iostream>
#include <vector>
#include <string>
#include <random>
#include <cassert>
#include <sstream>
#include <algorithm>
#include <fstream>

// --- PRG: Linear Congruential Generator ---
class PRG {
    uint64_t a, c, m;
public:
    PRG() : a(1664525), c(1013904223), m(1ULL << 32) {}
    std::vector<uint8_t> operator()(const std::vector<uint8_t>& seed) {
        uint64_t state = 0;
        for (auto b : seed) state = (state << 8) | b;
        std::vector<uint8_t> out;
        for (int i = 0; i < 8; ++i) {
            state = (a * state + c) % m;
            std::cout << state ;
            for (int j = 0; j < 4; ++j) {
                out.push_back((state >> (8 * j)) & 0xFF);
            }
            
        }
        return out;
    }
    static std::string to_hex(const std::vector<uint8_t>& v) {
        std::ostringstream oss;
        for (auto b : v) {
            oss << std::hex << ((b >> 4) & 0xF);
            oss << std::hex << (b & 0xF);
        }
        return oss.str();
    }
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i + 1 < hex.length(); i += 2) {
            uint8_t byte = 0;
            for (int n = 0; n < 2; ++n) {
                char c = hex[i + n];
                if (c >= '0' && c <= '9')
                    byte = (byte << 4) | (c - '0');
                else if (c >= 'a' && c <= 'f')
                    byte = (byte << 4) | (c - 'a' + 10);
                else if (c >= 'A' && c <= 'F')
                    byte = (byte << 4) | (c - 'A' + 10);
            }
            bytes.push_back(byte);
        }
        return bytes;
    }
};

// --- NIZK Proof System (Simulation Sound, Stub) ---
struct CRS {
    std::string desc;
};
struct Proof {
    std::string data;
};
class NIZK {
public:
    static CRS Setup(int lambda) {
        CRS crs;
        crs.desc = "crs_" + std::to_string(rand());
        return crs;
    }
    static Proof Prove(const CRS& crs, const std::string& statement, const std::string& witness) {
        Proof pf;
        pf.data = "proof_" + crs.desc + "_" + statement + "_" + witness;
        return pf;
    }
    static bool Vrfy(const CRS& crs, const std::string& statement, const Proof& pf) {
        return pf.data.find(crs.desc) != std::string::npos && pf.data.find(statement) != std::string::npos;
    }
};

// --- SPS Scheme ---
class SPS {
    int lambda, k;
    PRG prg;
public:
    struct SecretKey {
        std::vector<std::vector<std::vector<uint8_t>>> s; // [2][k][lambda bytes]
    };
    struct PublicKey {
        std::vector<std::vector<std::vector<uint8_t>>> vk; // [2][k][2*lambda bytes]
        CRS crs;
    };

    SPS(int lambda_bits, int k_bits) : lambda(lambda_bits), k(k_bits) {}

    void KeyGen(PublicKey& pk, SecretKey& sk) {
        pk.vk.resize(2, std::vector<std::vector<uint8_t>>(k));
        sk.s.resize(2, std::vector<std::vector<uint8_t>>(k));
        pk.crs = NIZK::Setup(lambda);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);

        for (int i = 0; i < 2; ++i) {
            for (int j = 0; j < k; ++j) {
                std::vector<uint8_t> seed(lambda);
                for (int l = 0; l < lambda; ++l)
                    seed[l] = dist(gen);
                sk.s[i][j] = seed;
                pk.vk[i][j] = prg(seed);
            }
        }
    }

    void PKeyGen(const std::vector<uint8_t>& m_star, PublicKey& pk, SecretKey& sk) {
        pk.vk.resize(2, std::vector<std::vector<uint8_t>>(k));
        sk.s.resize(2, std::vector<std::vector<uint8_t>>(k));
        pk.crs = NIZK::Setup(lambda);

        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<uint8_t> dist(0, 255);

        for (int i = 0; i < 2; ++i) {
            for (int j = 0; j < k; ++j) {
                if (i == ((m_star[j / 8] >> (j % 8)) & 1)) {
                    sk.s[i][j] = {};
                    std::vector<uint8_t> pi(2 * lambda);
                    for (int l = 0; l < 2 * lambda; ++l)
                        pi[l] = dist(gen);
                    pk.vk[i][j] = pi;
                } else {
                    std::vector<uint8_t> seed(lambda);
                    for (int l = 0; l < lambda; ++l)
                        seed[l] = dist(gen);
                    sk.s[i][j] = seed;
                    pk.vk[i][j] = prg(seed);
                }
            }
        }

        for (int i=0;i<lambda;i++)
        {
            for(int j=0;j<lambda;j++){
                //std:: cout << sk.s[i][j];
            }
        }
    }

    Proof Sign(const SecretKey& sk, const PublicKey& pk, const std::vector<uint8_t>& m) {
        int ell = -1;
        for (int j = 0; j < k; ++j) {
            int bit = (m[j / 8] >> (j % 8)) & 1;
            if (sk.s[bit][j].empty()) {
                ell = j;
                break;
            }
        }
        if (ell == -1) return Proof{"⊥"};
        int b = (m[ell / 8] >> (ell % 8)) & 1;
        std::string statement = "vk=" + vk_to_string(pk.vk) + ";m=" + bytes_to_hex(m);
        std::string witness = bytes_to_hex(sk.s[b][ell]);
        return NIZK::Prove(pk.crs, statement, witness);

    }

    bool Vrfy(const PublicKey& pk, const Proof& sig, const std::vector<uint8_t>& m) {
        std::string statement = "vk=" + vk_to_string(pk.vk) + ";m=" + bytes_to_hex(m);
        return NIZK::Vrfy(pk.crs, statement, sig);

    }

    static std::string bytes_to_hex(const std::vector<uint8_t>& v) {
        std::ostringstream oss;
        for (auto b : v) {
            oss << std::hex << ((b >> 4) & 0xF);
            oss << std::hex << (b & 0xF);
        }
        return oss.str();
    }
    static std::vector<uint8_t> hex_to_bytes(const std::string& hex) {
        std::vector<uint8_t> bytes;
        for (size_t i = 0; i + 1 < hex.length(); i += 2) {
            uint8_t byte = 0;
            for (int n = 0; n < 2; ++n) {
                char c = hex[i + n];
                if (c >= '0' && c <= '9')
                    byte = (byte << 4) | (c - '0');
                else if (c >= 'a' && c <= 'f')
                    byte = (byte << 4) | (c - 'a' + 10);
                else if (c >= 'A' && c <= 'F')
                    byte = (byte << 4) | (c - 'A' + 10);
            }
            bytes.push_back(byte);
        }
        return bytes;
    }
    static std::string vk_to_string(const std::vector<std::vector<std::vector<uint8_t>>>& vk) {
        std::ostringstream oss;
        for (int i = 0; i < vk.size(); ++i) {
            for (int j = 0; j < vk[i].size(); ++j) {
                oss << "[" << i << "," << j << "]=" << bytes_to_hex(vk[i][j]) << ";";
            }
        }
        return oss.str();
    }
    static void vk_from_string(const std::string& str, std::vector<std::vector<std::vector<uint8_t>>>& vk, int k) {
        vk.resize(2, std::vector<std::vector<uint8_t>>(k));
        size_t pos = 0;
        for (int i = 0; i < 2; ++i) {
            for (int j = 0; j < k; ++j) {
                std::string marker = "[" + std::to_string(i) + "," + std::to_string(j) + "]=";
                size_t start = str.find(marker, pos);
                if (start == std::string::npos) break;
                start += marker.length();
                size_t end = str.find(";", start);
                if (end == std::string::npos) break;
                std::string hex = str.substr(start, end - start);
                vk[i][j] = hex_to_bytes(hex);
                pos = end + 1;
            }
        }
    }
};

// Converts a normal string to a bit vector (ASCII binary representation)
std::vector<uint8_t> string_to_bitvec(const std::string& s, int k) {
    std::vector<uint8_t> v((k + 7) / 8, 0);
    int bitpos = 0;
    for (char ch : s) {
        for (int b = 7; b >= 0 && bitpos < k; --b, ++bitpos) {
            if ((ch >> b) & 1)
                v[bitpos / 8] |= (1 << (bitpos % 8));
        }
    }
    return v;
}

// Serialize/deserialize signature (Proof) as string
std::string serialize_sig(const Proof& sig) { return sig.data; }
Proof deserialize_sig(const std::string& s) { return Proof{s}; }

int main() {
    int lambda = 4; // For demonstration, use small lambda (not secure!)
    int k = 16 * 8; // Message length in bits (for 16 char strings)

    SPS sps(lambda, k);

    std::cout << "Choose mode: (1) Prover (2) Verifier: ";
    int mode;
    std::cin >> mode;
    std::cin.ignore();

    if (mode == 1) {
        // --- PROVER SIDE ---
        std::string mstar_str;
        std::cout << "Enter message to puncture at (as normal string): ";
        std::getline(std::cin, mstar_str);
        std::vector<uint8_t> m_star = string_to_bitvec(mstar_str, k);

        SPS::PublicKey pk;
        SPS::SecretKey sk;
        sps.PKeyGen(m_star, pk, sk);

        std::string m_str;
        std::cout << "Enter message to sign (as normal string): ";
        std::getline(std::cin, m_str);
        std::vector<uint8_t> m = string_to_bitvec(m_str, k);

        Proof sig = sps.Sign(sk, pk, m);

        std::ofstream sigfile("signature.txt");
        if (!sigfile.is_open()) {
            std::cout << "Error: Could not create signature file." << std::endl;
            return 1;
        }
        sigfile << serialize_sig(sig);
        sigfile.close();

        std::ofstream pkfile("publickey.txt");
        if (!pkfile.is_open()) {
            std::cout << "Error: Could not create public key file." << std::endl;
            return 1;
        }
        pkfile << SPS::vk_to_string(pk.vk);
        pkfile.close();

        std::ofstream crsfile("crs.txt");
        if (!crsfile.is_open()) {
            std::cout << "Error: Could not create CRS file." << std::endl;
            return 1;
        }
        crsfile << pk.crs.desc;
        crsfile.close();

        std::cout << "\n--- Prover Output ---\n";
        std::cout << "Message to verify (string): " << m_str << std::endl;
        std::cout << "Signature, public key, and CRS have been written to files.\n";
    } else if (mode == 2) {
        // --- VERIFIER SIDE ---
        std::string m_str;
        std::cout << "Enter message to verify (as normal string): ";
        std::getline(std::cin, m_str);
        std::vector<uint8_t> m = string_to_bitvec(m_str, k);

        std::ifstream sigfile("signature.txt");
        if (!sigfile.is_open()) {
            std::cout << "Error: Could not open signature file." << std::endl;
            return 1;
        }
        std::stringstream sigbuffer;
        sigbuffer << sigfile.rdbuf();
        Proof sig = deserialize_sig(sigbuffer.str());
        sigfile.close();

        std::ifstream pkfile("publickey.txt");
        if (!pkfile.is_open()) {
            std::cout << "Error: Could not open public key file." << std::endl;
            return 1;
        }
        std::stringstream pkbuffer;
        pkbuffer << pkfile.rdbuf();
        std::string pk_str = pkbuffer.str();
        pkfile.close();

        std::ifstream crsfile("crs.txt");
        if (!crsfile.is_open()) {
            std::cout << "Error: Could not open CRS file." << std::endl;
            return 1;
        }
        std::string crs_desc;
        std::getline(crsfile, crs_desc);
        crsfile.close();

        SPS::PublicKey pk;
        SPS::vk_from_string(pk_str, pk.vk, k);
        pk.crs.desc = crs_desc;

        bool valid = sps.Vrfy(pk, sig, m);
        std::cout << "\n--- Verifier Output ---\n";
        std::cout << "Verification: " << (valid ? "SUCCESS" : "FAIL") << std::endl;
    } else {
        std::cout << "Invalid mode." << std::endl;
    }
    return 0;
}
