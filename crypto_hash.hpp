#pragma once
// Value hashing helpers (moved here from the y-- core headers)
#include "ylang/vm.hpp"
#include "hash-library/md5.h"
#include "hash-library/sha1.h"
#include "hash-library/sha256.h"
#include "hash-library/sha3.h"
#include "hash-library/keccak.h"


template<typename HashAlg>
inline std::string computeHash(const Value& v);

inline std::string xorHexStrings(const std::string& a, const std::string& b) {
    std::string res;
    for (size_t i = 0; i < a.length() && i < b.length(); ++i) {
        int valA = (a[i] >= '0' && a[i] <= '9') ? (a[i] - '0') : (tolower(a[i]) - 'a' + 10);
        int valB = (b[i] >= '0' && b[i] <= '9') ? (b[i] - '0') : (tolower(b[i]) - 'a' + 10);
        int valRes = valA ^ valB;
        res += "0123456789abcdef"[valRes];
    }
    return res;
}

template<typename HashAlg>
inline std::string computeHash(const Value& v) {
    HashAlg alg;
    if (v.type == ValueType::STRING) {
        alg.add(v.asString().c_str(), v.asString().length());
        return alg.getHash();
    } else if (v.type == ValueType::INT) {
        std::string s = std::to_string(v.asInt());
        alg.add(s.c_str(), s.length());
        return alg.getHash();
    } else if (v.type == ValueType::FLOAT) {
        std::string s = std::to_string(v.asFloat());
        alg.add(s.c_str(), s.length());
        return alg.getHash();
    } else if (v.type == ValueType::BOOL) {
        std::string s = v.asBool() ? "true" : "false";
        alg.add(s.c_str(), s.length());
        return alg.getHash();
    } else if (v.type == ValueType::BIGINT) {
        std::string s = valueToString(v);
        alg.add(s.c_str(), s.length());
        return alg.getHash();
    } else if (v.type == ValueType::FILE) {
        auto *f = static_cast<FileObject *>(v.ref.get());
        std::ifstream ifs(f->path, std::ios::binary);
        if (ifs) {
            char buffer[4096];
            while (ifs.read(buffer, sizeof(buffer))) {
                alg.add(buffer, ifs.gcount());
            }
            if (ifs.gcount() > 0) {
                alg.add(buffer, ifs.gcount());
            }
        }
        return alg.getHash();
    } else if (v.type == ValueType::LIST || v.type == ValueType::TUPLE || v.type == ValueType::VECTOR) {
        // Sequential types
        std::string res;
        if (v.type == ValueType::LIST) {
            auto *list = static_cast<ListObject *>(v.ref.get());
            for (const auto& item : list->elements) {
                std::string subHash = computeHash<HashAlg>(item);
                alg.add(subHash.c_str(), subHash.length());
            }
        } else if (v.type == ValueType::TUPLE) {
            auto *tup = static_cast<TupleObject *>(v.ref.get());
            for (const auto& item : tup->elements) {
                std::string subHash = computeHash<HashAlg>(item);
                alg.add(subHash.c_str(), subHash.length());
            }
        } else {
            auto *vec = static_cast<VectorObject *>(v.ref.get());
            for (const auto& item : vec->elements) {
                std::string subHash = computeHash<HashAlg>(item);
                alg.add(subHash.c_str(), subHash.length());
            }
        }
        return alg.getHash();
    } else if (v.type == ValueType::DICT) {
        // Unordered -> hash pairs individually, then XOR them
        auto *dict = static_cast<DictObject *>(v.ref.get());
        std::string combinedHex = "";
        for (const auto& pair : dict->items) {
            std::string keyHash = computeHash<HashAlg>(pair.first);
            std::string valHash = computeHash<HashAlg>(pair.second);
            HashAlg pairAlg;
            pairAlg.add(keyHash.c_str(), keyHash.length());
            pairAlg.add(valHash.c_str(), valHash.length());
            std::string pairHex = pairAlg.getHash();
            if (combinedHex.empty()) combinedHex = pairHex;
            else combinedHex = xorHexStrings(combinedHex, pairHex);
        }
        if (combinedHex.empty()) combinedHex = alg.getHash();
        return combinedHex;
    } else if (v.type == ValueType::SET) {
        // Unordered -> hash individually, then XOR
        auto *set = static_cast<SetObject *>(v.ref.get());
        std::string combinedHex = "";
        for (const auto& item : set->elements) {
            std::string itemHex = computeHash<HashAlg>(item);
            if (combinedHex.empty()) combinedHex = itemHex;
            else combinedHex = xorHexStrings(combinedHex, itemHex);
        }
        if (combinedHex.empty()) combinedHex = alg.getHash();
        return combinedHex;
    } else {
        // fallback for everything else (functions, classes)
        std::string s = valueToString(v);
        alg.add(s.c_str(), s.length());
        return alg.getHash();
    }
}

class DoubleSHA256 {
    HL_SHA256 sha;
    std::string firstHash;
public:
    void add(const void* data, size_t numBytes) {
        sha.add(data, numBytes);
    }
    std::string getHash() {
        firstHash = sha.getHash();
        HL_SHA256 sha2;
        sha2.add(firstHash.c_str(), firstHash.length());
        return sha2.getHash();
    }
};

	
