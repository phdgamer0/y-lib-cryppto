#include "crypto_hash.hpp"
#include <iostream>



extern "C" void YlangLoadModule(std::shared_ptr<Env> env, const std::vector<std::string> &symbols) {
    auto moduleNamespace = std::make_shared<ClassObject>("Crypto");
		moduleNamespace->mro.push_back(moduleNamespace.get());
		auto define = [&](string name, NativeFunc f) {
			moduleNamespace->staticFields[name] = Value::Native(f);
			if (symbols.size() == 1 && symbols[0] == "*") {
				env->set(name, Value::Native(f), true);
				return;
			}
			for (const auto &s : symbols)
				if (s == name) {
					env->set(name, Value::Native(f), true);
					break;
				}
		};
		define("MD5", [](const vector<Value> &args, int l, int c) {
			if (args.empty()) return Value::String("");
			return Value::String(computeHash<HL_MD5>(args[0]));
		});
		define("SHA1", [](const vector<Value> &args, int l, int c) {
			if (args.empty()) return Value::String("");
			return Value::String(computeHash<HL_SHA1>(args[0]));
		});
		define("SHA256", [](const vector<Value> &args, int l, int c) {
			if (args.empty()) return Value::String("");
			return Value::String(computeHash<HL_SHA256>(args[0]));
		});
		define("SHA3", [](const vector<Value> &args, int l, int c) {
			if (args.empty()) return Value::String("");
			return Value::String(computeHash<HL_SHA3>(args[0]));
		});
		define("Keccak", [](const vector<Value> &args, int l, int c) {
			if (args.empty()) return Value::String("");
			return Value::String(computeHash<HL_Keccak>(args[0]));
		});
		define("DoubleSHA256", [](const vector<Value> &args, int l, int c) {
			if (args.empty()) return Value::String("");
			return Value::String(computeHash<DoubleSHA256>(args[0]));
		});
		Value modVal;
		modVal.type = ValueType::CLASS;
		modVal.ref = moduleNamespace;
		env->set("Crypto", modVal, false, false);
	}
