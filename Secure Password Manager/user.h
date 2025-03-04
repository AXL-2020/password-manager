#pragma once
#include <iostream>
#include <string>
#include <type_traits>
#include <limits>

class User {
	std::string username, password;
public:
	
	explicit User() = default;
	~User()			= default;

	void getLoginCreds();

	const std::string& getUsername() const;
	std::string& getPassword();

	template <typename T>
	T getInput();
};

template <typename T>
T User::getInput() {
	T result;

	if constexpr (std::is_same<T, std::string>::value)
		std::getline(std::cin, result);
	else if constexpr (std::is_same<T, char>::value) {
		std::cin >> result;
		std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');
	}
	else if constexpr (std::is_integral<T>::value) { 
		while (!(std::cin >> result)) {
			std::cin.clear();
			std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');  
			std::cout << "Invalid input. Try again: ";
		}
		std::cin.ignore((std::numeric_limits<std::streamsize>::max)(), '\n');  
	}
	else 
		static_assert(sizeof(T) == 0, "Unsupported data type.");

	return result;
}